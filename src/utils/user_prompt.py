from pynentry import PynEntry, PinEntryCancelled, show_message
from typing import Callable, Optional, Any
from .psuedofunc import PsuedoFunc
from getpass import getpass
from shutil import which
from abc import abstractmethod, ABCMeta
import sys
import click

"""
We can't use ABC by itself because another metaclass is also used
and it will error out in the subclasses inheriting from the ABC
because ABC does not use PsuedoFunc as it's metaclass

because if a metaclass and inheritance is used together to create a class,
all the bases of that class should be using that same metaclass (or subclass of that metaclass)
for it's creation, since we have to use ABC which is created using the ABCMeta metaclass 
and we have to use PsuedoFunc metaclass to create the PromptStrategy abstract class,

we have to create a metaclass which inherits from both ABCMeta and PsuedoFunc, 
so that classes inheriting from PromptStrategy can also use PseudoFunc
"""


class AbstractPsuedoFunc(ABCMeta, PsuedoFunc):
    pass


class PromptStrategy(metaclass=AbstractPsuedoFunc):
    DEFAULT_EMPTY_MESSAGE = "Password Can't Be Empty!"
    DEFAULT_MISMATCH_MESSAGE = "Passwords Don't Match!"

    @staticmethod
    @abstractmethod
    def __post_init__(
        prompt: str,
        allow_empty: bool = False,
        *,
        empty_message: Optional[str] = None,
    ):
        """prompt user with the provided prompt message and return the reply

        Args:
            prompt_message (str): the message to prompt the user with.
            empty_prompt_message (str, optional): Defaults to "Password Can't be Empty".
            allow_empty (bool, optional):  Defaults to False.
        """
        raise NotImplementedError(
            "__post_init__ not implemented in subclass of abstract class!"
        )

    @staticmethod
    @abstractmethod
    def and_confirm(
        prompt: str,
        confirm_prompt="Confirm Password: ",
        allow_empty: bool = False,
        *,
        empty_message: Optional[str] = None,
        mismatch_message: Optional[str] = None,
    ):
        """
        prompt input from user and ask to input it, again to confirm the input
        if the two instances don't match, the process is repeated till
        a match is obtained

        Args:
            prompt (str): message to the user with
            confirm_prompt (str, optional): confirm message to ask the user
              Defaults to "Confirm Password: ".
            allow_empty (bool, optional): should password to be empty or not.
              Defaults to False.
            empty_message (str, optional): the message to show when password entered
              is empty. if None, use default empty message. Defaults to None.
            mismatch_message (str, optional): message to show when password entered
              does not match second attempt if None use default mismatch message.
              Defaults to None.
        """
        raise NotImplementedError(
            "and_confirm not implemented in subclass of abstract class!"
        )

    @staticmethod
    @abstractmethod
    def until(
        prompt: str,
        breaking_closure: Callable[[str, int, Optional[PynEntry]], Any],
        no_break_closure: Callable[[], Any],
        attempt_count: int = 3,
    ):
        """
        prompts user from user till either the `breaking_closure`
        returns anything other than False or till the attempts run out,
        if that happens the `no_break_closure` is called and
        it's return value is returned

        the breaking_closure can return any type, IF the type returned is a boolean,
        then if it is True, the `current_inputted_password` is returned out of
        the function, else the return value of the breaking_closure is returned out
        the function instead

        Args:
            prompt (str): the message to prompt the user with

            breaking_closure (Callable[[str, int, Optional[PynEntry]], Any])
              Args:
                inputted_reply (str) is the current reply by the user
                attempts_left (int) is the number of attempts
                pynentry_instance (Optional[PynEntry]) if the user has pinentry installed,
                    it is used, and the current instance is passed in as third arg.

            no_break_closure (Callable[[], Any])
               called when no attempts are left for user,
               takes no arguments.

            attempt_count (int, optional): No of Attempts the user has to enter
              the right password. Defaults to 3.
        """
        raise NotImplementedError(
            "until not implemented in subclass of abstract class!"
        )


class TTYAskUser(PromptStrategy, metaclass=PsuedoFunc):
    @staticmethod
    def __post_init__(
        prompt: str,
        allow_empty: bool = False,
        *,
        empty_message: Optional[str] = None,
    ):
        empty_message = (
            TTYAskUser.DEFAULT_EMPTY_MESSAGE if empty_message is None else empty_message
        )
        while reply := getpass(prompt):
            if len(reply) == 0 and not allow_empty:
                click.echo(empty_message)
            else:
                return reply

    @staticmethod
    def and_confirm(
        prompt: str,
        confirm_prompt="Confirm Password: ",
        allow_empty: bool = False,
        *,
        mismatch_message: Optional[str] = None,
        empty_message: Optional[str] = None,
    ):
        mismatch_message = (
            TTYAskUser.DEFAULT_MISMATCH_MESSAGE
            if mismatch_message is None
            else mismatch_message
        )
        empty_message = (
            TTYAskUser.DEFAULT_EMPTY_MESSAGE if empty_message is None else empty_message
        )
        while True:
            reply, confirm_reply = [
                TTYAskUser(prompt, allow_empty, empty_message=empty_message)
                for prompt in [prompt, confirm_prompt]
            ]
            if reply == confirm_reply:
                return reply
            click.echo(mismatch_message)

    @staticmethod
    def until(
        prompt: str,
        breaking_closure: Callable[[str, int, Optional[PynEntry]], Any],
        no_break_closure: Callable[[], Any],
        attempt_count: int = 3,
    ):
        for i in range(1, attempt_count + 1):
            inputted_value = TTYAskUser(prompt)
            closure_result = breaking_closure(
                inputted_value,
                attempt_count - i,
                None,  # pass in PynEntry instance as None so that the closure handles it
            )
            if not isinstance(closure_result, bool):
                return closure_result
            if closure_result:
                return inputted_value
        else:
            # ran out of attempts, proceed with failing case
            return no_break_closure()


class PinentryAskUser(PromptStrategy, metaclass=PsuedoFunc):
    @staticmethod
    def __post_init__(
        prompt: str,
        allow_empty=False,
        *,
        empty_message: Optional[str] = None,
    ) -> str:
        empty_message = empty_message or PinentryAskUser.DEFAULT_EMPTY_MESSAGE
        with PynEntry() as p:
            # vvvvvvvv this is a hook used for prompting the user exactly once
            prompt_user = PinentryAskUser.use_prompt(p, prompt)
            while input_str := prompt_user():
                if input_str == "" and not allow_empty:
                    show_message(empty_message)
                else:
                    return input_str

    @staticmethod
    def use_prompt(
        pynentry_instance: PynEntry, prompt: str
    ) -> Callable[[Optional[str]], str]:
        """
        returns a closure which prompts user for input with the
        specified prompt using the current `pynentry_instance`

        it is also possible to pass a temporary prompt to the closure when calling it,
        which is then reset automatically after the closure runs
        """

        pynentry_instance.prompt = prompt

        def _prompt_user(temp_prompt: Optional[str] = None) -> str:
            """
            prompts user for input and, if it is cancelled, aborts program

            if a prompt is specified as an argument temporarily sets that prompt
            before resetting to old one this is done as to not pollute the PynEntry instance
            """
            # this is here so that if there was an old prompt before this
            # we can use the new prompt and then revert to the old one later
            old_prompt = pynentry_instance.prompt
            if temp_prompt is not None:
                pynentry_instance.prompt = temp_prompt

            try:
                passwd = pynentry_instance.get_pin()
            except PinEntryCancelled:
                sys.stderr.write("operation cancelled! Abort!\n")
                sys.exit()
            pynentry_instance.prompt = old_prompt
            return passwd

        return _prompt_user

    @staticmethod
    def and_confirm(
        prompt: str,
        confirm_prompt="Confirm Password: ",
        allow_empty: bool = False,
        *,
        mismatch_message: Optional[str] = None,
        empty_message: Optional[str] = None,
    ) -> str:
        empty_message = (
            PinentryAskUser.DEFAULT_EMPTY_MESSAGE
            if empty_message is None
            else empty_message
        )
        mismatch_message = (
            PinentryAskUser.DEFAULT_MISMATCH_MESSAGE
            if mismatch_message is None
            else mismatch_message
        )
        with PynEntry() as p:
            prompt_user = PinentryAskUser.use_prompt(p, prompt)
            while True:
                passwd = prompt_user()
                if not passwd and not allow_empty:
                    show_message(empty_message)
                    continue

                confirm_passwd = prompt_user(confirm_prompt)
                if passwd == confirm_passwd:
                    return passwd
                show_message(mismatch_message)

    @staticmethod
    def until(
        prompt: str,
        breaking_closure: Callable[[str, int, Optional[PynEntry]], Any],
        no_break_closure: Callable[[], Any],
        attempt_count: int = 3,
    ):
        with PynEntry() as p:
            prompt_user = PinentryAskUser.use_prompt(p, prompt)
            for current_attmpt_no in reversed(range(attempt_count + 1)):
                user_reply = prompt_user()
                closure_result = breaking_closure(user_reply, current_attmpt_no, p)
                if not isinstance(closure_result, bool):
                    return closure_result
                if closure_result:
                    return user_reply
            else:
                # ran out of attempts, proceed with failing case
                return no_break_closure()


class PipeAskUser(PromptStrategy, metaclass=PsuedoFunc):
    def __post_init__(
        prompt, allow_empty: bool = False, *, empty_message: Optional[str] = None
    ):
        del prompt
        return PipeAskUser.__read_from_stdin(allow_empty, empty_message=empty_message)

    # NOTE: the function signatures for __post_init__ and and_confirm are repeated
    # so that the function *signatures* and documentation the same as that of the
    # abstract class

    def and_confirm(
        prompt: str,
        confirm_prompt="Confirm Password: ",
        allow_empty: bool = False,
        *,
        mismatch_message: Optional[str] = None,
        empty_message: Optional[str] = None,
    ):
        del mismatch_message, confirm_prompt
        return PipeAskUser.__read_from_stdin(allow_empty, empty_message=empty_message)

    def until(
        prompt: str,
        breaking_closure: Callable[[str, int, Optional[PynEntry]], Any],
        no_break_closure: Callable[[], Any],
        attempt_count: int = 3,
    ):
        del attempt_count
        user_reply = PipeAskUser.__read_from_stdin()
        closure_result = breaking_closure(user_reply, 0)
        if not isinstance(closure_result, bool):
            return closure_result
        if closure_result:
            return user_reply
        return no_break_closure()

    def __read_from_stdin(
        allow_empty: bool = False,
        *,
        empty_message: Optional[str],
    ):
        empty_message = PipeAskUser.DEFAULT_EMPTY_MESSAGE
        reply = sys.stdin.read().strip()
        if reply == "" and not allow_empty:
            click.echo(empty_message, err=True)
            exit(1)
        return reply


if which("pinentry"):
    AskUser = PinentryAskUser
elif sys.__stdin__.isatty():
    AskUser = TTYAskUser
else:
    AskUser = PipeAskUser
