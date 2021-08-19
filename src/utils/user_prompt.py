import sys
from pynentry import PynEntry, PinEntryCancelled, show_message
from typing import Callable, Optional, Any
from class_utils import PostInit


class AskUser(metaclass=PostInit):
    def __init__(self, prompt):
        self.prompt = prompt

    def prompt(self):
        with PynEntry() as p:
            prompt_hook = AskUser.use_prompt(p, self.prompt)
            return prompt_hook()

    __post_init__ = prompt

    @staticmethod
    def use_prompt(pynentry_instance: PynEntry, prompt: str) -> Callable[[str], str]:
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
            # we can use the old prompt and then revert to the old one later
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
    def and_confirm(prompt: str, confirm_prompt="Confirm Password: ") -> str:
        """
        prompt input from user and ask to input it, again to confirm the input
        if the two instances don't match, the process is repeated till
        a match is obtained
        """
        with PynEntry() as p:
            prompt_password = AskUser.use_prompt(p, prompt)
            while (passwd := prompt_password()) != prompt_password(confirm_prompt):
                show_message("Passwords don't' match! try again! ")

        return passwd

    @staticmethod
    def until(
        prompt: str,
        breaking_closure: Callable[[str, PynEntry, int], Any],
        no_break_closure: Callable[[], Any],
        attempt_count: int = 3,
    ):
        """
        prompts user from user till either the `breaking_closure`
        returns anything other than False (doesn't have to be a boolean)
        or till the attempts run out, if that happens
        the `no_break_closure` is called without arguments and
        it's return value is returned

        the breaking closure's function signature should look like this
        ```
        def breaking_closure(
            current_inputted_password: str,
            pyentry_instance: pynentry.PynEntry,
            attempts_left: int,
        ) -> Any:
        ```

        the breaking_closure can return any type, IF the type returned is a boolean,
        then if it is True, the `current_inputted_password` is returned out of
        the function, else the return value of the breaking_closure is returned out
        the function instead
        """
        with PynEntry() as p:
            prompt_user = AskUser.use_prompt(p, prompt)
            for i in range(1, attempt_count + 1):
                inputted_value = prompt_user()
                closure_result = breaking_closure(inputted_value, p, attempt_count - i)
                if not isinstance(closure_result, bool):
                    return closure_result
                if closure_result:
                    return inputted_value
            else:
                # ran out of attempts, proceed with failing case
                return no_break_closure()


if __name__ == "__main__":
    print(AskUser("Enter something: "))
