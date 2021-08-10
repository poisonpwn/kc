import pynentry
import sys


class PassInput:
    def get_prompt_password_hook(pinentry_instance, prompt):
        pinentry_instance.description = prompt
        pinentry_instance.prompt = ">"

        def __prompt_password():
            try:
                return pinentry_instance.get_pin()
            except pynentry.PinEntryCancelled:
                print("operation cancelled! Aborting!")
                sys.exit()

        return __prompt_password

    def prompt_password_and_confirm(prompt):
        with pynentry.PynEntry() as p:
            prompt_password = PassInput.get_prompt_password_hook(p, prompt)
            while (passwd := prompt_password()) != prompt_password(
                "Confirm Password: "
            ):
                pynentry.show_message("Passwords don't' match! try again! ")

        return passwd

    def prompt_password_until(
        prompt, breaking_closure, no_break_closure, attempt_count=3
    ):
        """
        prompts password from user till either the breaking closure returns True
        or till the attempts run out, if that happens the no_break_closure is run

        the breaking Closure will have the current inputted password as first argument
        the PyEntry instance passed in as second argument
        and the and the number of attempts left passed in as third argument

        if the returned value of the breaking closure is not boolean then it returns that out of the function
        """
        with pynentry.PynEntry() as p:
            prompt_password = PassInput.get_prompt_password_hook(p, prompt)
            for i in range(1, attempt_count + 1):
                password = prompt_password()
                closure_result = breaking_closure(password, p, attempt_count - i)
                if not isinstance(closure_result, bool):
                    return closure_result
                if closure_result:
                    return password
            else:
                no_break_closure()
