import os
from pathlib import Path
from functools import wraps
from . import exceptions


def get_home_dir():
    if (home_dir := os.environ.get("XDG_DATA_HOME")) is not None:
        return Path(home_dir)
    return Path.home()


def get_default_value_from_env(env_var, default, constructor=None):
    env_var_value = os.environ.get(env_var)
    if env_var_value is not None:
        if constructor is not None:
            return constructor(env_var_value)
        return env_var_value
    return default


class exit_manager:
    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            return
        if exc_type is not exceptions.Exit:
            raise
        exit(exc_value.error_code)


def exit_if_raised(func):
    @wraps(func)
    def __wrapped_func(*args, **kwargs):
        with exit_manager():
            func(*args, **kwargs)

    return __wrapped_func
