import os
from pathlib import Path


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
