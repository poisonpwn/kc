import os
from pathlib import Path


def get_home_dir():
    if (home_dir := os.environ.get("XDG_DATA_HOME")) is not None:
        return Path(home_dir)
    return Path.home()
