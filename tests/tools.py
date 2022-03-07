import sys
from contextlib import contextmanager
from string import ascii_letters, digits, punctuation
from random import choices


def random_chars(size: int):
    return "".join(choices(random_chars.char_choices, k=size))


random_chars.char_choices = f"{ascii_letters}{digits}{punctuation}"
