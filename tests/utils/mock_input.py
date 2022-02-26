import sys
from contextlib import contextmanager


@contextmanager
def replace_stdin(target):
    orig = sys.stdin
    sys.stdin = target
    yield
    sys.stdin = orig
