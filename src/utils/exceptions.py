class SameKeyFileError(Exception):
    """Error raised when public key and secret key file have the same path"""

    def __init__(self, path, *args):
        self.path = path
        super().__init__(*args)


class Exit(Exception):
    """Error raised program exit is unavoidable"""

    def __init__(self, error_code: int = 0, *args):
        self.error_code = error_code
        super().__init__(*args)


class InvalidFilenameErr(Exception):
    """Error raised when invalid filename argument is passed in"""


class PasswdFileExistsErr(Exception):
    """Error raised when a keyfile is attempted to be entered
    into the keystore but it already exists"""


class EmptyError(Exception):
    """Error raised an invalid empty value is found"""


class StdinError(Exception):
    """Error raised when password via stdin cannot be handled gracefully."""


class InvalidPasswordError(Exception):
    """Error raised when password doesn't comply with criteria"""
