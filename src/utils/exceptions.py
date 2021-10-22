class SameKeyFileError(Exception):
    """Error raised when public key and secret key file have the same path"""

    def __init__(self, path, message):
        self.path = path
        self.message = message
        super().__init__(message)


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
