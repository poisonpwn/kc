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


class EmptyError(Exception):
    """Error raised an invalid empty value is found"""
