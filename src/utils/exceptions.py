class SameKeyFileError(Exception):
    """Error raised when public key and secret key file have the same path"""

    def __init__(self, path, message):
        self.path = path
        self.message = message
        super().__init__(message)


class PostInitNotFoundErr(Exception):
    """Error raised when PseudoFunc metaclass was attempted to use a create a class,
    but the class did not contain __post_init__ function to run after init"""

    pass


class InvalidFilenameErr(Exception):
    """Error raised when invalid filename argument is passed in"""

    pass


class PassFileExistsErr(Exception):
    """Error raised when a keyfile is attempted to be entered
    into the keystore but it already exists"""

    pass


class EmptyError(Exception):
    """Error raised an invalid empty value is found"""

    pass


class InvalidPasswordError(Exception):
    """Error raised when password doesn't comply with criteria"""

    pass
