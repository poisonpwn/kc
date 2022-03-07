class DecryptionError(Exception):
    """error raised when decryption fails"""


class Exit(Exception):
    """Error raised program exit is unavoidable"""

    def __init__(self, message: str, error_code: int = 1, stderr=True, *args):
        self.stderr = stderr
        self.error_code = error_code
        super().__init__(message, *args)
