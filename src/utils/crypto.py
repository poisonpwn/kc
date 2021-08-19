from typing import Optional
from pyargon2 import hash
from nacl.secret import SecretBox
from nacl.encoding import RawEncoder
from nacl.utils import random


class KeySecretBox(SecretBox):
    """
    creates a SecretBox from a key derived from
    the password and salt passed in,
    using the argon2 key derivation function
    """

    KDF_SALT_BYTES = 32

    def __init__(self, passwd: str, salt: Optional[str] = None, encoding=RawEncoder):
        if salt is None:
            salt = random(KeySecretBox.KDF_SALT_BYTES).hex()
        self.salt: str = salt
        derived_symmetric_key = hash(
            passwd,
            self.salt,
            hash_len=SecretBox.KEY_SIZE,
            encoding="raw",
        )
        super().__init__(derived_symmetric_key, encoding)


if __name__ == "__main__":
    box = KeySecretBox("hello, world")
    print(box.encrypt(b"this is not a good password").hex())
    print(box.salt)
