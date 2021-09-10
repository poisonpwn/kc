from base64 import encode
from typing import Optional
from pyargon2 import hash
from nacl.secret import SecretBox, EncryptedMessage
from nacl import encoding
from nacl.utils import random


class KeySecretBox(SecretBox):
    """
    creates a SecretBox from a key derived from
    the password, using argon2 key derivation
    """

    KDF_SALT_BYTES = 32

    def __init__(
        self, passwd: str, salt: Optional[str] = None, encoding=encoding.RawEncoder
    ):

        """Create a SecretBox from the password provided,
        optionallly also provide a salt, which should be used when deriving the key
        otherwise, a salt is randomly generated
        """

        if salt is None:
            salt = random(KeySecretBox.KDF_SALT_BYTES).hex()
        self.salt = salt
        derived_symmetric_key = hash(
            passwd,
            self.salt,
            hash_len=SecretBox.KEY_SIZE,
            encoding="raw",
        )
        super().__init__(derived_symmetric_key, encoding)

    def encrypt(
        self, plain_text, nonce=None, encoding=encoding.RawEncoder
    ) -> "PassEncryptedMessage":
        nacl_encrypted_message = super().encrypt(plain_text, nonce, encoding)
        return PassEncryptedMessage.from_nacl_encrypted_message(
            self.salt, nacl_encrypted_message
        )

    @classmethod
    def decrypt_message(
        cls,
        encrypted_message: "PassEncryptedMessage",
        passwd: str,
        nonce=None,
        encoding=encoding.RawEncoder,
    ):
        secret_box = cls(passwd, encrypted_message.salt)
        return secret_box.decrypt(
            encrypted_message,
            nonce,
            encoding,
        )


class PassEncryptedMessage(EncryptedMessage):
    """an nacl.secret.EncryptedMessages subclass (bytes subclass)
    that holds an Encrypted message and the salt that was used to encrypt it
    """

    def __new__(cls, cipher_text, salt: str, **kwargs):
        encrypted_message = super().__new__(cls, cipher_text, **kwargs)
        encrypted_message.salt = salt
        return encrypted_message

    @classmethod
    def from_nacl_encrypted_message(
        cls, salt: str, encrypted_message: EncryptedMessage
    ):
        encrypted_message.salt = salt
        encrypted_message.__class__ = cls
        return encrypted_message

    @classmethod
    def from_hex_combined(cls, message_hex, salt_seperator="|"):
        encrypted_message, _, salt = message_hex.partition(salt_seperator)
        return cls(bytes.fromhex(encrypted_message), salt)

    def to_hex_combined(self, delim="|") -> str:
        return delim.join([self.hex(), self.salt])

    def __eq__(self, other) -> bool:
        return super().__eq__(other) and self.salt == other.salt

    def __ne__(self, other) -> bool:
        return not (self == other)