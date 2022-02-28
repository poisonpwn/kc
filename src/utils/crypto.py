from typing import Optional

import pyargon2
import bson
from nacl import encoding
from nacl.secret import EncryptedMessage, SecretBox
from nacl.utils import random as random_bytes


class KeySecretBox(SecretBox):
    """creates a SecretBox from a key derived from
    the password, using argon2 key derivation
    """

    KDF_SALT_BYTES = 32

    def __init__(
        self, passwd: str, salt: Optional[str] = None, encoding=encoding.RawEncoder
    ):
        """Create a SecretBox from the password provided,
        the salt argument, if specified, will be used to derive the key
        else a random salt is generated.
        """

        if salt is None:
            salt = random_bytes(KeySecretBox.KDF_SALT_BYTES).hex()

        self._salt = salt
        derived_symmetric_key = pyargon2.hash(
            passwd,
            salt,
            hash_len=SecretBox.KEY_SIZE,
            encoding="raw",
        )
        super().__init__(derived_symmetric_key, encoding)

    @property
    def salt(self):
        return self._salt

    def encrypt(
        self, plain_text, nonce=None, encoding=encoding.RawEncoder
    ) -> "PassEncryptedMessage":
        """encrypt the message and return the ciphertext.
        encode using the specified encoding format"""

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
        """decrypt the message using the provided password and return the plaintext.

        Args:
            encrypted_message (PassEncryptedMessage): the message to decrypt
            passwd (str): the password to decrypt the message with
            nonce ([type], optional): Number used ONCE, to be used when decrypting
              if nonce is None, it is assumed that the message object contains the nonce.
              Defaults to None.
            encoding (encoding.Encoder, optional): [description]. Defaults to encoding.RawEncoder.
              the encoder to be used to encode the plaintext.

        Returns:
            Any: the decrypted message
        """
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

    @classmethod
    def from_nacl_encrypted_message(cls, salt, encrypted_message: EncryptedMessage):
        obj = cls(encrypted_message)
        obj.__dict__.update(encrypted_message.__dict__)
        obj._salt = salt
        return obj

    def __bytes__(self):
        return bson.dumps(
            {
                k: v
                for k, v in self.__dict__.items()
                if k in ["_ciphertext", "_salt", "_nonce"]
            }
        )

    @classmethod
    def from_bytes(cls, message_bytes):
        parsed_bson = bson.loads(message_bytes)
        obj = cls(parsed_bson["_nonce"] + parsed_bson["_ciphertext"])
        obj.__dict__.update(parsed_bson)
        return obj

    @property
    def salt(self):
        return self._salt

    def __eq__(self, other) -> bool:
        eq = super().__eq__(other)
        if isinstance(other, PassEncryptedMessage):
            return eq and other.salt == self.salt
        return eq

    def __ne__(self, other) -> bool:
        return not (self == other)
