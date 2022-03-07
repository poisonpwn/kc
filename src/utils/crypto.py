from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol, Optional, Tuple, NewType
import pyargon2
import nacl.exceptions
from nacl.secret import SecretBox
from nacl.public import (
    SealedBox,
    PrivateKey as NaclPrivateKey,
    PublicKey as NaclPublicKey,
)
from nacl.utils import random as random_bytes
from .serializible import SerializibleDataclass
from .exceptions import DecryptionError


class EncryptionBox(Protocol):
    def encrypt(message_bytes: bytes) -> bytes:
        pass

    def decrypt(encrypted_message_bytes: bytes) -> bytes:
        pass


class KeyDeriver(ABC):
    salt_size: int

    @abstractmethod
    def derive_key(passwd: str, salt: str, size: int) -> bytes:
        pass


class Argon2KeyDeriver(KeyDeriver):
    salt_size = 32

    @classmethod
    def derive_key(cls, passwd: str, salt: str, size: int):
        return pyargon2.hash(
            password=passwd,
            salt=salt,
            hash_len=size,
            encoding="raw",
        )


@dataclass
class SymmetricEncryptedMessage(SerializibleDataclass):
    mesg: bytes
    salt: str


class SymmetricEncryptionBox:
    key_encryptor: EncryptionBox = SecretBox
    key_deriver: KeyDeriver = Argon2KeyDeriver
    key_size: int = SecretBox.KEY_SIZE
    salt_generator = random_bytes

    def __init__(self, passwd: str, salt: Optional[str] = None):
        if salt is None:
            salt_size = SymmetricEncryptionBox.key_deriver.salt_size
            salt = SymmetricEncryptionBox.salt_generator(salt_size).hex()

        self._salt = salt
        self.encryptor = SymmetricEncryptionBox.key_encryptor(
            self.key_deriver.derive_key(passwd, salt, SymmetricEncryptionBox.key_size)
        )

    @property
    def salt(self):
        return self._salt

    def encrypt(self, message: bytes) -> SymmetricEncryptedMessage:
        return SymmetricEncryptedMessage(self.encryptor.encrypt(message), self.salt)

    def decrypt(self, message: bytes) -> bytes:
        try:
            return self.encryptor.decrypt(message)
        except nacl.exceptions.CryptoError as e:
            raise DecryptionError(*e.args)

    @classmethod
    def decrypt_message(
        cls, passwd: str, encrypted_message: SymmetricEncryptedMessage
    ) -> bytes:
        encryptor = cls(passwd, encrypted_message.salt)
        return encryptor.decrypt(encrypted_message.mesg)


AssymetricEncryptionBox = SealedBox
PublicKey = NaclPublicKey
SecretKey = NaclPrivateKey
AssymetricEncryptedMessage = NewType("AssymetricEncryptedMessage", bytes)


def generate_keypair() -> Tuple[SecretKey, PublicKey]:
    nacl_private_key = NaclPrivateKey.generate()
    nacl_public_key = nacl_private_key.public_key

    return nacl_private_key, nacl_public_key
