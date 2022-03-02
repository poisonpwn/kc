from abc import ABC, abstractmethod
from dataclasses import dataclass
import pyargon2
from nacl.secret import SecretBox
from nacl.utils import random as random_bytes
from typing import Optional
from .serializible import SerializibleDataclass


class Encryptor(ABC):
    @abstractmethod
    def encrypt(bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(bytes) -> bytes:
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
        return pyargon2.hash(password=passwd, salt=salt, hash_len=size, encoding="raw")


@dataclass
class SymmetricEncryptedMessage(SerializibleDataclass):
    message: bytes
    salt: bytes


class SymmetricEncryptor:
    key_encryptor: Encryptor = SecretBox
    key_deriver: KeyDeriver = Argon2KeyDeriver
    key_size: int = SecretBox.KEY_SIZE
    salt_generator = random_bytes

    def __init__(self, passwd: str, salt: Optional[bytes] = None):
        if salt is None:
            salt_size = SymmetricEncryptor.key_deriver.salt_size
            salt = SymmetricEncryptor.salt_generator(salt_size).hex()

        self._salt = salt
        self.encryptor = SymmetricEncryptor.key_encryptor(
            self.key_deriver.derive_key(passwd, salt, SymmetricEncryptor.key_size)
        )

    @property
    def salt(self):
        return self._salt

    def encrypt(self, message: bytes) -> SymmetricEncryptedMessage:
        return SymmetricEncryptedMessage(self.encryptor.encrypt(message), self.salt)

    def decrypt(self, message: bytes) -> bytes:
        return self.encryptor.decrypt(message)

    @classmethod
    def decrypt_message(
        cls, passwd: str, encrypted_message: SymmetricEncryptedMessage
    ) -> bytes:
        encryptor = cls(passwd, encrypted_message.salt)
        return encryptor.decrypt(encrypted_message.message)
