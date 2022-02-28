from utils.crypto import PassEncryptedMessage
from nacl.utils import random as random_bytes
from nacl.secret import SecretBox, EncryptedMessage
import pyargon2
import pytest


SALT_SIZE = 40
PASSWD = "some_test_passwd"
MESG = b"this is is a test message"


@pytest.fixture(scope="module")
def salt():
    return random_bytes(SALT_SIZE).hex()


@pytest.fixture(scope="module")
def secret_key_bytes(salt):
    return pyargon2.hash(
        PASSWD,
        salt,
        hash_len=SecretBox.KEY_SIZE,
        encoding="raw",
    )


@pytest.fixture(scope="module")
def nacl_encrypted_message(secret_key_bytes):
    return SecretBox(secret_key_bytes).encrypt(MESG)


@pytest.fixture(scope="module")
def pass_encrypted_message(nacl_encrypted_message: EncryptedMessage, salt: str):
    pass_encrypted_mesg = PassEncryptedMessage.from_nacl_encrypted_message(
        salt, nacl_encrypted_message
    )
    assert pass_encrypted_mesg.salt == salt
    assert pass_encrypted_mesg.nonce == nacl_encrypted_message.nonce
    assert pass_encrypted_mesg.ciphertext == nacl_encrypted_message.ciphertext
    return pass_encrypted_mesg


def test_serialize_deserialize(pass_encrypted_message):
    serialized = bytes(pass_encrypted_message)
    deserialized = PassEncryptedMessage.from_bytes(serialized)
    assert deserialized.salt == pass_encrypted_message.salt
    assert deserialized.nonce == pass_encrypted_message.nonce
    assert deserialized.ciphertext == pass_encrypted_message.ciphertext
