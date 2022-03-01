import pytest
from utils.symmetric_crypto import SymmetricEncryptor, SymmetricEncryptedMessage

message = b"test message"
passwd = "test passwd"


@pytest.fixture(scope="module")
def encryptor():
    return SymmetricEncryptor(passwd)


@pytest.fixture()
def encrypted_message(encryptor):
    return encryptor.encrypt(message)


def test_decrypt_message(encryptor, encrypted_message: SymmetricEncryptedMessage):
    decrypted_message = encryptor.decrypt(encrypted_message.message)
    assert decrypted_message == message
