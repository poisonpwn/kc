import pytest
from utils.crypto import (
    SymmetricEncryptionBox,
    SymmetricEncryptedMessage,
    AssymetricEncryptionBox,
    generate_keypair,
)

mesg = b"test message"
passwd = "test passwd"


@pytest.fixture(scope="module")
def symmetric_encryptor():
    return SymmetricEncryptionBox(passwd)


@pytest.fixture()
def symmetric_encrypted_mesg(symmetric_encryptor):
    return symmetric_encryptor.encrypt(mesg)


def test_symmetric_decrypt(
    symmetric_encryptor, symmetric_encrypted_mesg: SymmetricEncryptedMessage
):
    decrypted_mesg = symmetric_encryptor.decrypt(symmetric_encrypted_mesg.mesg)
    assert decrypted_mesg == mesg


@pytest.fixture(scope="module")
def key_pair():
    return generate_keypair()


@pytest.fixture(scope="module")
def assymetric_encryptor(key_pair):
    _, public_key = key_pair
    return AssymetricEncryptionBox(public_key)


@pytest.fixture(scope="module")
def assymetric_decryptor(key_pair):
    secret_key, _ = key_pair
    return AssymetricEncryptionBox(secret_key)


@pytest.fixture(scope="module")
def assymetric_encrypted_mesg(assymetric_encryptor):
    return assymetric_encryptor.encrypt(mesg)


def test_assymetric_decrypt(assymetric_encrypted_mesg, assymetric_decryptor):
    decrypted_mesg = assymetric_decryptor.decrypt(assymetric_encrypted_mesg)
    assert decrypted_mesg == mesg
