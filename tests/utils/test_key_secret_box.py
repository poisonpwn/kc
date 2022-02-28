from utils import crypto
import pytest

message = b"this is a message."
passwd = "this is a password."


@pytest.fixture(autouse=True, scope="module")
def key_secret_box():
    return crypto.KeySecretBox(passwd)


@pytest.fixture(scope="module")
def encrypted_message(
    key_secret_box: crypto.KeySecretBox,
) -> crypto.PassEncryptedMessage:
    return key_secret_box.encrypt(message)


def test_decrypt(key_secret_box, encrypted_message):
    plain_text = key_secret_box.decrypt(encrypted_message)
    assert plain_text == message


def test_decrypt_classmethod(encrypted_message):
    plain_text = crypto.KeySecretBox.decrypt_message(encrypted_message, passwd)
    assert plain_text == message
