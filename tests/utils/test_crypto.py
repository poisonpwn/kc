from utils import crypto
import pytest

message = b"this is a message."
passwd = "this is a password."


@pytest.fixture
def key_secret_box():
    return crypto.KeySecretBox(passwd)


@pytest.fixture
def cipher_text(key_secret_box: crypto.KeySecretBox):
    return key_secret_box.encrypt(message)


def test_decrypt(key_secret_box, cipher_text):
    plain_text = key_secret_box.decrypt(cipher_text)
    assert plain_text == message


def test_decrypt_classmethod(cipher_text):
    plain_text = crypto.KeySecretBox.decrypt_message(cipher_text, passwd)
    assert plain_text == message
