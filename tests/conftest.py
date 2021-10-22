import pytest
from nacl.public import PrivateKey
from random import choices, shuffle
from string import ascii_letters, digits, punctuation
from shutil import rmtree


@pytest.fixture(scope="session")
def secret_key():
    return PrivateKey.generate()


@pytest.fixture(scope="session")
def public_key(secret_key: PrivateKey):
    return secret_key.public_key


@pytest.fixture(scope="session")
def master_passwd():
    passwd_char_list = [
        *choices(ascii_letters, k=6),
        *choices(digits, k=4),
        *choices(punctuation, k=3),
    ]
    shuffle(passwd_char_list)
    return "".join(passwd_char_list)


@pytest.fixture(scope="session", autouse=True)
def keyfile_parent_dir(tmp_path_factory):
    keyfile_parent_dir = tmp_path_factory.mktemp("keyfile_parent_dir")
    yield keyfile_parent_dir
    rmtree(keyfile_parent_dir)
