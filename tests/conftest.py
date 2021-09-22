import pytest
from nacl.public import PrivateKey


@pytest.fixture(scope="session")
def secret_key():
    return PrivateKey.generate()


@pytest.fixture
def public_key(secret_key: PrivateKey):
    return secret_key.public_key
