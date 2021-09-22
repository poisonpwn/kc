import pytest
from pass_store import PassStore


@pytest.fixture(scope="module")
def pass_store(tmp_path_factory) -> PassStore:
    pass_store_parent = tmp_path_factory.mktemp("test_pass_store")
    pass_store = PassStore(pass_store_parent, should_create_keystore=False)
    return pass_store


@pytest.fixture
def inserted_credentials(pass_store: "PassStore", public_key):
    service_name = "service_name"
    passwd = "test_password"
    pass_store.insert_passwd(service_name, passwd, public_key)
    return service_name, passwd


def test_retrieve_passwd(pass_store: "PassStore", inserted_credentials, secret_key):
    service_name, passwd = inserted_credentials
    decrypted_pass = pass_store.retrieve_passwd(service_name, secret_key)
    assert decrypted_pass == passwd
