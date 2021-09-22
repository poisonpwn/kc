import pytest
from pass_store import PassStore


@pytest.fixture(scope="module")
def pass_store(tmp_path_factory) -> PassStore:
    pass_store_parent = tmp_path_factory.mktemp("test_pass_store")
    pass_store = PassStore(pass_store_parent, should_create_keystore=False)
    return pass_store


service_name = "test_service_name"
passwd = "test_password"


def test_insert_passwd(pass_store: "PassStore", public_key):
    pass_store.insert_passwd(service_name, passwd, public_key)


@pytest.mark.run(after="test_insert_passwd")
def test_retrieve_passwd(pass_store: "PassStore", secret_key):
    decrypted_pass = pass_store.retrieve_passwd(service_name, secret_key)
    assert decrypted_pass == passwd
