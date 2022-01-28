import pytest
from pass_store import PasswdStore


@pytest.fixture(scope="module")
def pass_store(tmp_path_factory) -> PasswdStore:
    pass_store_parent = tmp_path_factory.mktemp("test_pass_store")
    pass_store = PasswdStore(pass_store_parent)
    return pass_store


service_name = "test_service_name"
passwd = "test_password"


def test_insert_passwd(pass_store: "PasswdStore", public_key):
    pass_store.insert_passwd(service_name, passwd, public_key)


@pytest.mark.run(after="test_insert_passwd")
def test_retrieve_passwd(pass_store: "PasswdStore", secret_key):
    get_secret_key_callback = lambda: secret_key
    decrypted_pass = pass_store.retrieve_passwd(service_name, get_secret_key_callback)
    assert decrypted_pass == passwd
