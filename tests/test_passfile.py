import pytest
from pass_store import PassFile
from utils.exceptions import EmptyError
from utils.exceptions import PassFileExistsErr


@pytest.fixture(autouse=True, scope="session")
def pass_file(tmp_path_factory, service_name="service_name"):
    passfile_parent = tmp_path_factory.mktemp("passfile_parent")
    with pytest.raises(EmptyError):
        PassFile.from_service_name("", passfile_parent)
    pass_file = PassFile.from_service_name(service_name, passfile_parent)
    return pass_file


@pytest.mark.run(before="test_passwd_write")
def test_nonexistant_read(pass_file: PassFile, secret_key):
    with pytest.raises(FileNotFoundError):
        pass_file.retrieve_passwd(secret_key)


passwd = "test password in pass store"


def test_passwd_write(pass_file: PassFile, public_key):
    pass_file.write_passwd(passwd, public_key)
    with pytest.raises(PassFileExistsErr):
        pass_file.write_passwd(passwd, public_key)


@pytest.mark.run(after="test_passwd_write")
def test_password_read(pass_file: PassFile, secret_key):
    decrpyted_passwd = pass_file.retrieve_passwd(secret_key)
    assert decrpyted_passwd == passwd
