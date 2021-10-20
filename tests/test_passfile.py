import pytest
from pass_store import PasswdFile
from utils.exceptions import EmptyError
from utils.exceptions import PasswdFileExistsErr


@pytest.fixture(autouse=True, scope="module")
def passfile_parent(tmp_path_factory):
    return tmp_path_factory.mktemp("passfile_parent")


def test_empty_filename():
    with pytest.raises(EmptyError):
        PasswdFile.from_service_name("", passfile_parent)


@pytest.fixture(autouse=True, scope="module")
def pass_file(passfile_parent, service_name="service_name"):
    pass_file = PasswdFile.from_service_name(service_name, passfile_parent)
    return pass_file


passwd = "M0Ms_-Sp46h377i"


def test_passwd_write(pass_file: PasswdFile, public_key):
    pass_file.write_passwd(passwd, public_key)
    with pytest.raises(PasswdFileExistsErr):
        pass_file.write_passwd(passwd, public_key)


@pytest.mark.run(before="test_passwd_write")
def test_nonexistant_read(pass_file: PasswdFile, secret_key):
    with pytest.raises(FileNotFoundError):
        pass_file.retrieve_passwd(secret_key)


@pytest.mark.run(after="test_passwd_write")
def test_password_read(pass_file: PasswdFile, secret_key):
    decrpyted_passwd = pass_file.retrieve_passwd(secret_key)
    assert decrpyted_passwd == passwd
