from utils.keyfiles import PasswdFile
from utils.exceptions import EmptyError
from utils.exceptions import PasswdFileExistsErr
from pathlib import Path
from nacl.public import PrivateKey
import shutil
import pytest


@pytest.fixture(autouse=True, scope="module")
def passfile_parent(tmp_path_factory) -> Path:
    parent_dir: Path = tmp_path_factory.mktemp("passfile_parent")
    yield parent_dir
    shutil.rmtree(parent_dir)


def test_empty_service_name(passfile_parent):
    with pytest.raises(EmptyError):
        PasswdFile.from_service_name("", passfile_parent)


def test_malicious_service_name(passfile_parent: Path):
    malicious_service_name = "nested_folder/../../../../service_name"
    passwd_file = PasswdFile.from_service_name(malicious_service_name, passfile_parent)
    assert passwd_file.with_suffix("") == passfile_parent / "service_name"


@pytest.fixture(autouse=True, scope="module")
def pass_file(passfile_parent, service_name="service_name"):
    pass_file = PasswdFile.from_service_name(service_name, passfile_parent)
    assert not pass_file.exists()
    yield pass_file


passwd = "M0Ms_-Sp46h377i"
tmp_alias_path_tails = ["parent_folder/nested_service_name.ext", "something.ext"]


@pytest.mark.run(before="test_passwd_write")
def test_nonexistant_read(
    pass_file: PasswdFile,
    secret_key: PrivateKey,
):
    assert not pass_file.exists()
    get_secret_key_callback = lambda: secret_key
    with pytest.raises(FileNotFoundError):
        pass_file.retrieve_passwd(get_secret_key_callback)


@pytest.mark.run(before="test_passwd_write")
@pytest.mark.parametrize("tmp_alias_dest_path_tail", tmp_alias_path_tails)
def test_alias_nonexistant_source(
    pass_file: PasswdFile,
    passfile_parent: Path,
    tmp_alias_dest_path_tail: str,
):
    assert not pass_file.exists()
    tmp_alias_dest_path = (
        passfile_parent / tmp_alias_dest_path_tail
    )  # can't be made fixture cause of test ordering and parametrization
    with pytest.raises(FileNotFoundError):
        pass_file.alias(tmp_alias_dest_path)
    assert not tmp_alias_dest_path.exists()


def test_passwd_write(pass_file: PasswdFile, public_key):
    assert not pass_file.exists()
    pass_file.write_passwd(passwd, public_key)
    assert pass_file.exists()
    with pytest.raises(PasswdFileExistsErr):
        pass_file.write_passwd(passwd, public_key)


@pytest.mark.run(after="test_passwd_write")
def test_password_read(pass_file: PasswdFile, secret_key):
    assert pass_file.exists()
    get_secret_key_callback = lambda: secret_key
    decrpyted_passwd = pass_file.retrieve_passwd(get_secret_key_callback)
    assert decrpyted_passwd == passwd


@pytest.mark.run(after="test_passwd_write")
@pytest.mark.parametrize("tmp_alias_dest_path_tail", tmp_alias_path_tails)
def test_alias(
    pass_file: PasswdFile, passfile_parent: Path, tmp_alias_dest_path_tail: str
):
    assert pass_file.exists()
    tmp_alias_dest_path = passfile_parent / tmp_alias_dest_path_tail
    pass_file.alias(tmp_alias_dest_path)
    assert tmp_alias_dest_path.exists()
    assert tmp_alias_dest_path.is_symlink()
    assert tmp_alias_dest_path.readlink() == pass_file
