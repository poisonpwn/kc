from utils.keyfiles import PasswdFile
from utils.exceptions import EmptyError, Exit
from .mock_input import replace_stdin
from pathlib import Path
from io import StringIO
from nacl.public import PrivateKey
from string import ascii_letters
from random import choices
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


@pytest.mark.parametrize(
    "malicious_service_name_pair",
    [
        ("nested_folder/../../../../test_service_name_0", "test_service_name_0"),
        ("../test_service_name_1", "test_service_name_1"),
    ],
)
def test_malicious_service_name(
    malicious_service_name_pair: str, passfile_parent: Path
):
    malicious_service_name, resolved_service_name = malicious_service_name_pair
    passwd_file = PasswdFile.from_service_name(malicious_service_name, passfile_parent)
    assert passwd_file.with_suffix("") == passfile_parent / resolved_service_name


@pytest.fixture(autouse=True, scope="module")
def pass_file(passfile_parent):
    service_name = "".join(choices(ascii_letters, k=10))
    pass_file = PasswdFile.from_service_name(service_name, passfile_parent)
    assert not pass_file.exists()
    yield pass_file


passwd = "M0Ms_-Sp46h377i"


@pytest.fixture(params=["parent_folder/nested_service_name.ext", "something.ext"])
def tmp_alias_dest_path(passfile_parent: Path, request):
    path = passfile_parent / request.param
    yield path
    path.unlink(missing_ok=True)


@pytest.mark.order(before="test_passwd_write")
def test_nonexistant_read(
    pass_file: PasswdFile,
    secret_key: PrivateKey,
):
    assert not pass_file.exists()
    get_secret_key_callback = lambda: secret_key
    with pytest.raises(FileNotFoundError):
        pass_file.retrieve_passwd(get_secret_key_callback)


@pytest.mark.order(before="test_passwd_write")
def test_alias_nonexistant_source(pass_file: PasswdFile, tmp_alias_dest_path: Path):
    assert not pass_file.exists()
    with pytest.raises(FileNotFoundError):
        pass_file.alias(tmp_alias_dest_path)
    assert not tmp_alias_dest_path.exists()


@pytest.mark.dependency(name="passwd write")
def test_passwd_write(pass_file: PasswdFile, public_key):
    assert not pass_file.exists()
    pass_file.write_passwd(passwd, public_key)
    assert pass_file.exists()
    with pytest.raises(Exit):
        with replace_stdin(StringIO("n")):
            pass_file.write_passwd(passwd, public_key)


@pytest.mark.dependency(name="passwd read", depends=["passwd write"])
@pytest.mark.order(after="test_passwd_write")
def test_passwd_read(pass_file: PasswdFile, secret_key):
    assert pass_file.exists()
    get_secret_key_callback = lambda: secret_key
    decrpyted_passwd = pass_file.retrieve_passwd(get_secret_key_callback)
    assert decrpyted_passwd == passwd


@pytest.mark.dependency(depends=["passwd write"])
@pytest.mark.order(after="test_passwd_write")
def test_alias(pass_file: PasswdFile, tmp_alias_dest_path: Path):
    assert pass_file.exists()
    pass_file.alias(tmp_alias_dest_path)
    assert tmp_alias_dest_path.exists()
    assert tmp_alias_dest_path.is_symlink()
    assert tmp_alias_dest_path.readlink() == pass_file


@pytest.mark.dependency(depends=["passwd read"])
@pytest.mark.order(after="test_passwd_read")
def test_password_overwrite(pass_file: PasswdFile, secret_key, public_key):
    assert pass_file.exists()
    overwritten_passwd = "OVERWRITTEN_PASS"
    with replace_stdin(StringIO("y")):
        pass_file.write_passwd(overwritten_passwd, public_key)
    secret_key_callback = lambda: secret_key
    decrypted_pass = pass_file.retrieve_passwd(secret_key_callback)
    assert decrypted_pass == overwritten_passwd
