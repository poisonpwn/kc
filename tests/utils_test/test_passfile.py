from pathlib import Path
from unittest.mock import Mock, patch, ANY

import click.exceptions
import pytest
import utils.exceptions
from tests.tools import random_chars
from utils.fs_handler import FsHandler
from utils.keyfiles import PasswdFile


@pytest.mark.parametrize(
    "filename",
    [
        ".enc",
        "no_file_ext",
        "empty_file_ext.",
        "wrong_file_ext.sec",
        "wrong_file_ext.pub",
    ],
)
def test_passwd_file_creation(filename):
    with pytest.raises(utils.exceptions.Exit):
        PasswdFile(Path(filename))


@pytest.fixture(autouse=True, scope="module")
def passwd_file():
    path_mock = Mock(spec=Path)
    path_mock.suffix = PasswdFile.PASSWD_FILE_EXT
    passwd_file = PasswdFile(path_mock)
    yield passwd_file
    passwd_file.path.reset_mock()


encrypted_passwd_bytes = bytes(random_chars(12), "utf-8")


@patch.object(FsHandler, "write")
def test_passwd_write(write_mock, passwd_file: PasswdFile):
    passwd_file.write(encrypted_passwd_bytes)
    write_mock.assert_called_with(encrypted_passwd_bytes, overwrite_mesg=ANY)


@patch.object(FsHandler, "read", return_value=b"return value bytes")
def test_passwd_read(read_mock, passwd_file: PasswdFile):
    return_value_bytes = read_mock.return_value
    read_bytes = passwd_file.read()
    assert read_bytes == return_value_bytes


def test_remove_abort(passwd_file: PasswdFile):
    passwd_file.path.exists.return_value = True
    with pytest.raises(utils.exceptions.Exit):
        with patch("click.confirm", side_effect=click.exceptions.Abort):
            passwd_file.remove()
    passwd_file.path.unlink.assert_not_called()


def test_remove_confirmed(passwd_file: PasswdFile):
    passwd_file.path.exists.return_value = True
    with patch("click.confirm", return_value=None):
        passwd_file.remove()
    passwd_file.path.unlink.assert_called()


@pytest.fixture(scope="module")
def alias_path_mock():
    return Mock(spec=Path)


def test_alias_nonexistant_source(
    passwd_file: PasswdFile,
    alias_path_mock: Mock,
):
    passwd_file.path.exists.return_value = False
    with pytest.raises(FileNotFoundError):
        passwd_file.alias(alias_path_mock)
    passwd_file.path.symlink_to.assert_not_called()
    passwd_file.path.mkdir.assert_not_called()


def test_alias(
    passwd_file: PasswdFile,
    alias_path_mock: Mock,
):
    passwd_file.path.exists.return_value = True
    passwd_file.alias(alias_path_mock)
    alias_path_mock.parent.mkdir.assert_called()
    alias_path_mock.symlink_to.assert_called_with(
        passwd_file.path, target_is_directory=False
    )
