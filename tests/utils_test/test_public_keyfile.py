import utils.exceptions as exceptions
from utils.keyfiles import PublicKeyFile
import pytest
from unittest.mock import patch


@pytest.mark.parametrize(
    "filename",
    [
        ".pub",
        "empty_file_ext.",
        "no_file_ext",
        "wrong_file_ext.enc",
        "wrong_file_ext.gg",
    ],
)
def test_public_keyfile_creation(filename, keyfile_parent_dir):
    with pytest.raises(exceptions.Exit):
        keyfile_path = keyfile_parent_dir / filename
        PublicKeyFile(keyfile_path)


@pytest.fixture(scope="module")
def public_keyfile(keyfile_parent_dir):
    return PublicKeyFile(keyfile_parent_dir / "nacl_public_key.pub")


@patch("utils.keyfiles.PublicKeyFile.file_handler_cls.write")
def test_write(write_mock, public_key, public_keyfile: PublicKeyFile):
    public_keyfile.write(public_key)
    write_mock.assert_called()


@patch(
    "utils.keyfiles.PublicKeyFile.file_handler_cls.read",
    return_value=b"return value bytes",
)
def test_read(read_mock, public_keyfile: PublicKeyFile):
    return_value_bytes = read_mock.return_value
    read_bytes = public_keyfile.read()
    assert read_bytes == return_value_bytes
