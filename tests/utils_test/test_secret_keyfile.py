from utils.keyfiles import SecretKeyFile
from utils.exceptions import Exit
from unittest.mock import Mock, patch, ANY
import pytest


@pytest.mark.parametrize(
    "filename",
    [
        ".sec",
        "no_file_ext",
        "empty_file_ext.",
        "wrong_file_ext.pub",
        "wrong_file_ext.gg",
    ],
)
def test_secret_keyfile_creation(filename, keyfile_parent_dir):
    secret_keyfile_filepath = keyfile_parent_dir / filename
    with pytest.raises(Exit):
        SecretKeyFile(secret_keyfile_filepath)


@pytest.fixture(scope="module")
def secret_keyfile(keyfile_parent_dir):
    return SecretKeyFile(keyfile_parent_dir / "nacl_secret_key.sec")


@patch("utils.keyfiles.SecretKeyFile.file_handler_cls.write")
def test_write_encrypted(write_mock, secret_keyfile: SecretKeyFile):
    mesg_mock = Mock()
    mesg_mock.serialize.return_value = b"serialized bytes"
    secret_keyfile.write(mesg_mock)
    write_mock.assert_called_with(mesg_mock.serialize(), overwrite_mesg=ANY)


@patch("utils.keyfiles.SecretKeyFile.file_handler_cls.read")
@patch(
    "utils.keyfiles.SecretKeyFile.message_type.deserialize",
    return_value=b"deserialized_bytes",
)
def test_reterive_encrypted(deserialize_mock, read_mock, secret_keyfile: SecretKeyFile):
    read_message = secret_keyfile.read()
    read_mock.assert_called()
    deserialize_mock.assert_called()
    assert read_message == deserialize_mock()
