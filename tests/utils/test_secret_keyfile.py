from nacl.public import PrivateKey
from utils.keyfiles import SecretKeyFile
import utils.exceptions as exceptions
import pytest


@pytest.mark.parametrize(
    "filename",
    [
        ".enc",
        "no_file_ext",
        "empty_file_ext.",
        "wrong_file_ext.pub",
        "wrong_file_ext.gg",
    ],
)
def test_secret_keyfile_creation(filename, keyfile_parent_dir):
    secret_keyfile_filepath = keyfile_parent_dir / filename
    with pytest.raises(exceptions.InvalidFilenameErr):
        SecretKeyFile(secret_keyfile_filepath)


@pytest.fixture(scope="module")
def secret_keyfile(keyfile_parent_dir):
    return SecretKeyFile(keyfile_parent_dir / "nacl_secret_key.enc")


def test_write_encrypted(
    secret_key: PrivateKey, secret_keyfile: SecretKeyFile, master_passwd: str
):
    assert not secret_keyfile.exists()
    secret_keyfile.write_encrypted(
        secret_key, master_passwd, should_print_write_mesg=False
    )
    assert secret_keyfile.exists()


def test_reterive_encrypted(
    secret_key: PrivateKey, secret_keyfile: SecretKeyFile, master_passwd
):
    assert secret_keyfile.exists()
    decrypted_secret_key = secret_keyfile.retrieve(master_passwd)
    assert decrypted_secret_key == secret_key
    # NOTE: keyfiles get deleted when the whole keyfiles
    # directory gets nuked in conftest.py after yield
