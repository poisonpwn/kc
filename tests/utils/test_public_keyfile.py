import utils.exceptions as exceptions
from utils.keyfiles import PublicKeyFile
import pytest


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
    with pytest.raises(exceptions.InvalidFilenameErr):
        keyfile_path = keyfile_parent_dir / filename
        PublicKeyFile(keyfile_path)


@pytest.fixture(scope="module")
def public_keyfile(keyfile_parent_dir):
    return PublicKeyFile(keyfile_parent_dir / "nacl_public_key.pub")


def test_write(public_key, public_keyfile: PublicKeyFile):
    assert not public_keyfile.exists()
    public_keyfile.write(public_key, should_print_write_mesg=False)
    assert public_keyfile.exists()


@pytest.mark.run(after="test_write")
def test_read(public_key, public_keyfile: PublicKeyFile):
    read_public_key = public_keyfile.retrieve()
    assert read_public_key == public_key
