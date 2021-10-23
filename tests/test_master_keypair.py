from master_keypair import MasterKeyPair
from utils.keyfiles import PublicKeyFile, SecretKeyFile
from nacl.public import SealedBox
import pytest


@pytest.fixture(scope="module")
def master_keypair(tmp_path_factory):
    secret_keyfile = SecretKeyFile(
        tmp_path_factory.mktemp("secret_file_parent")
        / f"seckey.{SecretKeyFile.SECKEY_FILE_EXT}"
    )
    public_keyfile = PublicKeyFile(
        tmp_path_factory.mktemp("public_key_parent")
        / f"pubkey.{PublicKeyFile.PUBKEY_FILE_EXT}"
    )

    master_keypair = MasterKeyPair(secret_keyfile, public_keyfile)

    yield master_keypair

    master_keypair.secret_keyfile.unlink()
    master_keypair.public_keyfile.unlink()


def test_generate_keypair(master_keypair: MasterKeyPair, master_passwd: str):
    assert not master_keypair.public_keyfile.exists()
    assert not master_keypair.public_keyfile.exists()

    master_keypair.generate_keypair(master_passwd)

    assert master_keypair.public_keyfile.exists()
    assert master_keypair.public_keyfile.exists()


@pytest.mark.run(after="test_generate_keypair")
def test_encrypt_decrypt(master_keypair: MasterKeyPair, master_passwd):
    secret_key = master_keypair.get_secret_key(master_passwd)
    public_key = master_keypair.get_public_key()

    mesg = b"hello, world!"

    encryption_box = SealedBox(public_key)
    encrypted_mesg = encryption_box.encrypt(mesg)

    decryption_box = SealedBox(secret_key)
    decrypted_mesg = decryption_box.decrypt(encrypted_mesg)
    assert mesg == decrypted_mesg


def test_change_master_password(master_keypair: MasterKeyPair, master_passwd):
    new_passwd = "nothing special"
    master_keypair.change_master_password(new_passwd, master_passwd)

    # this decryption will fail if it wasn't encrypted with the new password properly
    master_keypair.secret_keyfile.retrieve(new_passwd)
