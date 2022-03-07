from master_key_pair import MasterKeyPair
from utils.keyfiles import SecretKeyFile, PublicKeyFile
from nacl.public import SealedBox
import pytest


@pytest.fixture(scope="module")
def master_keypair(tmp_path_factory):
    secret_key_path = SecretKeyFile(
        tmp_path_factory.mktemp("secret_file_parent")
        / f"seckey{SecretKeyFile.SECRET_KEY_SUFFIX}"
    )
    public_key_path = PublicKeyFile(
        tmp_path_factory.mktemp("public_key_parent")
        / f"pubkey{PublicKeyFile.PUBLIC_KEY_SUFFIX}"
    )

    master_keypair = MasterKeyPair(secret_key_path, public_key_path)

    yield master_keypair

    master_keypair.secret_key_file.path.unlink()
    master_keypair.public_key_file.path.unlink()


@pytest.mark.dependency(name="keypair generate")
def test_generate_keypair(master_keypair: MasterKeyPair, master_passwd: str):
    assert not master_keypair.public_key_file.path.exists()
    assert not master_keypair.public_key_file.path.exists()

    master_keypair.generate_keypair(master_passwd)

    assert master_keypair.public_key_file.path.exists()
    assert master_keypair.public_key_file.path.exists()


@pytest.mark.dependency(depends=["keypair generate"])
@pytest.mark.order(after="test_generate_keypair")
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

    master_keypair.get_secret_key(new_passwd)
