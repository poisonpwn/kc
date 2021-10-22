from .exceptions import InvalidFilenameErr, EmptyError
from .crypto import KeySecretBox, PassEncryptedMessage
from nacl.public import PrivateKey, PublicKey
from functools import cached_property
from pathlib import Path
import click


class PublicKeyFile:
    """a file which contains the public key of a keypair"""

    PUBKEY_FILE_EXT = ".pub"

    def __init__(self, path: Path):
        self.path = path

    def remove(self):
        self.path.unlink()

    @property
    def path(self) -> Path:
        return self.__filepath

    @path.setter
    def path(self, new_public_key_filepath: Path):
        self.__filepath = new_public_key_filepath.absolute()

        if (
            self.__filepath.suffix is None
            or self.__filepath.suffix != self.PUBKEY_FILE_EXT
        ):
            raise InvalidFilenameErr(
                f"secret key file name has to have extension {self.PUBKEY_FILE_EXT}"
            )

    def write(
        self,
        public_key: PublicKey,
        *,
        should_confirm_overwrite: bool = True,
        should_print_write_mesg: bool = True,
    ):
        """write the public key to disk at filepath location

        Args:
            public_key (PublicKey): the public key to write to disk
        """
        if should_confirm_overwrite and self.path.exists():
            try:
                click.confirm(
                    f"file {self.path} already EXISTS! Overwrite?",
                    abort=True,
                )
            except click.exceptions.Abort:
                click.echo("Operation Cancelled! Aborting...")
                exit(0)

        self.path.parent.mkdir(exist_ok=True)
        with open(self.path, "wb") as public_key_file:
            public_key_file.write(public_key.encode())

        if should_print_write_mesg:
            click.echo(f"public key file written at {self.path}")

    def retrieve(self):
        """read/retrieve the public key from disk at the filepath"""
        if not self.path.exists():
            click.echo(f"public key does not exist in {self.path}!", err=True)
            exit(0)
        with open(self.path, "rb") as public_key_file:
            return PublicKey(public_key_file.read())


class SecretKeyFile:
    """a file which contains the private key of a keypair"""

    SECKEY_FILE_EXT = ".enc"

    def __init__(self, __path: Path):
        self.path = __path

    # this property is cached because it will be run again and again
    # while checking if the password was correct, but the file contents won't change
    @cached_property
    def encrypted_file_bytes(self):
        if not self.path.exists():
            click.echo(f"secret key does not exist in {self.path}!", err=True)
            exit(0)
        with open(self.path, "rb") as secret_key_filepath:
            return PassEncryptedMessage.from_bytes(secret_key_filepath.read())

    @property
    def path(self):
        return self.__filepath

    def remove(self):
        self.path.unlink()

    @path.setter
    def path(self, new_filepath: Path):
        self.__filepath = new_filepath.resolve()

        if self.path.suffix != self.SECKEY_FILE_EXT:
            raise InvalidFilenameErr(
                f"secret key file name has to have extension {self.SECKEY_FILE_EXT}"
            )

        if hasattr(self, "file_bytes"):
            # delete the current file bytes so that it is recomputed when needed
            del self.encrypted_file_bytes

    def write_encrypted(
        self,
        secret_key_bytes: PrivateKey,
        master_passwd,
        *,
        should_confirm_overwrite=True,
        should_print_write_mesg: bool = True,
    ):
        if should_confirm_overwrite and self.path.exists():
            try:
                click.confirm(
                    f"file {self.path} already EXISTS! Overwrite?",
                    default=False,
                    show_default=True,
                    abort=True,
                )
            except click.exceptions.Abort:
                click.echo("Operation Cancelled! Aborting...")
                exit(0)

        # create a secret box with the password and use that to encrypt the secret key
        secret_box = KeySecretBox(master_passwd)
        encrypted_secret_key = secret_box.encrypt(secret_key_bytes.encode())

        self.path.parent.mkdir(exist_ok=True)
        with open(self.path, "wb") as secret_key_file:
            secret_key_file.write(bytes(encrypted_secret_key))

        if hasattr(self, "encrypted_file_bytes"):
            del self.encrypted_file_bytes

        if should_print_write_mesg:
            click.echo(f"secret key file written at {self.path}")

    def retrieve(self, master_passwd: str):
        secret_box = KeySecretBox(master_passwd)

        return PrivateKey(
            secret_box.decrypt_message(self.encrypted_file_bytes, master_passwd)
        )
