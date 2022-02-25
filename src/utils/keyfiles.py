from functools import cached_property
from pathlib import Path
from typing import Callable

import click
from nacl.public import PrivateKey, PublicKey, SealedBox
from pathvalidate import sanitize_filepath

from .crypto import KeySecretBox, PassEncryptedMessage
from .exceptions import EmptyError, InvalidFilenameErr, PasswdFileExistsErr, Exit
from .misc import get_home_dir
from .logging import get_logger

logger = get_logger(__name__)


class KeyFile(Path):
    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls, *args, **kwargs).absolute()
        return self

    # type(Path()) is necessary because path returns different type in __new__
    _flavour = type(Path())._flavour
    DEFAULT_PARENT_DIR = get_home_dir() / ".kc_keys"


class PublicKeyFile(KeyFile):
    """a file which contains the public key of a keypair"""

    PUBKEY_FILE_EXT = ".pub"
    DEFAULT_LOCATION = KeyFile.DEFAULT_PARENT_DIR / f"NaCl_pubkey{PUBKEY_FILE_EXT}"

    # args and kwargs required for __new__
    # don't call super().__init__(*args, **kwargs) here
    def __init__(self, *args, **kwargs):
        if self.suffix != self.PUBKEY_FILE_EXT:
            logger.debug("invalid file extension provided to PublicKeyFile")
            raise InvalidFilenameErr(
                f"public key file name has to have extension {self.PUBKEY_FILE_EXT}"
            )

    def write(
        self,
        public_key: PublicKey,
        *,
        should_confirm_overwrite: bool = True,
    ):
        """write the public key to disk at filepath location

        Args:
            public_key (PublicKey): the public key to write to disk
            should_confirm_overwrite (bool): ask user to confirm overwrite,
             if file already exists
        """
        if should_confirm_overwrite and self.exists():
            try:
                click.confirm(
                    f"file {self} already EXISTS! Overwrite?",
                    abort=True,
                )
            except click.exceptions.Abort:
                click.echo("Operation Cancelled! Aborting...")
                logger.debug("abort PublicKeyFile overwrite")
                raise Exit()

        self.parent.mkdir(exist_ok=True)
        with open(self, "wb") as public_key_file:
            public_key_file.write(public_key.encode())

        logger.info(f"public key file written at {self}")

    def retrieve(self):
        """read/retrieve the public key from disk at the filepath"""
        if not self.exists():
            logger.debug("tried to retrieve non existant PublicKeyFile")
            click.echo(f"public key does not exist in {self}!", err=True)
            raise Exit()
        with open(self, "rb") as public_key_file:
            return PublicKey(public_key_file.read())


class SecretKeyFile(KeyFile):
    """a file which contains the private key of a keypair."""

    SECKEY_FILE_EXT = ".enc"
    DEFAULT_LOCATION = KeyFile.DEFAULT_PARENT_DIR / f"NaCl_seckey{SECKEY_FILE_EXT}"

    def __init__(self, *args, **kwargs):
        if self.suffix != self.SECKEY_FILE_EXT:
            logger.debug("invalid file extension provided to SecretKeyFile")
            raise InvalidFilenameErr(
                f"secret key file name has to have extension {self.SECKEY_FILE_EXT} but receieved {self}"
            )

    # this property is cached because it will be run again and again
    # while checking if the password was correct,
    # but the file contents wont change.
    @cached_property
    def encrypted_file_bytes(self):
        if not self.exists():
            logger.debug("tried to retrieve non existant SecretKeyFile")
            click.echo(f"secret key does not exist in {self}!", err=True)
            raise Exit()

        with open(self, "rb") as secret_key_filepath:
            return PassEncryptedMessage.from_bytes(secret_key_filepath.read())

    def write_encrypted(
        self,
        secret_key_bytes: PrivateKey,
        master_passwd,
        *,
        should_confirm_overwrite=True,
    ):
        if should_confirm_overwrite and self.exists():
            try:
                click.confirm(
                    f"file {self} already EXISTS! Overwrite?",
                    default=False,
                    show_default=True,
                    abort=True,
                )
            except click.exceptions.Abort:
                click.echo("Operation Cancelled! Aborting...")
                logger.debug("abort SecretKeyFile overwrite")
                raise Exit()

        # create a secret box with the password and use that to encrypt the secret key
        secret_box = KeySecretBox(master_passwd)
        encrypted_secret_key = secret_box.encrypt(secret_key_bytes.encode())

        self.parent.mkdir(exist_ok=True)
        with open(self, "wb") as secret_key_file:
            secret_key_file.write(bytes(encrypted_secret_key))

        # clear the cached encrypted bytes
        if hasattr(self, "encrypted_file_bytes"):
            del self.encrypted_file_bytes
            logger.debug("cached encrypted secret keyfile bytes erased from memory")

        logger.info(f"secret key file written at {self}")

    def retrieve(self, master_passwd: str):
        secret_box = KeySecretBox(master_passwd)
        return PrivateKey(
            secret_box.decrypt_message(self.encrypted_file_bytes, master_passwd)
        )


class PasswdFile(KeyFile):
    """represents a file containing a password
    which may or may not exist on disk yet
    """

    PASSWD_FILE_EXT = ".enc"

    def __init__(self, *args, **kwargs):
        if self.suffix is None:
            logger.debug("invalid empty file extension provided to PasswdFile")
            raise InvalidFilenameErr(
                f"passwd file can't have empty extension, extension required: {self.PASSWD_FILE_EXT}"
            )
        elif self.suffix != self.PASSWD_FILE_EXT:
            logger.debug("invalid file extension provided to PasswdFile")
            raise InvalidFilenameErr(
                f"passwd has to have extension {self.PASSWD_FILE_EXT}, not {self.suffix}"
            )

    @classmethod
    def from_service_name(cls, service_name: str, passwd_store_path: Path):
        """create a PassFile instance with filestem `service_name`
        under the `passwd_store_path`

        Args:
            service_name (str): the service the password is for,
              this will become the filestem of the passfile.

            passwd_store_path (pathlib.Path): the passwd_store_path directory
              under which the passfile is to be placed.

        Raises:
            EmptyError: raised when service name is empty
        """
        if len(service_name) == 0:
            logger.debug("invalid empty service name provided to PasswdFile")
            raise EmptyError("service name of password can't be empty!")

        filesys_root = Path("").absolute().root
        service_name: Path = sanitize_filepath(
            Path(filesys_root, service_name), platform="auto"
        )
        service_name = service_name.with_suffix(cls.PASSWD_FILE_EXT).relative_to(
            filesys_root
        )
        return cls(passwd_store_path / service_name)

    def alias(self, destination_path: Path):
        if not self.exists():
            logger.debug("tried to alias non existant PasswdFile")
            raise FileNotFoundError(f"passwd file doesn't exist at {self}")
        destination_path.parent.mkdir(exist_ok=True, parents=True)
        destination_path.symlink_to(self, target_is_directory=False)

    def retrieve_passwd(self, get_secret_key_callback: Callable[[], PrivateKey]) -> str:
        """retrieve and decrypt the password contained in the keyfile

        Args:
            secret_key (PrivateKey): secret key used to decrypt the passwd file

        Raises:
            FileNotFoundError: raised if the passwd file doesn't exist on disk
        """

        if not self.exists():
            logger.debug("tried to retrive non existant PasswdFile")
            raise FileNotFoundError(f"passwd file doesn't exist at {self}")

        secret_key = get_secret_key_callback()
        with open(self, "rb") as f:
            encrypted_passwd_bytes = f.read()
        decrypted_passwd_bytes = SealedBox(secret_key).decrypt(encrypted_passwd_bytes)

        return decrypted_passwd_bytes.decode("utf-8")

    def write_passwd(self, passwd: str, public_key: PublicKey):
        """encrypt and write the passfile to disk

        Args:
            key (str): the key to enter into the keystore

            public_key (PublicKey):  the public key to be used to encrypt the key with

        Raises:
            PassFileExistsErr: raised when the passfile attempted to
              be written to disk already exists.
        """
        if self.exists():
            logger.debug("tried to write to an existing PasswdFile")
            raise PasswdFileExistsErr(f"PasswdFile already exists at location {self}")
        encrypted_passwd_bytes = SealedBox(public_key).encrypt(bytes(passwd, "utf-8"))
        # make the parent directory in case of passwords which are organized. eg. 'alt/google'
        self.parent.mkdir(parents=True, exist_ok=True)
        with open(self, "wb") as f:
            f.write(encrypted_passwd_bytes)
