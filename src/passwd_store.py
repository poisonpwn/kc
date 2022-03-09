import logging
from pathlib import Path
from typing import Callable, Union, ClassVar, Type

import click
from pathvalidate import sanitize_filepath

from utils.directory_tree import DirectoryTree
from utils.exceptions import Exit
from utils.crypto import SecretKey, PublicKey, AssymetricEncryptionBox
from utils.keyfiles import PasswdFile
from utils.misc import get_home_dir

logger = logging.getLogger(__name__)


class PasswdFileFactory:
    passwd_file_cls = PasswdFile

    def __init__(self, parent_path: Path):
        self.parent_path = parent_path

    def get_passwd_file(self, service_name: str):
        if len(service_name) == 0:
            logger.debug("invalid empty service name provided to PasswdFile")
            raise Exit("service name of password can't be empty!")

        filesys_root = Path("").absolute().root
        service_name: Path = sanitize_filepath(
            Path(filesys_root, service_name), platform="auto"
        )
        service_name = service_name.with_suffix(PasswdFile.PASSWD_FILE_EXT).relative_to(
            filesys_root
        )
        return PasswdFile(self.parent_path / service_name)


class PasswdStore:
    """manages Create, Read, Update, Delete (CRUD) operations
    on the password database on disk. Each file in the database is
    in the form <service_name>.<passfile_ext>, extension used is defined
    by PassStore.KEY_FILE_EXT

    Args:
        passwd_store_path (pathlib.Path): the path to the directory
          which is the root of the pass_store. if None, use
          default pass_store_path defined by PassStore.DEFAULT_KEY_STORE_PATH .
          Defaults to None"""

    PASSWD_STORE_DIR_ENV_VAR: ClassVar[str] = "KC_PASSWORD_STORE"
    DEFAULT_LOCATION: ClassVar[Path] = get_home_dir() / ".kc-passwd-store"
    assymetric_encryptor: ClassVar[
        Type[AssymetricEncryptionBox]
    ] = AssymetricEncryptionBox
    passwd_file_factory_cls: ClassVar[Type[PasswdFileFactory]] = PasswdFileFactory

    def __init__(self, passwd_store_path: Path):
        self.passwd_store_path = passwd_store_path
        self.passwd_store_path.mkdir(exist_ok=True, parents=True)
        self.passwd_file_factory = PasswdStore.passwd_file_factory_cls(
            passwd_store_path
        )

    def alias(self, source_service_name: str, dest_service_name: str):
        """symlink file to another place in passwd_store

        Args:
            source_service_name (str): service name of passwd to alias
            dest_service_name (str): destination service name
        """
        source = self.passwd_file_factory.get_passwd_file(source_service_name)
        dest = self.passwd_file_factory.get_passwd_file(dest_service_name)
        try:
            source.alias(dest.path)
        except FileNotFoundError:
            raise Exit(
                f"fatal: {self.__get_service_name(source.path)}"
                f"does not exist in passwd store ({self.passwd_store_path})"
            )

    def __get_service_name(self, path: Path) -> str:
        return path.with_suffix("").relative_to(self.passwd_store_path)

    def __get_overwrite_mesg(self, path: Path):
        return (
            f"{self.__get_service_name(path)} already EXISTS! in keystore, Overwrite?"
        )

    def __get_service_name_not_found_mesg(self, service_name: str):
        return (
            f"fatal: password for {service_name} does not exist "
            f"in keystore ({self.passwd_store_path.absolute()})"
        )

    def insert_passwd(
        self,
        service_name: str,
        passwd: str,
        public_key: PublicKey,
        *,
        should_confirm_overwrite: bool = True,
    ):
        """encrypt the password given and write it to disk at key store location.

        Args:
            service_name (str): the service the password is for,
              it will also become the file stem of the passfile

            passwd (str): the password to encrypt and insert into pass store

            public_key (utils.crypto.PublicKey): the public key to be
              used for encrypting the password
        """
        passwd_file = self.passwd_file_factory.get_passwd_file(service_name)
        encryption_box = PasswdStore.assymetric_encryptor(public_key)
        encrypted_passwd_bytes = encryption_box.encrypt(passwd.encode("utf-8"))

        passwd_file.write(
            encrypted_passwd_bytes,
            should_confirm_overwrite=should_confirm_overwrite,
            overwrite_mesg=self.__get_overwrite_mesg,
            should_backup=False,
        )

    def remove_passwd(self, service_name: str, should_confirm_delete: bool = True):
        """remove password corresponding to the service name.

        Args:
            service_name (str): service name associated with password
              that is to be removed
            should_confirm_delete (bool, optional): confirm before removing
              the password. Defaults to True.
        """
        passwd_file = self.passwd_file_factory.get_passwd_file(service_name)
        try:
            passwd_file.remove(should_confirm_delete)
        except FileNotFoundError:
            logger.info(f"{passwd_file !r} not found in passwd store {self !r}")
            raise Exit(
                f"fatal: service name {service_name} doesn't exist in passwd store"
            )

        logger.info(f"removing file {passwd_file.path}")

    def retrieve_passwd(
        self,
        service_name: str,
        secret_key: Union[Callable[..., SecretKey], SecretKey],
    ) -> str:
        """return the decrypted password from the keystore

        Args:
            secret_key (utils.crypto.SecretKey): the secret key to be used for
              decrypting the pass_file

            service_name (str): the service of the password to be decrypted
        """
        passwd_file = self.passwd_file_factory.get_passwd_file(service_name)
        try:
            encrypted_passwd_bytes = passwd_file.read()
        except FileNotFoundError:
            raise Exit(self.__get_service_name_not_found_mesg(service_name))

        if callable(secret_key):
            secret_key = secret_key()

        if not isinstance(secret_key, SecretKey):
            raise TypeError(
                "secret_key has to be a SecretKey or a callable that returns a SecretKey."
            )

        encryption_box = PasswdStore.assymetric_encryptor(secret_key)
        decrypted_passwd_bytes = encryption_box.decrypt(encrypted_passwd_bytes)

        return decrypted_passwd_bytes.decode("utf-8")

    def __repr__(self):
        return f"{type(self).__name__}({self.passwd_store_path})"

    def print_tree(self):
        """
        prints and returns whole directory tree containing all the keyfiles and folders
        inside self.pass_store_path, returns None if the tree was empty

        only the folders with atleast one VALID passfile are included in the tree
        """

        # include only those nodes themselves are key files or
        # is a directory which contains keyfiles somewhere in its tree
        tree_filter_predicate = lambda node: node.is_dir() or (
            node.is_file() and node.suffix == PasswdFile.PASSWD_FILE_EXT
        )

        dir_tree = DirectoryTree(self.passwd_store_path, tree_filter_predicate)
        if dir_tree.is_empty:
            raise Exit(
                f"no keys in {self.passwd_store_path.absolute()}",
                error_code=0,
                stderr=False,
            )

        click.echo(dir_tree.compute_str())
