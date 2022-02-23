from utils.directory_tree import DirectoryTree
from utils.exceptions import PasswdFileExistsErr, Exit
from utils.keyfiles import PasswdFile, get_home_dir
from nacl.public import PrivateKey, PublicKey
from functools import partial
from pathlib import Path
from typing import Callable
import click


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

    PASSWD_STORE_DIR_ENV_VAR = "KC_PASSWORD_STORE"
    DEFAULT_LOCATION = get_home_dir() / ".kc-passwd-store"

    def __init__(self, passwd_store_path: Path):
        self.passwd_store_path = passwd_store_path

        # create if it doesn't exist
        self.passwd_store_path.mkdir(exist_ok=True, parents=True)

        # create a passwd file factory function that creates a passwd file instance
        # which is located inside the passwd store directory
        self.passwd_file_factory = partial(
            PasswdFile.from_service_name, passwd_store_path=passwd_store_path
        )

    def alias(self, source_service_name, dest_service_name):
        """symlink file to another place in passwd_store

        Args:
            source_service_name (str): service name of passwd to alias
            dest_service_name (str): destination service name
        """
        source = self.passwd_file_factory(source_service_name)
        dest = self.passwd_file_factory(dest_service_name)
        try:
            source.alias(dest)
        except FileNotFoundError:
            service_name_no_ext = source.with_suffix("").relative_to(
                self.passwd_store_path
            )
            click.echo(
                f"{service_name_no_ext} does not exist in in passwd store ({self.passwd_store_path})"
            )

    def insert_passwd(self, service_name: str, passwd: str, public_key: PublicKey):
        """encrypt the password given and write it to disk at key store location

        Args:
            service_name (str): the service the password is for,
              it will also become the file stem of the passfile

            passwd (str): the password to encrypt and insert into pass store

            public_key (nacl.public.PublicKey): the public key to be
              used for encrypting the password
        """
        passwd_file = self.passwd_file_factory(service_name)
        try:
            passwd_file.write_passwd(passwd, public_key)
        except PasswdFileExistsErr:
            prompt = f"the passfile {passwd_file} already exists in {self.passwd_store_path} Overwrite?"
            try:
                click.confirm(prompt, default=False, abort=True, show_default=True)
            except click.Abort:
                click.echo("Aborting...")
                raise Exit()

    def remove_passwd(self, service_name: str):
        """remove password corresponding to the service name.

        Args:
            service_name (str): service name associated with password
              that is to be removed
            should_confirm (bool, optional): confirm before removing
              the password. Defaults to True.
        """
        passwd_file = self.passwd_file_factory(service_name)
        try:
            passwd_file.unlink()
        except FileNotFoundError:
            click.echo(
                f"password for {service_name} does not exist in keystore", err=True
            )
            raise Exit()

    def retrieve_passwd(
        self, service_name: str, get_secret_key_callback: Callable[..., PrivateKey]
    ) -> str:
        """return the decrypted password from the keystore

        Args:
            secret_key (nacl.public.SecretKey): the secret key to be used for
              decrypting the pass_file

            service_name (str): the service for which the password is to be decrypted

        Returns:
            str: decrypted password corresponding to the service name in the pass store
        """
        try:
            passwd_file = self.passwd_file_factory(service_name)
            return passwd_file.retrieve_passwd(get_secret_key_callback)
        except FileNotFoundError:
            click.echo(
                f"password for {service_name} does not exist in pass store",
                err=True,
            )
            raise Exit()

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
            click.echo(f"no keys in {self.passwd_store_path.absolute()}")
            return

        click.echo(dir_tree.compute_str())
