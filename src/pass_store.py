from utils.directory_tree import DirectoryTree
from utils.exceptions import PasswdFileExistsErr
from utils.keyfiles import PasswdFile
from nacl.public import PrivateKey, PublicKey
from pathlib import Path
import click
import os


class PasswdStore:
    """manages Create, Read, Update, Delete (CRUD) operations
    on the password database on disk. Each file in the database is
    in the form <service_name>.<passfile_ext>, extension used is defined
    by PassStore.KEY_FILE_EXT

    Args:
        pass_store_path (pathlib.Path): the path to the directory
          which is the root of the pass_store. if None, use
          default pass_store_path defined by PassStore.DEFAULT_KEY_STORE_PATH .
          Defaults to None"""

    PASSWD_STORE_DIR_ENV_VAR = "KC_PASSWORD_STORE"

    @staticmethod
    def default_passwd_store_path():
        password_store_parent = os.environ.get("XDG_DATA_HOME")
        if password_store_parent is not None:
            return Path(password_store_parent) / "kc-password-store"
        return Path.home() / ".kc-password-store"

    def __init__(self, pass_store_path: Path):
        self.passwd_store_path = pass_store_path
        self.passwd_store_path.mkdir(exist_ok=True, parents=True)

    def insert_passwd(self, service_name: str, passwd: str, public_key: PublicKey):
        """encrypt the password given and write it to disk at key store location

        Args:
            service_name (str): the service the password is for,
              it will also become the file stem of the passfile

            passwd (str): the password to encrypt and insert into pass store

            public_key (nacl.public.PublicKey): the public key to be
              used for encrypting the password
        """
        passwd_file = PasswdFile.from_service_name(service_name, self.passwd_store_path)
        try:
            passwd_file.write_passwd(passwd, public_key)
        except PasswdFileExistsErr:
            prompt = f"the passfile {passwd_file} already exists in {self.passwd_store_path} Overwrite?"
            try:
                click.confirm(prompt, default=False, abort=True, show_default=True)
            except click.Abort:
                click.echo("Aborting...")
                exit()

    def retrieve_passwd(self, service_name: str, secret_key: PrivateKey) -> str:
        """return the decrypted password from the keystore

        Args:
            secret_key (nacl.public.SecretKey): the secret key to be used for
              decrypting the pass_file

            service_name (str): the service for which the password is to be decrypted

        Returns:
            str: decrypted password corresponding to the service name in the pass store
        """
        try:
            passwd_file = PasswdFile.from_service_name(
                service_name, self.passwd_store_path
            )
            return passwd_file.retrieve_passwd(secret_key)
        except FileNotFoundError:
            click.echo(
                f"password for {service_name} does not exist in pass store",
                err=True,
            )
            exit()

    def print_tree(self):
        """
        prints and returns whole directory tree containing all the keyfiles and folders
        inside self.pass_store_path, returns None if the tree was empty

        only the folders with atleast one VALID passfile are included in the tree
        """

        # include only those nodes themselves are key files or
        # is a directory which contains keyfiles somewhere in its tree
        tree_filter_predicate = lambda node: node.is_dir() or (
            node.is_file() and node.suffix == PasswdStore.PASSWD_FILE_EXT
        )

        dir_tree = DirectoryTree(self.passwd_store_path, tree_filter_predicate)
        if dir_tree.is_empty:
            print(f"no keys in {self.passwd_store_path.absolute()}")
            return

        print(dir_tree.compute_str())
