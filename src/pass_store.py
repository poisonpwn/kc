from nacl.public import SealedBox, PrivateKey, PublicKey
from utils.directory_tree import DirectoryTree
from typing import Final, Optional
from pathlib import Path
from utils.exceptions import PassFileExistsErr, EmptyError
import os
import click


class PassStore:
    """manages Create, Read, Update, Delete (CRUD) operations
    on the password database on disk. Each file in the database is
    in the form <service_name>.<passfile_ext>, extension used is defined
    by PassStore.KEY_FILE_EXT

    Args:
        pass_store_path (pathlib.Path): the path to the directory
          which is the root of the pass_store. if None, use
          default pass_store_path defined by PassStore.DEFAULT_KEY_STORE_PATH .
          Defaults to None

        should_create_keystore (bool): whether to create the pass store root dir
          during init, if it doens't exist already
    """

    KEY_STORE_DIR_ENV_VAR = "KEYSTORE_DIR"
    KEY_FILE_EXT = "enc"
    DEFAULT_KEY_STORE_PATH: Final[Path] = Path.home() / ".password-store"

    def __init__(self, pass_store_path: Optional[Path] = None):
        self.pass_store_path = pass_store_path
        if pass_store_path is None:
            # keystore was None so check in environment
            env_key_store_dir = os.environ.get(PassStore.KEY_STORE_DIR_ENV_VAR)
            self.pass_store_path = (
                PassStore.DEFAULT_KEY_STORE_PATH
                if env_key_store_dir is None
                # keystore was also not specified in environment
                else Path(env_key_store_dir)
            )

        if not self.pass_store_path.exists():
            os.makedirs(self.pass_store_path)

    def insert_passwd(self, service_name: str, passwd: str, public_key: PublicKey):
        """encrypt the password given and write it to disk at key store location

        Args:
            service_name (str): the service the password is for,
              it will also become the file stem of the passfile

            passwd (str): the password to encrypt and insert into pass store

            public_key (nacl.public.PublicKey): the public key to be
              used for encrypting the password
        """
        pass_file = PassFile.from_service_name(service_name, self.pass_store_path)
        try:
            pass_file.write_passwd(passwd, public_key)
        except PassFileExistsErr:
            prompt = f"the passfile {pass_file} already exists in {self.pass_store_path} Overwrite?"
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
            pass_file = PassFile.from_service_name(service_name, self.pass_store_path)
            return pass_file.retrieve_passwd(secret_key)
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
            node.is_file() and node.suffix[1:] == PassStore.KEY_FILE_EXT
        )

        dir_tree = DirectoryTree(self.pass_store_path, tree_filter_predicate)
        if dir_tree.is_empty:
            print(f"no keys in {self.pass_store_path.absolute()}")
            return

        print(dir_tree.compute_str())


class PasswdFile:
    """represents a file containing a password
    which may or may not exist on disk yet

    Args:
        path (str): path to the passfile
    """

    def __init__(self, path):
        self.path = path

    @classmethod
    def from_service_name(cls, service_name, pass_store_path):
        """create a PassFile instance from service name
        under the pass_store_path

        Args:
            service_name (str): the service the password is for,
              this will become the filestem of the passfile.

            pass_store_path (pathlib.Path): the pass_store_path directory
              under which the passfile is to be placed.

        Raises:
            EmptyError: raised when service name is empty
        """
        if len(service_name) == 0:
            raise EmptyError("service name of password can't be empty!")

        return cls(pass_store_path / f"{service_name}.{PassStore.KEY_FILE_EXT}")

    def retrieve_passwd(self, secret_key: PrivateKey) -> str:
        """retrieve and decrypt the key contained in the keyfile

        Args:
            secret_key (PrivateKey): the secret key that should be used
              to decrypt the passfile contents

        Raises:
            FileNotFoundError: raised if the passfile doesn't exist on disk

        Returns:
            str: the decrypted password which the passfile contained
        """

        if not self.path.exists():
            raise FileNotFoundError(f"passfile doesn't exist at {self.path}")

        with open(self.path, "rb") as f:
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
        if self.path.exists():
            raise PassFileExistsErr(f"passfile already exists at location {self.path}")

        encrypted_passwd_bytes = SealedBox(public_key).encrypt(bytes(passwd, "utf-8"))

        with open(self.path, "wb") as f:
            f.write(encrypted_passwd_bytes)
