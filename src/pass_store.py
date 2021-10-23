from nacl.public import SealedBox, PrivateKey, PublicKey
from utils.directory_tree import DirectoryTree
from pathlib import Path
from utils.exceptions import PasswdFileExistsErr, EmptyError
import os
from utils.keyfiles import KeyFile
import click


class PasswdStore:
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


class PasswdFile(KeyFile):
    """represents a file containing a password
    which may or may not exist on disk yet
    """

    @classmethod
    def from_service_name(cls, service_name, passwd_store_path):
        """create a PassFile instance with filestem `service_name`
        under the `passwd_store_path`

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

        return cls(passwd_store_path / f"{service_name}{PasswdStore.PASSWD_FILE_EXT}")

    def retrieve_passwd(self, secret_key: PrivateKey) -> str:
        """retrieve and decrypt the password contained in the keyfile

        Args:
            secret_key (PrivateKey): the secret key that should be used
              to decrypt the passfile contents

        Raises:
            FileNotFoundError: raised if the passwd file doesn't exist on disk
        """

        if not self.exists():
            raise FileNotFoundError(f"passwd file doesn't exist at {self}")

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
            raise PasswdFileExistsErr(f"passfile already exists at location {self}")

        encrypted_passwd_bytes = SealedBox(public_key).encrypt(bytes(passwd, "utf-8"))

        with open(self, "wb") as f:
            f.write(encrypted_passwd_bytes)
