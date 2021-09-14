from nacl.public import SealedBox, PrivateKey, PublicKey
from utils.misc_classes import DirectoryTree
from typing import Final, Optional
from pathlib import Path
from utils.exceptions import KeyFileExistsAlready, EmptyError
import os
import click


class KeyStore:
    KEY_STORE_DIR_ENV_VAR = "KEYSTORE_DIR"
    KEY_FILE_EXT = "enc"
    DEFAULT_KEY_STORE_PATH: Final[Path] = Path.home() / ".password-store"

    def __init__(
        self, key_store_dir: Optional[Path] = None, should_create_keystore=True
    ):
        self.key_store_dir = key_store_dir
        if key_store_dir is None:
            # keystore was None so check in environment
            env_key_store_dir = os.environ.get(KeyStore.KEY_STORE_DIR_ENV_VAR)
            self.key_store_dir = (
                KeyStore.DEFAULT_KEY_STORE_PATH
                if env_key_store_dir is None
                # keystore was also not specified in environment
                else Path(env_key_store_dir)
            )

        if not self.key_store_dir.exists() and should_create_keystore:
            os.makedirs(self.key_store_dir)

    def insert_passwd(self, service_name: str, passwd: str, public_key: PublicKey):
        """encrypt the password given and write it to disk at key store location

        Args:
            service_name (str): the service the password is for,
              it will also become the file stem of the keyfile

            passwd (str): the password to encrypt

            public_key (nacl.public.PublicKey): the public key to be used for encrypting the password
        """
        keyfile = KeyFile.from_service_name(service_name, self)
        try:
            keyfile.write_key(passwd, public_key)
        except KeyFileExistsAlready:
            prompt = f"the keyfile {keyfile} already exists in {self.key_store_dir} Overwrite?"
            try:
                click.confirm(prompt, default=False, abort=True, show_default=True)
            except click.Abort:
                click.echo("Aborting...")
                exit()

    def retrieve_passwd(self, service_name: str, secret_key: PrivateKey) -> str:
        """return the decrypted password from the keystore

        Args:
            secret_key (nacl.public.SecretKey): the secret key to be used for decrypting the keyfile

            service_name (str): the service for which the password is to be decrypted,
              also becomes the file stem of the keyfile

        """
        try:
            keyfile = KeyFile.from_service_name(service_name, self)
            return keyfile.retrieve_key(secret_key)
        except FileNotFoundError:
            click.echo(
                f"password for {service_name} does not exist in keystore",
                err=True,
            )
            exit()

    def print_tree(self) -> Optional[str]:
        """
        prints and returns whole directory tree containing all the keyfiles and folders
        at the self.key_store_dir location, returns None if the tree was empty

        only the folders with atleast one valid keyfile are included in tree
        """

        # include only those nodes themselves are key files or # is a directory which contains keyfiles somewhere in its tree
        tree_filter_predicate = lambda node: node.is_dir() or (
            node.is_file() and node.suffix[1:] == KeyStore.KEY_FILE_EXT
        )

        dir_tree = DirectoryTree(self.key_store_dir, tree_filter_predicate)
        if dir_tree.is_empty:
            print(f"no keys in {self.key_store_dir.absolute()}")
            return
        print(dir_tree.compute_str())
        return dir_tree


class KeyFile:
    def __init__(self, path):
        self.path = path

    @classmethod
    def from_service_name(cls, service_name, keystore):
        if len(service_name) == 0:
            raise EmptyError("service name of password can't be empty!")
        return cls(keystore.key_store_dir / f"{service_name}.{KeyStore.KEY_FILE_EXT}")

    def retrieve_key(self, secret_key) -> str:
        if not self.path.exists():
            raise FileNotFoundError(f"KeyFile doesn't exist at {self.path}")

        with open(self.path, "rb") as f:
            encrypted_passwd_bytes = f.read()

        return SealedBox(secret_key).decrypt(encrypted_passwd_bytes).decode("utf-8")

    def write_key(self, key, public_key: PublicKey):
        if self.path.exists():
            raise KeyFileExistsAlready(
                f"KeyFile already exists at location {self.path}"
            )

        encrypted_passwd_bytes = SealedBox(public_key).encrypt(bytes(key, "utf-8"))

        with open(self.path, "wb") as f:
            f.write(encrypted_passwd_bytes)
