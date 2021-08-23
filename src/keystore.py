from nacl.public import SealedBox, PrivateKey, PublicKey
from utils.exceptions import EmptyError
from utils.misc_classes import DirectoryTree
from typing import Final, Optional
from pathlib import Path
import os
import click


class KeyStore:
    KEY_STORE_DIR_ENV_VAR = "KEYSTORE_DIR"
    KEY_FILE_EXT = "enc"
    DEFAULT_KEY_STORE_PATH: Final[Path] = Path.home() / ".password-store"

    def __init__(self, key_store_dir: Optional[Path] = None):
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

        if not self.key_store_dir.exists():
            os.makedirs(self.key_store_dir)

    def insert_passwd(self, service_name: str, passwd: str, public_key: PublicKey):
        """encrypt the password given and write it to disk at key store location

        Args:
            service_name (str): the service the password is for,
              it will also become the file stem of the keyfile

            passwd (str): the password to encrypt

            public_key (nacl.public.PublicKey): the public key to be used for encrypting the password
        """
        keyfile = self._verify_and_get_keyfile_path(service_name)
        if keyfile.exists():
            prompt = f"the keyfile {keyfile} already exists in {self.key_store_dir} Overwrite?"
            try:
                click.confirm(prompt, default=False, abort=True, show_default=True)
            except click.Abort:
                click.echo("Aborting...")
                exit()

        encrypted_passwd_bytes = SealedBox(public_key).encrypt(bytes(passwd, "utf-8"))

        with open(keyfile, "w") as f:
            f.write(encrypted_passwd_bytes.hex())

    def retrieve_passwd(self, service_name: str, secret_key: PrivateKey) -> str:
        """return the decrypted password from the keystore

        Args:
            secret_key (nacl.public.SecretKey): the secret key to be used for decrypting the keyfile

            service_name (str): the service for which the password is to be decrypted,
              also becomes the file stem of the keyfile

        """
        keyfile = self._verify_and_get_keyfile_path(service_name)
        if not keyfile.exists():
            click.echo(
                f"password for {service_name} does not exist in keystore",
                err=True,
            )
            exit()

        with open(keyfile, "r") as f:
            encrypted_passwd_bytes = bytes.fromhex(f.read())
        return SealedBox(secret_key).decrypt(encrypted_passwd_bytes).decode("utf-8")

    def _verify_and_get_keyfile_path(self, service_name: str):
        """check if the service_name is not empty and if not,
        then return the path for the keyfile

        Args:
            service_name (str): the service name to verify and return the keyfile to
              the service name becomes the file stem of the keyfile

        Returns:
            EmptyError: if the service name is empty i.e == ""
        """
        if service_name == "":
            return EmptyError("service the password is for can't be empty!")
        return self.key_store_dir / f"{service_name}.{self.KEY_FILE_EXT}"

    def print_tree(self) -> Optional[str]:
        """
        prints and returns whole directory tree containing all the keyfiles and folders
        at the self.key_store_dir location, returns None if the tree was empty

        only the folders with atleast one valid keyfile are included in tree
        """

        # include only those nodes themselves are key files or # is a directory which contains keyfiles somewhere in its tree
        tree_filter_predicate = (
            lambda node: node.is_file() and node.suffix[1:] == KeyStore.KEY_FILE_EXT
        )
        dir_tree = DirectoryTree(self.key_store_dir, tree_filter_predicate)
        if dir_tree is None:
            print(f"no keys in {self.key_store_dir.absolute()}")
            return None

        print(dir_tree)
        return dir_tree
