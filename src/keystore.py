import os
from pathlib import Path
from utils.misc_classes import DirectoryTree
from typing import Final, Optional


class KeyStore:
    KEY_STORE_DIR_ENV_VAR = "KEYSTORE_DIR"
    KEY_FILE_EXT = ".gpg"
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

    def __str__(self):
        """
        returns whole directory tree containing all the keyfiles and parent dirs
        at the self.key_store_dir location

        only the folders with atleast one valid keyfile are included in tree
        """

        # include only those nodes themselves are key files or
        # is a directory which contains keyfiles somewhere in its tree
        tree_filter_predicate = (
            lambda node: node.is_file() and node.suffix == KeyStore.KEY_FILE_EXT
        )
        tree = DirectoryTree(self.key_store_dir, tree_filter_predicate)
        if tree is None:
            return f"no keys in {self.key_store_dir.absolute()}"
        return tree


if __name__ == "__main__":
    key_store = KeyStore()
    print(key_store)
