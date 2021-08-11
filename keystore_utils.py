import os
from pathlib import Path
from class_utils import PostInit


class treeprint(metaclass=PostInit):
    space = "  "
    pipe = "│  "
    tee = "├── "
    elbow = "└── "

    def __init__(self, root_path, filter_predicate):
        self.root_path = root_path
        self.filter_predicate = filter_predicate

    @staticmethod
    def tree(root, filter_predicate, prefix=["├── "]):
        append_list = []
        for node in root.iterdir():
            cur_node_name = ["   ", *prefix, node.stem]
            if filter_predicate(node):
                if node.is_symlink():
                    cur_node_name.extend([" -> ", str(node.readlink().with_suffix(""))])
                append_list.append(cur_node_name)
                continue
            if node.is_dir():
                child_node_prefix = prefix.copy()
                child_node_prefix[-1] = treeprint.pipe
                child_node_prefix.extend([treeprint.space, treeprint.tee])
                sublist = treeprint.tree(node, filter_predicate, child_node_prefix)
                if sublist is not None:
                    append_list.extend([cur_node_name, *sublist])

        if len(append_list) == 0:
            return None
        append_list[-1][-2] = treeprint.elbow
        return append_list

    def __post_init__(self):
        return "\n".join(
            [
                self.root_path.name,
                *[
                    "".join(i)
                    for i in treeprint.tree(self.root_path, self.filter_predicate)
                ],
            ]
        )


class KeyStore:
    KEY_STORE_DIR_ENV_VAR = "KEYSTORE_DIR"

    def __init__(self, key_store_dir=None):
        self.key_store_dir = key_store_dir
        if key_store_dir is None:
            env_keystore_dir = os.environ.get(KeyStore.KEY_STORE_DIR_ENV_VAR)
            self.key_store_dir = (
                Path.home() / ".password-store"
                if env_keystore_dir is None
                else Path(env_keystore_dir)
            )
        if not self.key_store_dir.exists():
            os.makedirs(self.key_store_dir)

    def __str__(self):
        return treeprint(
            self.key_store_dir, lambda node: node.is_file() and node.suffix == ".gpg"
        )


if __name__ == "__main__":
    key_store = KeyStore()
    print(key_store)
