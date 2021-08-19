import os
from pathlib import Path
from typing import Final, Optional, Callable
from utils.class_utils import PostInit


class KeyStore:
    KEY_STORE_DIR_ENV_VAR = "KEYSTORE_DIR"
    KEY_FILE_EXT = ".gpg"
    DEFAULT_KEY_STORE_PATH: Final[Path] = Path.home() / ".password-store"

    def __init__(self, key_store_dir: Optional[Path] = None):
        self.key_store_dir = key_store_dir
        if key_store_dir is None:
            # keystore was None so check in environment
            env_keystore_dir = os.environ.get(KeyStore.KEY_STORE_DIR_ENV_VAR)
            self.key_store_dir = (
                KeyStore.DEFAULT_KEY_STORE_PATH
                if env_keystore_dir is None
                # keystore was also not specified in environment
                else Path(env_keystore_dir)
            )
        if not self.key_store_dir.exists():
            os.makedirs(self.key_store_dir)

    def __str__(self):
        """
        returns whole directory tree containing all the keyfiles and parent dirs
        at the self.key_store_dir location, only the folders with atleast
        one valid keyfile are included in tree
        """
        tree_filter_predicate = (
            lambda node: node.is_file() and node.suffix == KeyStore.KEY_FILE_EXT
        )
        tree = Tree(self.key_store_dir, tree_filter_predicate)
        if tree is None:
            return f"no keys in {self.key_store_dir.absolute()}"
        return tree


class Tree(metaclass=PostInit):
    space = "  "
    pipe = "│  "
    tee = "├── "
    elbow = "└── "
    elipses = "..."
    arrow = " -> "
    MAX_RECURSE_LIMIT = 10

    def __init__(self, root_path, filter_predicate):
        self.root_path = root_path
        assert root_path.exists()
        self.filter_predicate = filter_predicate

    @staticmethod
    def tree(
        root: Path,
        filter_predicate: Callable[[Path], bool],
        prefix: str = ["├── "],
        depth: int = 0,
    ):

        # this is list of nodes that will be printed in the output tree
        # each entry will become a new line in the output tree
        included_nodes_list = []

        for node in root.iterdir():
            cur_node_name_list = [*prefix, node.stem]
            if filter_predicate(node):
                # * NOTE: a file node is only included (i.e 'valid' )
                # * if it passes the filter_predicate

                # filter_predicate returned true and node is valid
                if node.is_symlink():
                    # node is actually an alias to another file, so,
                    # append " ->  relative/path/to/actual/file" to node name
                    cur_node_name_list.extend(
                        [Tree.arrow, str(node.readlink().with_suffix(""))]
                    )
                included_nodes_list.append(cur_node_name_list)
                continue

            if node.is_dir():
                # * NOTE: a directory node is only valid if contains atleast one valid child node
                # * somewhere in it's subtree, so we need to search all of this node's
                # * children recursively

                # shallow copy is required so that the current node's
                # sibling nodes' prefixes don't change, because we have to mutate the prefix
                child_node_prefix = prefix.copy()

                # replace the previous pointer with a pipe
                child_node_prefix[-1] = Tree.pipe
                child_node_prefix.extend([Tree.space, Tree.tee])

                if depth > Tree.MAX_RECURSE_LIMIT:
                    # * NOTE: if tree is deeper than MAX_RECURSE_LIMIT levels deep
                    # * it will not be traversed, an ellipses ('...')
                    # * as single child is shown instead

                    # tree is too deep now don't traverse it, show elipses instead
                    included_nodes_list.extend(
                        [
                            cur_node_name_list,
                            # replace tee with elbow and add ellipses
                            child_node_prefix[:-1] + [Tree.elbow, "..."],
                        ]
                    )
                    continue

                # the entire subtree the current directory node is a parent of
                # i.e the valid child nodes of this current directory node
                subtree_list = Tree.tree(
                    node,
                    filter_predicate,
                    child_node_prefix,
                    depth + 1,  # increment the depth so that we don't traverse too deep
                )

                if subtree_list is not None:
                    # sublist contained nodes we want to include
                    included_nodes_list.extend([cur_node_name_list, *subtree_list])

        if len(included_nodes_list) == 0:
            # entire current tree didn't have any valid nodes
            return None

        # replace pointer (second last element of the last node's name list) of
        # last node of each subtree with elbow to cap off that subtree
        # like in
        # ├── item
        # ├── item
        # └── last_item
        # ^^^ an elbow symbol is to denote the end of a tree
        included_nodes_list[-1][-2] = Tree.elbow

        return included_nodes_list

    def __post_init__(self):
        tree = Tree.tree(self.root_path, self.filter_predicate)
        return (
            None
            if tree is None  # root path didn't have any valid nodes (recursivly)
            else "\n".join(  #                       vvvv indent the lines from the left margin
                [f"\n  {self.root_path}", *["".join(["\t", *i]) for i in tree]]
            )
        )


if __name__ == "__main__":
    key_store = KeyStore()
    print(key_store)
