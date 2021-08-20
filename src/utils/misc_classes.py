from typing import Callable
from pathlib import Path


class PostInit(type):
    """
    enables the use of a class as a psuedofunction of sorts

    it overrides the __call__ of `type` class to actuall call an internel function
    of the class itself

    i.e when the actual class constructor is called

    value = Something() # class which has metaclass PostInit

    a class instance is NOT created, instance it returns the output of the __post_init__
    of the Something class
    """

    def __call__(cls, *args, **kwargs):
        try:
            return type.__call__(cls, *args, **kwargs).__post_init__()
        except AttributeError:
            print(
                f"class {cls.__name__} needs to have "
                "__post_init__ attribute defined."
            )
            raise


class DirectoryTree(metaclass=PostInit):
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
                        [DirectoryTree.arrow, str(node.readlink().with_suffix(""))]
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
                child_node_prefix[-1] = DirectoryTree.pipe
                child_node_prefix.extend([DirectoryTree.space, DirectoryTree.tee])

                if depth > DirectoryTree.MAX_RECURSE_LIMIT:
                    # * NOTE: if tree is deeper than MAX_RECURSE_LIMIT levels deep
                    # * it will not be traversed, an ellipses ('...')
                    # * as single child is shown instead

                    # tree is too deep now don't traverse it, show elipses instead
                    included_nodes_list.extend(
                        [
                            cur_node_name_list,
                            # replace tee with elbow and add ellipses
                            child_node_prefix[:-1] + [DirectoryTree.elbow, "..."],
                        ]
                    )
                    continue

                # valid child nodes of this current directory node
                subtree_list = DirectoryTree.tree(
                    node,
                    filter_predicate,
                    child_node_prefix,
                    # increment depth so that traversal stops when we go too deep
                    depth + 1,
                )

                if subtree_list is not None:
                    included_nodes_list.extend([cur_node_name_list, *subtree_list])

        if len(included_nodes_list) == 0:
            # entire current tree didn't have any valid nodes
            return None

        # replace pointer (second last element of the last node's name list) of
        # last node of each subtree with elbow to cap off that subtree
        # └── last_item
        # ^^^ an elbow symbol is used to denote the end of a tree
        included_nodes_list[-1][-2] = DirectoryTree.elbow

        return included_nodes_list

    def __post_init__(self):
        tree = DirectoryTree.tree(self.root_path, self.filter_predicate)
        return (
            None
            if tree is None  # root path didn't have any valid nodes (recursivly)
            else "\n".join(  #                       vvvv indent the lines from the left margin
                [f"\n  {self.root_path}", *["".join(["\t", *i]) for i in tree]]
            )
        )