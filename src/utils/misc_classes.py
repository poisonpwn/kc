from typing import Callable, List
from pathlib import Path
from functools import update_wrapper
from inspect import signature
from pathlib import Path
from exceptions import PostInitNotFoundErr


class PsuedoFunc(type):
    """turns the class constructor act like a regular function and make it
    return a value instead of an instance of the class

    when the 'constructor' of the class is called i.e ClassName(args)
    those args are passed to the __post_init__ function of the class
    and the return value of that function is what is actually returned
    instad of the instance

    the __init__ of class also recieves the same arguments, and can still be used
    but the instance methods of the class cannot be used from the outside as an
    instance of the class is not returned by the constructor

    the class's __init__ signature will be replaced with that of the __post_init__ function
    to aid documetation
    """

    def __new__(meta_cls, name, bases, dct):
        cls_post_init = dct.get("__post_init__")

        if cls_post_init is None:
            print(
                f"class {dct['__name__']} needs to have "
                "__post_init__ attribute defined."
            )
            raise PostInitNotFoundErr(
                "can't find __post_init__ in class passed in to PostInit"
            )

        if isinstance(cls_post_init, (staticmethod, classmethod)):
            cls_post_init = cls_post_init.__func__  # the actual function inside

        dct_init = dct.get("__init__")
        if dct_init is None:
            dct_init = lambda *args, **kwargs: None
        cls_init = update_wrapper(dct_init, cls_post_init)

        post_init_sig = signature(cls_post_init)
        post_init_sig = post_init_sig.replace(
            parameters=tuple(post_init_sig.parameters.values())
        )

        # replace the function signature of the __init__ with that of __post_init__
        cls_init.__signature__ = post_init_sig

        # replace init with the newly formed one
        dct["__init__"] = cls_init
        return type.__new__(meta_cls, name, bases, dct)

    def __call__(cls, *args, **kwargs):
        # make sure the __init__ runs with same args
        instance = type.__call__(cls, *args, **kwargs)

        # call the post init with the same arguments so as to imitate a real function
        return instance.__post_init__(*args, **kwargs)


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