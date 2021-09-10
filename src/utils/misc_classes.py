from typing import Callable, List
from dataclasses import dataclass
from abc import ABC, abstractmethod
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


class Node(ABC):
    tee = "├── "
    elbow = "└── "
    space = "    "
    pipe = "│   "

    @abstractmethod
    def compute_str(self, prefix, is_last) -> List[str]:
        ...


@dataclass
class File(Node):
    path: Path
    arrow = " -> "
    _ellipses = " ..."

    @classmethod
    def ellipses(cls, prefix):
        return "".join([*prefix, File.elbow, File._ellipses])

    def compute_str(self, prefix: str, is_last: bool) -> str:
        curr_node_name_list = prefix + [
            File.elbow if is_last else File.tee,
            self.path.stem,
        ]
        if self.path.is_symlink():
            curr_node_name_list += [
                File.arrow,
                str(self.path.readlink().with_suffix("")),
            ]

        return "".join(curr_node_name_list)


class DirectoryTree(Node):
    MAX_RECURSE_DEPTH = 7

    def __init__(
        self,
        path: Path,
        filter_predicate: Callable[[Path], bool],
        depth: int = 0,
    ):
        assert path.exists(), f"Directory {self.path} Does Not Exist"
        self.path = path
        self.is_empty: bool = False
        self.show_ellipses: bool = False
        self.is_root: bool = depth == 0

        if depth >= DirectoryTree.MAX_RECURSE_DEPTH:
            self.show_ellipses = True
            return

        self.child_nodes_list: List[Node] = []
        for node_path in self.path.iterdir():
            if not filter_predicate(node_path):
                continue

            if node_path.is_file():
                self.child_nodes_list.append(File(node_path))
            elif node_path.is_dir():
                dir = DirectoryTree(node_path, filter_predicate, depth + 1)
                if not dir.is_empty:
                    self.child_nodes_list.append(dir)

        if len(self.child_nodes_list) == 0:
            self.is_empty = True
            del self.child_nodes_list

    def compute_str(self, prefix=[], is_last=True):
        assert not self.is_empty, "can't compute string for empty dir"

        if self.is_root:
            curr_node_name = f"\n{self.path.absolute()}"
        else:
            curr_node_name = "".join(
                prefix
                + [
                    DirectoryTree.elbow if is_last else DirectoryTree.tee,
                    self.path.absolute().name,
                ]
            )
        node_strings = [curr_node_name]

        child_node_prefix = prefix + [
            DirectoryTree.space if is_last else DirectoryTree.pipe
        ]

        if self.show_ellipses:
            node_strings.append(File.ellipses(child_node_prefix))
            return "\n".join(node_strings)

        no_of_nodes = len(self.child_nodes_list)
        for index, node in enumerate(self.child_nodes_list):
            is_last = index == no_of_nodes - 1
            if isinstance(node, File):
                node_strings.append(
                    node.compute_str(child_node_prefix, is_last=is_last)
                )
                continue

            subdir_children = node.compute_str(child_node_prefix, is_last=is_last)
            node_strings.append(subdir_children)
        return "\n".join(node_strings)


tree = DirectoryTree(
    Path.home() / ".password-store",
    filter_predicate=lambda node: node.is_dir()
    or (node.is_file() and node.suffix == ".gpg"),
)
print(tree.compute_str())
