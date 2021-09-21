from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Callable, Optional


class Node(ABC):
    tee = "├── "
    elbow = "└── "
    space = "    "
    pipe = "│   "

    @abstractmethod
    def compute_str(self, prefix, is_last) -> List[str]:
        pass


@dataclass
class File(Node):
    path: Path
    arrow = " -> "
    ellipses = " ..."

    @classmethod
    def show_ellipses(cls, prefix):
        return "".join([*prefix, File.elbow, File.ellipses])

    def compute_str(self, prefix: str, is_last: bool) -> str:
        curr_node_name_list = prefix + [
            File.elbow if is_last else File.tee,
            self.path.stem,
        ]

        if self.path.is_symlink():
            # show that file is a symlink by adding ' -> <realpath>' next to it's name
            curr_node_name_list += [
                File.arrow,
                str(self.path.readlink().with_suffix("")),
            ]

        return "".join(curr_node_name_list)


class DirectoryTree(Node):
    MAX_RECURSE_DEPTH = 7
    DEFAULT_FILTER_PREDICATE = lambda _: True

    """Algo for computing str of directory tree:

        ### Step I -> Data Aggregation:
        1)  check if the maximum recursion limit has been reached, the child tree will not be traversed.
            instead, show_ellipses flag is set, so that a '...' is shown as child instead.
            
            if depth is 0, the is_root flag is set to True.
        
            if the recursion limit has not been reached, create a list of child nodes.

        2) iterate through each node in current directory

        3) check if node passes the predicate passed in to the function, 
           if not, continue to next iteration, else, do the following:

           if node is file, create a File object from the node's path and append it
           to the list of children.

           if the node is a directory, recursively call this algorithm on that child directory,
           if child directory's DirectoryTree object's list of children is not empty, append it to
           the current list of child nodes.

        5)  after iterating through the current directory's contents, check if the 
            list of child nodes is empty. if yes, then set the is_empty flag on the current directory,
            delete the list of child nodes

        6)  return the DirectoryTree for current directory.


        ### Step II -> Data Processing (String Computation):

        1) create a list that contains each line of the output tree
        2) if the current directory is the root of the tree we are computing,
           append '\n<absolute path of root>' as the first line of the output list
           (node_strings_list).

           else, check the following:
              if is_last flag passed in is true, then append '<prefix>└── <node path>' to the list
              list.

              if is_last is not true, then append '<prefix>├── <node path>' to the list.
        3) if show_ellipses flag is set then, add ellipses as only child of tree and 
           return the "".join() of the output list. else, continue with the following steps.
        
        4) set child_node_prefix as:
            '<prefix><space>' if is_last is true
            else '<prefix>│   ' if it is not

        4) iterate through the current directory's child nodes, keeping in mind if the current node
           is the last child or not using the is_last_child flag.

        5) if node is a file, then call it's compute_str method using the child_node_prefix and
           pass in the is_last_child as it's is_last named parameter, and append it's output str
           to the output tree string list.
        
        6) if the node is a directory, recursively call compute_str on it passing in the 
           child_prefix and the is_last_child flag as it's is_last named parameter, and
           append it's output str to output tree string list.
        
        7) after iterating through the current directories children, "\n".join the output tree
           string list and return the output.
    """

    def __init__(
        self,
        path: Path,
        filter_predicate: Optional[Callable[[Path], bool]],
        depth: int = 0,
    ):
        assert path.exists(), f"Directory {self.path} Does Not Exist"
        self.path = path.absolute()

        self.is_empty: bool = False
        self.show_ellipses: bool = False
        filter_predicate = (
            DirectoryTree.DEFAULT_FILTER_PREDICATE
            if filter_predicate is None
            else filter_predicate
        )
        self.is_root: bool = depth == 0

        if depth > DirectoryTree.MAX_RECURSE_DEPTH:
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
            node_strings.append(File.show_ellipses(child_node_prefix))
            return "\n".join(node_strings)

        no_of_nodes = len(self.child_nodes_list)
        for index, node in enumerate(self.child_nodes_list):
            is_last_child = index == no_of_nodes - 1
            if isinstance(node, File):
                node_strings.append(
                    node.compute_str(child_node_prefix, is_last=is_last_child)
                )
                continue

            subdir_children = node.compute_str(child_node_prefix, is_last=is_last_child)
            node_strings.append(subdir_children)

        return "\n".join(node_strings)
