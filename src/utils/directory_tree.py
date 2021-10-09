from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Callable, Optional
from os.path import relpath


class Node(ABC):
    tee = "├── "
    elbow = "└── "
    space = "    "
    pipe = "│   "

    @abstractmethod
    def compute_str(self, prefix, is_last):
        pass


@dataclass
class File(Node):
    path: Path
    arrow = " -> "
    ellipses = " ..."

    @classmethod
    def show_ellipses(cls, prefix):
        return "".join([*prefix, File.elbow, File.ellipses])

    def compute_str(self, prefix: List[str], is_last: bool) -> str:
        curr_node_name_list = prefix + [
            File.elbow if is_last else File.tee,
            self.path.stem,
        ]

        if self.path.is_symlink():
            # show that file is a symlink by adding ' -> <realpath>' next to it's name
            curr_node_name_list += [
                File.arrow,
                relpath(self.path.readlink().with_suffix(""), self.path.parent),
            ]

        return "".join(curr_node_name_list)


class DirectoryTree(Node):
    MAX_RECURSE_DEPTH = 7
    DEFAULT_FILTER_PREDICATE = lambda _: True

    """Algo for computing str of directory tree:

    ### Step I -> Data Aggregation:

        ```
        if depth is zero:
            set is_root flag

        if maximum recursion depth reached:
            show ellipses instead of childnodes
            by settng ellipses flag
        else:
            create empty child nodes list
            for every directory or file (node) in current directory:
                if node does not pass filter function:
                    go to --NEXT-- node in in iteration
                else:
                    if node is a file:
                        append File(node path) to child nodes list
                    if node is a directory:

                        recursively call algorithm on node and 
                        increment depth by one

                        if node's child node's empty flag is set:
                            append node and it's child nodes 
                            list to current child nodes list

            if current child nodes list is still empty:
                set empty flag
                
            --RETURN-- current directory object
        ```

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
            self.DEFAULT_FILTER_PREDICATE
            if filter_predicate is None
            else filter_predicate
        )
        self.is_root: bool = depth == 0

        if depth > self.MAX_RECURSE_DEPTH:
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

    """
    ### Step II -> Data Processing (String Computation)
        performed on the resultant list of data aggregation step:
        
        create list will contain every line of output string
        
        if is_root flag is set:
            append absolute path of root as first line
        
        if is_last flag is set:
            append '<current prefix><elbow><node_path>' to  list
        else:
            append '<current prefix><tee><node path>' to  list

        if is_last is set:
            child node prefix = current prefix + <space> 
        else:
            child node prefix = current prefix + <pipe>

        if show_ellipses flag is set:
            add File.ellipses() as only child and --RETURN-- joined string
        else:
            if is_last is set:
                append '<prefix><space>' to list
            else:
                append '<prefix><pipe>' to list''
        
        for each file or directory (node) in current directory's child node list:
            if current index is last:
                set is_last_child flag to True
            else:
                set it to False
                
            if node is a file:
                call it's compute str method with child_node_prefix
                and is_last_child as parameters and append result to list

            else if node is a directory:
                recursively call this algorithm on current directory
                and append result to output list
        
        --RETURN-- newline joined output list as str
    """

    def compute_str(self, prefix=[], is_last=True):
        assert not self.is_empty, "can't compute string for empty dir"

        if self.is_root:
            curr_node_name = f"\n{self.path.absolute()}"
        else:
            curr_node_name = "".join(
                prefix
                + [
                    self.elbow if is_last else self.tee,
                    self.path.absolute().name,
                ]
            )

        node_strings = [curr_node_name]

        child_node_prefix = prefix + [self.space if is_last else self.pipe]

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
