from utils.directory_tree import DirectoryTree
from string import ascii_lowercase
from collections import deque
from random import choices
from abc import ABC

import pytest
import os


class Node(ABC):
    pass


File = type("File", (Node,), {})
Symlink = type("Symlink", (Node,), {})


class Dir(Node):
    def __init__(self, *args):
        self.children = args

    def create_fs(self, path: str, file_queue=None):
        if file_queue is None:
            file_queue = deque()

        for node in self.children:
            random_suffix = "".join(choices(ascii_lowercase, k=2))

            if node is File:
                child_filepath = path / f"file-{random_suffix}.enc"
                open(child_filepath, "a").close()
                file_queue.appendleft(child_filepath)
                continue

            if isinstance(node, Dir):
                child_dir_path = path / f"dir-{random_suffix}"
                os.mkdir(child_dir_path)
                node.create_fs(child_dir_path, file_queue)
                continue

        child_filepath = path / f"link-{random_suffix}.enc"
        os.symlink(file_queue.pop(), child_filepath)


test_keystore_schema = Dir(
    File,
    Dir(
        File,
        File,
        Dir(
            File,
            Symlink,
            File,
        ),
    ),
    File,
    Symlink,
)


@pytest.fixture(autouse=True)
def keystore_root_path(tmp_path):
    test_keystore_schema.create_fs(tmp_path)
    return tmp_path


@pytest.mark.skip
def test_dir_tree(keystore_root_path, capsys):
    keystore_dir = DirectoryTree(keystore_root_path, lambda _: True)
    with capsys.disabled():
        print()
        print(keystore_dir.compute_str())
