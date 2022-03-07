from pathlib import Path

import pytest

from utils.exceptions import Exit
from utils.fs_handler import FsHandler
from unittest.mock import patch, MagicMock
import click.exceptions

BYTES = b"this is a message"
OTHER_BYTES = b"this is a message"


@pytest.fixture(
    scope="module", params=["temp_path_1.txt", "parent_folder_2/temp_path_2.txt"]
)
def tmp_path(tmp_path_factory):
    file_parent = tmp_path_factory.mktemp("temp_file")
    tmp_path = file_parent / "temp_path.txt"
    return tmp_path


@pytest.fixture(scope="module")
def fs_handler(tmp_path):
    return FsHandler(tmp_path)


@patch("utils.fs_handler.Path.write_bytes")
def test_write(write_bytes_mock: MagicMock, fs_handler: FsHandler):
    with patch("utils.fs_handler.Path.exists", return_value=False):
        fs_handler.write(BYTES)
    write_bytes_mock.assert_called_once_with(BYTES)


@patch("utils.fs_handler.Path.exists", return_value=True)
@patch("utils.fs_handler.Path.read_bytes", return_value=b"read bytes")
def test_read(read_bytes_mock: MagicMock, _, fs_handler: FsHandler):
    read_bytes_patched = read_bytes_mock.return_value

    read_bytes = fs_handler.read()
    assert read_bytes == read_bytes_patched
    read_bytes_mock.assert_called()

    read_bytes_mock.reset_mock()

    read_bytes = fs_handler.read()
    assert read_bytes == read_bytes_patched


@patch("utils.fs_handler.Path.exists", return_value=True)
@patch("utils.fs_handler.Path.read_bytes", return_value=b"read bytes")
def test_flush_cache(read_bytes_mock: MagicMock, _, fs_handler: FsHandler):

    fs_handler.read()
    read_bytes_mock.reset_mock()

    with patch("utils.fs_handler.Path.write_bytes") as write_bytes_mock, patch(
        "utils.fs_handler.Path.exists", return_value=False
    ):
        fs_handler.write(b"some random bytes")
        write_bytes_mock.assert_called()

    fs_handler.read()
    read_bytes_mock.assert_called()


@patch("shutil.copy")
@patch("utils.fs_handler.Path.write_bytes")
def test_abort_overwrite(write_bytes_mock, copy_mock, fs_handler: FsHandler):
    with pytest.raises(Exit), patch(
        "utils.fs_handler.Path.exists", return_value=True
    ), patch("click.confirm", side_effect=click.exceptions.Abort):
        fs_handler.write(OTHER_BYTES)
    write_bytes_mock.assert_not_called()
    copy_mock.assert_not_called()


@patch("shutil.copy")
@patch("utils.fs_handler.Path.write_bytes")
def test_overwrite(write_bytes_mock, copy_mock, tmp_path: Path, fs_handler: FsHandler):
    with patch("click.confirm", return_value=None), patch(
        "utils.fs_handler.Path.exists", return_value=True
    ):
        fs_handler.write(OTHER_BYTES)
    write_bytes_mock.assert_called_once_with(OTHER_BYTES)
    backup_dir = tmp_path.parent / "backup"
    backup_dir_dest_path = backup_dir / f"BACKUP__{tmp_path.name}"
    copy_mock.assert_called_with(tmp_path, backup_dir_dest_path)
