from pathlib import Path

import pytest

from utils.exceptions import Exit
from utils.fs_handler import FsHandler
from unittest.mock import patch
import click.exceptions

BYTES = b"this is a message"
OTHER_BYTES = b"this is a message"


@pytest.fixture(scope="module")
def tmp_path(tmp_path_factory):
    file_parent = tmp_path_factory.mktemp("temp_file")
    tmp_path = file_parent / "temp_path.txt"
    return tmp_path


@pytest.fixture(scope="module")
def fs_handler(tmp_path):
    return FsHandler(tmp_path)


@pytest.mark.order(before="test_read_write")
def test_nonexistant_read(fs_handler, tmp_path):
    assert not tmp_path.exists()
    with pytest.raises(FileNotFoundError):
        fs_handler.read()


@pytest.mark.dependency(name="test-read-write")
def test_read_write(fs_handler: FsHandler, tmp_path: Path):
    assert not tmp_path.exists()
    fs_handler.write(BYTES)
    assert tmp_path.exists()
    read_bytes = fs_handler.read()
    assert read_bytes == BYTES


@pytest.mark.dependency(depends=["test-read-write"])
@pytest.mark.order(after="test_read_write")
def test_confirm_no(tmp_path, fs_handler: FsHandler):
    assert tmp_path.exists()
    with pytest.raises(Exit):
        with patch("click.confirm", side_effect=click.exceptions.Abort()):
            fs_handler.write(OTHER_BYTES)
    read_bytes = fs_handler.read()
    assert read_bytes == BYTES


@pytest.mark.dependency(name="test-confirm-yes", depends=["test-read-write"])
@pytest.mark.order(after="test_read_write")
def test_confirm_yes(fs_handler: FsHandler):
    with patch("click.confirm"):
        fs_handler.write(OTHER_BYTES)
    read_bytes = fs_handler.read()
    assert read_bytes == OTHER_BYTES


@pytest.mark.dependency(depends=["test-confirm-yes"])
@pytest.mark.order(after="test_confirm_yes")
def test_backup(tmp_path: Path):
    backup_path_dir = tmp_path.parent / "backup"
    tmp_file_name = f"BACKUP__{tmp_path.name}"
    backup_file_path = backup_path_dir / tmp_file_name
    assert backup_file_path.exists()
    read_bytes = backup_file_path.read_bytes()
    assert read_bytes == OTHER_BYTES
