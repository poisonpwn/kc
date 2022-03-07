import logging
from functools import cached_property
from pathlib import Path
from .exceptions import Exit
import shutil
from typing import Optional, Union, Callable

import click
from .misc import get_home_dir

logger = logging.getLogger(__name__)


class FsHandler:
    DEFAULT_OVERWRITE_MESSAGE = "file {} EXISTS!, Overwrite?"
    DEFAULT_PARENT_DIR = get_home_dir() / ".kc_keys"

    def __init__(self, path: Path):
        self.path = path

    @cached_property
    def file_bytes(self):
        logger.debug(f"read bytes from {self.path}")
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            logger.debug("tried to read non existant file")
            raise

    def write(
        self,
        mesg: bytes,
        *,
        should_confirm_overwrite=True,
        overwrite_mesg: Optional[Union[str, Callable[[Path], str]]] = None,
        should_backup=True,
    ):
        """write bytes to disk, if it already exists ask user for confirmation,
        with specified `overwrite_message`, if should_backup is True, will backup
        the file before overwrite to <PARENT>/backup/BACKUP__<filename>

        Args:
            mesg (bytes): the bytes to be written

            should_confirm_overwrite (bool): whether to ask confirmation before file overwrite

            overwrite_message (Optional[Union[str, Callable[[Path],str]]]): message the user
              will be prompted with if the file exists and `should_confirm_ovewrite` is true.
              can also be a `Callable[[Path],str]` where the current file path is provided as
              argument and returns a formatted str, if left `None` default ovewrite message is
              used.

            should_backup (bool): whether to backup the file to a new location before overwrite.
              the location picked is <PARENT>/backup/BACKUP__<FILENAME>"""

        if self.path.exists() and should_confirm_overwrite:
            if should_confirm_overwrite:
                logger.debug(f"attempting overwrite of file {self.path}")
                self._confirm_overwrite(overwrite_mesg)

            if should_backup:
                self._save_backup()

        self.path.parent.mkdir(exist_ok=True)
        self.path.write_bytes(mesg)
        logger.debug(f"message written to file {self.path}")

        if "file_bytes" in self.__dict__:
            logger.debug(f"erasing cached bytes of file {self.path}")
            del self.file_bytes

    def _confirm_overwrite(
        self, confirm_mesg: Optional[Union[str, Callable[[Path], str]]] = None
    ):
        """if file already exists, ask user for confirmation before overwriting
        the file."""
        if confirm_mesg is None:
            confirm_mesg = self.DEFAULT_OVERWRITE_MESSAGE.format(self.path)
        elif callable(confirm_mesg):
            confirm_mesg = confirm_mesg(self.path)

        try:
            click.confirm(confirm_mesg, abort=True)
        except click.Abort:
            logger.debug(f"aborting overwrite of file {self.path}")
            raise Exit("Aborting...", error_code=0)

    def _save_backup(self):
        """save a backup of the file under <parent>/backup/BACKUP_<filename>"""
        backup_dir = self.path.parent / "backup"
        backup_dir.mkdir(exist_ok=True)
        backup_dest_path = backup_dir / f"BACKUP__{self.path.name}"
        shutil.copy(self.path, backup_dest_path)
        assert backup_dest_path.exists()
        logger.info(f"backup of {self.path} created at {backup_dest_path}")

    def read(self):
        """reads the bytes of file
        raises:
           FileNotFoundError: raised when file was not found on the disk"""
        return self.file_bytes
