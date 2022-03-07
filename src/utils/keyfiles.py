import logging
import click
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, Type, Union, Callable

from .crypto import AssymetricEncryptedMessage, PublicKey, SymmetricEncryptedMessage
from .exceptions import Exit
from .fs_handler import FsHandler
from .misc import get_home_dir

logger = logging.getLogger(__name__)


class KeyFile(ABC):
    DEFAULT_PARENT_DIR: ClassVar[Path] = get_home_dir() / ".kc_keys"
    message_type: ClassVar[Type]  # constructible from bytes
    file_handler_cls: ClassVar[Type] = FsHandler

    def __init__(self, path: Path):
        self._validate(path)
        self.path = path
        self._fs_handler = KeyFile.file_handler_cls(path)

    @classmethod
    @abstractmethod
    def _validate(cls, path: Path) -> bool:
        ...

    def write(self, data: "message_type", **kwargs):
        return self._fs_handler.write(data, **kwargs)

    def read(self) -> bytes:
        return self._fs_handler.read()

    def __repr__(self):
        return f"{type(self).__name__}({self.path})"


class SecretKeyFile(KeyFile):
    SECRET_KEY_SUFFIX = ".sec"
    DEFAULT_LOCATION = KeyFile.DEFAULT_PARENT_DIR / f"NaCl_seckey{SECRET_KEY_SUFFIX}"
    message_type: ClassVar[Type] = SymmetricEncryptedMessage

    @classmethod
    def _validate(cls, path: Path):
        if path.suffix is None:
            logger.debug(f"invalid empty file extension provided to {cls.__name__}")
            raise Exit(
                f"secret key file can't have empty extension, extension required: {cls.SECRET_KEY_SUFFIX}"
            )
        if path.suffix != cls.SECRET_KEY_SUFFIX:
            logger.debug(f"invalid file extension provided to {cls.__name__}")
            raise Exit(
                f"secret key filename has to have extension {cls.SECRET_KEY_SUFFIX}"
                f"but receieved {path}"
            )

    @staticmethod
    def __default_overwrite_mesg_func(path: Path) -> str:
        return f"secret key file {path} EXISTS!, Overwrite?"

    def write(self, data: SymmetricEncryptedMessage, **kwargs):
        kwargs.setdefault("overwrite_mesg", self.__default_overwrite_mesg_func)
        data_bytes = data.serialize()
        logger.debug(f"writing encrypted secret key bytes to {self !r}")
        super().write(data_bytes, **kwargs)

    def read(self) -> SymmetricEncryptedMessage:
        logger.debug(f"reading encrypted secret key bytes from {self !r}")
        read_bytes = self._fs_handler.read()
        return self.message_type.deserialize(read_bytes)


class PublicKeyFile(KeyFile):
    PUBLIC_KEY_SUFFIX: ClassVar[str] = ".pub"
    DEFAULT_LOCATION: ClassVar[Path] = (
        KeyFile.DEFAULT_PARENT_DIR / f"NaCl_pubkey{PUBLIC_KEY_SUFFIX}"
    )
    message_type: ClassVar[Type] = PublicKey

    @classmethod
    def _validate(cls, path: Path):
        if path.suffix is None:
            logger.debug(
                f"invalid empty file extension provided to {cls.__name__}, file: {path}"
            )
            raise Exit(
                f"secret key file can't have empty extension, extension required: {cls.PUBLIC_KEY_SUFFIX}"
            )
        elif path.suffix != cls.PUBLIC_KEY_SUFFIX:
            logger.debug(
                f"invalid file extension provided to {cls.__name__}, file: {path}"
            )
            raise Exit(
                f"public key file name has to have extension {cls.PUBLIC_KEY_SUFFIX},"
                f"not {path.suffix}"
            )

    @staticmethod
    def __default_overwrite_mesg(path) -> str:
        return f"public key file {path} EXISTS!, Overwrite?"

    def write(self, data: message_type, **kwargs):
        kwargs.setdefault("overwrite_mesg", self.__default_overwrite_mesg)
        logger.debug(f"writing public key bytes to {self !r}")
        super().write(
            bytes(data),
            **kwargs,
        )

    def read(self) -> bytes:
        logger.debug(f"reading public key bytes from {self !r}")
        return super().read()


class PasswdFile(KeyFile):
    PASSWD_FILE_EXT = ".enc"
    message_type: ClassVar[Type] = AssymetricEncryptedMessage

    @classmethod
    def _validate(cls, path):
        if path.suffix is None:
            logger.debug(
                f"invalid empty file extension provided to {cls.__name__}, file: {path}"
            )
            raise Exit(
                f"passwd file can't have empty extension, extension required: {cls.PASSWD_FILE_EXT}"
            )
        elif path.suffix != cls.PASSWD_FILE_EXT:
            logger.debug(
                f"invalid file extension provided to {cls.__name__}, file: {path}"
            )
            raise Exit(
                f"passwd has to have extension {cls.PASSWD_FILE_EXT}, not {path.suffix}"
            )

    def alias(self, destination_path: Path):
        if not self.path.exists():
            logger.debug(f"tried to alias non existant {self !r}")
            raise FileNotFoundError(f"passwd file doesn't exist at {self.path}")
        destination_path.parent.mkdir(exist_ok=True, parents=True)
        logger.info(f"symlinking {self.path} to {destination_path}")
        destination_path.symlink_to(self.path, target_is_directory=False)

    def remove(
        self,
        should_confirm_delete: bool = True,
        delete_confirm_mesg: Union[
            Callable[[Path], str], str
        ] = "Are you sure you want to remove password?",
    ):
        if not self.path.exists():
            logging.debug(f"attempted to delete nonexistant passwd file {self !r}")
            raise FileNotFoundError(f"{self !r} file not not found")

        if should_confirm_delete:
            logging.debug(f"attempting delete of {self !r} from disk")
            self.__confirm_delete(delete_confirm_mesg)

        logger.info(f"removing file {self.path}")
        self.path.unlink()

    def __confirm_delete(self, delete_confirm_mesg: Union[Callable[[Path], str], str]):
        if callable(delete_confirm_mesg):
            delete_confirm_mesg = delete_confirm_mesg()

        if not isinstance(delete_confirm_mesg, str):
            raise TypeError(
                "delete_confirm_mesg has to be either a str or a callable that returns a str."
            )
        try:
            click.confirm(delete_confirm_mesg, abort=True)
        except click.exceptions.Abort:
            raise Exit("Remove Aborted", error_code=0, stderr=False)

    @staticmethod
    def __default_overwrite_mesg(path) -> str:
        f"passwd file {path} Exists! Overwrite?"

    def write(self, data: bytes, **kwargs):
        kwargs.setdefault("overwrite_mesg", self.__default_overwrite_mesg)
        logger.debug(f"writing encrypted passwd bytes to {self !r}")
        super().write(data, **kwargs)

    def read(self) -> AssymetricEncryptedMessage:
        logger.debug(f"reading encrypted passwd bytes from {self !r}")
        return PasswdFile.message_type(super().read())
