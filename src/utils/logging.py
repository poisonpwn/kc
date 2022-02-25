import logging
from contextlib import contextmanager


class LogLevelStreamHandler(logging.StreamHandler):
    @contextmanager
    def set_tmp_stream(self, stream: str):
        old_stream = self.setLevel(stream)
        yield
        if old_stream is not None:
            self.setLevel(old_stream)

    def emit(self, record):
        if record.level >= logging.INFO:
            super().emit(record)
            return
        with self.set_tmp_stream("sys.stdout"):
            super().emit(record)


class LogLevelFormatter(logging.Formatter):
    debug_format = "DEBUG: %(name)s: %(funcName)s:%(lineno)d: %(msg)s"
    info_format = "%(msg)s"

    def __init__(self):
        super().__init__(fmt="%(levelname)s: %(msg)s", datefmt=None, style="%")

    def format(self, record):

        # Save the original format configured by the user
        # when the logger formatter was instantiated
        format_orig = self._style._fmt

        # Replace the original format with one customized by logging level
        if record.levelno == logging.DEBUG:
            self._style._fmt = self.debug_format

        elif record.levelno == logging.INFO:
            self._style._fmt = self.info_format

        result = logging.Formatter.format(self, record)

        # Restore the original format configured by the user
        self._style._fmt = format_orig

        return result


def get_logger(logger_name):
    pass


def get_console_formatter():
    pass
