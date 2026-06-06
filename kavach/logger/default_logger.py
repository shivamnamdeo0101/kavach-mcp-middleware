import logging
from logger.base_logger import BaseLogger

class DefaultLogger(BaseLogger):
    def __init__(self, name="kavach", level=logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            # Compact format: [LEVEL] timestamp | message
            formatter = logging.Formatter(
                "[%(levelname)s] %(asctime)s | %(message)s",
                datefmt="%H:%M:%S"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def info(self, msg, **kwargs):
        if kwargs:
            msg = f"{msg} | {kwargs}"
        self.logger.info(msg)

    def error(self, msg, **kwargs):
        if kwargs:
            msg = f"{msg} | {kwargs}"
        self.logger.error(msg)

    def debug(self, msg, **kwargs):
        if kwargs:
            msg = f"{msg} | {kwargs}"
        self.logger.debug(msg)

    def warning(self, msg, **kwargs):
        if kwargs:
            msg = f"{msg} | {kwargs}"
        self.logger.warning(msg)