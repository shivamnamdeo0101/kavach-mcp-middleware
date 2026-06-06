from .base_logger import BaseLogger
from .default_logger import DefaultLogger

class LoggerManager:
    _instance = None
    _logger: BaseLogger = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LoggerManager, cls).__new__(cls)
        return cls._instance

    def set_logger(self, logger: BaseLogger):
        """Override default logger"""
        self._logger = logger

    def get_logger(self):
        if self._logger is None:
            self._logger = DefaultLogger()
        return self._logger