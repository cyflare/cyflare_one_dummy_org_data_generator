import logging
import os
import sys
from logging.config import dictConfig
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

# Load environment variables from the .env file
load_dotenv(find_dotenv(raise_error_if_not_found=True))

# Setup default variables
PROJECT_NAME = "CyFlare One Dummy Org Data Generator"
PROJECT_SLUG = "cyflare_one_dummy_org_data_generator"
PROJECT_DIR = Path(__file__).parent.parent.resolve()

# Logging setup


class ExcludeErrorFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno < logging.ERROR


dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {"exclude_error": {"()": ExcludeErrorFilter}},
        "formatters": {
            "simple": {"format": "%(asctime)s %(levelname)-8s %(name)s %(message)s"}
        },
        "handlers": {
            "console_stdout": {
                "formatter": "simple",
                "level": os.environ.get("LOG_LEVEL"),
                "class": "logging.StreamHandler",
                "stream": sys.stdout,
                "filters": ["exclude_error"],
            },
            "console_stderr": {
                "formatter": "simple",
                "level": "ERROR",
                "class": "logging.StreamHandler",
                "stream": sys.stderr,
            },
            "file": {
                "formatter": "simple",
                "level": os.environ.get("LOG_LEVEL"),
                "class": "logging.handlers.RotatingFileHandler",
                "filename": PROJECT_DIR / "logs" / "app.log",
                "maxBytes": 1024 * 1024 * 100,  # in MB
                "backupCount": 5,
                "delay": True,
            },
        },
        "loggers": {
            "": {
                "handlers": ["console_stdout", "console_stderr", "file"],
                "level": "DEBUG",
            },
            "urllib3": {"level": "WARNING"},
        },
    }
)
logger = logging.getLogger("{}.{}".format(PROJECT_SLUG, __name__))


# Define the exception handler for unhandled exceptions
def handle_exception(exctype, value, traceback):
    """Sends unhandled exceptions to logging mechanism."""
    # ignore KeyboardInterrupt so a console python program can exit with ctrl + c
    if issubclass(exctype, KeyboardInterrupt):
        sys.__excepthook__(exctype, value, traceback)
        return
    # rely entirely on python's logging module for formatting the exception
    logger.critical("Uncaught exception", exc_info=(exctype, value, traceback))


# Hook up the exception handler
sys.excepthook = handle_exception


DEFAULT_CUSTOMER_NAME = "Cyflare Demo Generated"
