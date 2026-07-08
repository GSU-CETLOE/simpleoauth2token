"""Logging service for simpleoauth2token.

Writes informational events (INFO, ERROR, ...) to working/logs/oauth2.log
and echoes them to the console.
"""

import logging
from pathlib import Path

LOG_FILE_NAME = "oauth2.log"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def getLogger(name: str = "simpleoauth2token", workingDir: str | Path = "working") -> logging.Logger:
    """Return a logger that writes to <workingDir>/logs/oauth2.log and the console.

    Repeat calls with the same name return the same configured logger without
    attaching duplicate handlers.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    logsDir = Path(workingDir) / "logs"
    logsDir.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter(LOG_FORMAT)

    fileHandler = logging.FileHandler(logsDir / LOG_FILE_NAME, encoding="utf-8")
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)

    return logger
