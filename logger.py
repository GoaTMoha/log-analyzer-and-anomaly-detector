import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import DEFAULT_LOG_FILE

LOGGER_NAME = "log_analyzer"

MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB

BACKUP_COUNT = 5

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(
    level: int | str = logging.INFO,
    log_file: Path = DEFAULT_LOG_FILE
) -> logging.Logger:

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
            encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    except OSError as error:
        logger.error("Failed to initialize file logging: %s", error)

    return logger


if __name__ == "__main__":

    app_logger = setup_logger(level=logging.DEBUG)

    app_logger.debug("Debug message")
    app_logger.info("Log Analyzer started")
    app_logger.warning("Suspicious authentication activity")
    app_logger.error("Failed to parse authentication log")
    app_logger.critical("Critical security event detected")

    print("\nLogger test completed.")
