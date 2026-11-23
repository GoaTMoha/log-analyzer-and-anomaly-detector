
import json
import logging

from dataclasses import dataclass
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent

CONFIG_FILE = BASE_DIR / "data" / "config.json"

DEFAULT_REPORT_DIR = BASE_DIR / "reports"
DEFAULT_LOG_FILE = BASE_DIR / "logs" / "analyzer.log"


@dataclass
class Config:

    failed_login_threshold: int = 5

    brute_force_window_minutes: int = 10

    multiple_usernames_threshold: int = 5

    multiple_ips_threshold: int = 5

    root_login_alert: bool = True

    business_hours: tuple[int, int] = (8, 18)

    business_hours_detection: bool = True

    excessive_sudo_threshold: int = 5

    new_ip_detection: bool = True

    report_output: Path = DEFAULT_REPORT_DIR

    log_output: Path = DEFAULT_LOG_FILE

    log_level: str = "INFO"

    html_report: bool = True

    cli_report: bool = True


logger = logging.getLogger("log_analyzer.config")


def validate_config(data: dict[str, Any]) -> None:

    if not isinstance(data, dict):
        raise ValueError("Configuration must be a JSON object.")

    integer_fields = [
        "failed_login_threshold",
        "brute_force_window_minutes",
        "multiple_usernames_threshold",
        "multiple_ips_threshold",
        "excessive_sudo_threshold"
    ]

    boolean_fields = [
        "root_login_alert",
        "business_hours_detection",
        "new_ip_detection",
        "html_report",
        "cli_report"
    ]

    for field in integer_fields:

        if field in data:

            value = data[field]

            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"{field} must be a positive integer."
                )

    for field in boolean_fields:

        if field in data:

            if type(data[field]) is not bool:
                raise ValueError(
                    f"{field} must be a boolean."
                )

    if "business_hours" in data:

        hours = data["business_hours"]

        if (
            not isinstance(hours, list)
            or len(hours) != 2
            or any(type(hour) is not int for hour in hours)
            or not (0 <= hours[0] < hours[1] <= 24)
        ):
            raise ValueError(
                "business_hours must contain two valid hours, "
                "for example [8, 18]."
            )

    if "log_level" in data:

        valid_levels = [
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL"
        ]

        if data["log_level"] not in valid_levels:
            raise ValueError("Invalid logging level.")

    for field in ["report_output", "log_output"]:

        if field in data:

            if (
                not isinstance(data[field], str)
                or not data[field].strip()
            ):
                raise ValueError(
                    f"{field} must be a non-empty string."
                )


def load_config(
    config_path: Path = CONFIG_FILE
) -> Config:

    config_path = Path(config_path)

    defaults = Config()

    if not config_path.exists():

        logger.warning(
            "Configuration file not found: %s. "
            "Using default settings.",
            config_path
        )

        return defaults

    try:

        with config_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        validate_config(data)

        allowed_fields = Config.__dataclass_fields__

        filtered_data = {
            key: value
            for key, value in data.items()
            if key in allowed_fields
        }

        if len(filtered_data) != len(data):
            logger.warning(
                "Unknown configuration fields were ignored."
            )

        if "business_hours" in filtered_data:

            filtered_data["business_hours"] = tuple(
                filtered_data["business_hours"]
            )

        if "report_output" in filtered_data:

            filtered_data["report_output"] = (
                BASE_DIR / filtered_data["report_output"]
            )

        if "log_output" in filtered_data:

            filtered_data["log_output"] = (
                BASE_DIR / filtered_data["log_output"]
            )

        config = Config(**filtered_data)

        logger.info(
            "Configuration loaded successfully."
        )

        return config

    except (json.JSONDecodeError, ValueError, OSError) as error:

        logger.error(
            "Configuration loading failed: %s. "
            "Using default settings.",
            error
        )

        return defaults


def initialize_directories(config: Config) -> None:

    try:

        config.report_output.mkdir(
            parents=True,
            exist_ok=True
        )

        config.log_output.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        logger.info(
            "Project directories initialized."
        )

    except OSError as error:

        logger.error(
            "Directory initialization failed: %s",
            error
        )

        raise

