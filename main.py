import argparse
import logging
import sys
from pathlib import Path

from anomaly_detector import AnomalyDetector
from cli_report import generate_cli_report
from config import BASE_DIR, Config, initialize_directories, load_config
from event_classifier import classify_event
from html_report import HTMLReportGenerator
from logger import setup_logger
from parser import parse_log
from risk_assessor import assess_risk
from statistics import LogStatistics


DEFAULT_LOG_INPUT = BASE_DIR / "data" / "sample_auth.log"

logger = logging.getLogger("log_analyzer.main")


def analyze(log_file: Path, config: Config) -> dict:

    events, valid_count, invalid_count = parse_log(log_file)

    if invalid_count:
        logger.warning(
            "Skipped %d malformed line(s) in %s", invalid_count, log_file
        )

    if not valid_count:
        logger.warning("No valid log entries found in %s", log_file)

    for event in events:
        event["event_type"] = classify_event(event["raw"])

    detector = AnomalyDetector(
        failed_login_threshold=config.failed_login_threshold,
        multiple_ip_threshold=config.multiple_ips_threshold
    )

    return {
        "stats": LogStatistics(events).generate_summary(),
        "risk": assess_risk(detector.detect(events)),
        "valid_lines": valid_count,
        "invalid_lines": invalid_count
    }


def build_html_data(result: dict) -> dict:

    stats = result["stats"]

    return {
        "summary": stats,
        "severity_counts": result["risk"]["severity_statistics"],
        "findings": result["risk"]["findings"],
        "top_attacker_ips": [
            {"ip": ip, "count": count}
            for ip, count in stats["top_attacking_ips"]
        ],
        "targeted_usernames": [
            {"username": username, "count": count}
            for username, count in stats["most_targeted_users"]
        ]
    }


def main(argv: list[str] | None = None) -> int:

    arg_parser = argparse.ArgumentParser(
        description="Analyze a Linux authentication log for suspicious activity."
    )
    arg_parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=DEFAULT_LOG_INPUT,
        help="path to the log file (default: data/sample_auth.log)"
    )
    args = arg_parser.parse_args(argv)

    config = load_config()

    try:
        initialize_directories(config)
    except OSError as error:
        print(f"Error: cannot create output folders: {error}", file=sys.stderr)
        return 1

    setup_logger(level=config.log_level, log_file=config.log_output)
    logger.info("Analyzing %s", args.log_file)

    try:
        result = analyze(args.log_file, config)
    except OSError as error:
        logger.error("Cannot read log file %s: %s", args.log_file, error)
        return 1

    stats = result["stats"]
    risk = result["risk"]

    if config.cli_report:
        generate_cli_report(
            stats=stats,
            findings=risk["findings"],
            attacker_ips=dict(stats["top_attacking_ips"]),
            targeted_users=dict(stats["most_targeted_users"]),
            event_counts=stats["event_distribution"]
        )

    if config.html_report:
        try:
            report_path = HTMLReportGenerator().generate(
                build_html_data(result),
                config.report_output / "report.html"
            )
        except Exception as error:  # the generator already logged the details
            logger.error("HTML report was not created: %s", error)
            return 1

        print(f"\nHTML report saved to: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
