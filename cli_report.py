import os
import sys
from collections import Counter
from datetime import datetime
from typing import Any


USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


class Colors:
    RESET = "\033[0m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""

    RED = "\033[91m" if USE_COLOR else ""
    GREEN = "\033[92m" if USE_COLOR else ""
    YELLOW = "\033[93m" if USE_COLOR else ""
    CYAN = "\033[96m" if USE_COLOR else ""
    WHITE = "\033[97m" if USE_COLOR else ""


def print_line(char: str = "=", width: int = 65) -> None:
    """Print a horizontal separator."""
    print(char * width)


def print_header(title: str) -> None:
    """Display a formatted section header."""
    print()
    print_line("=")
    print(f"{Colors.BOLD}{Colors.CYAN}{title}{Colors.RESET}")
    print_line("=")


def print_item(label: str, value: Any) -> None:
    """Display a label and its corresponding value."""
    print(f"{label:<30}: {value}")


def format_severity(severity: str, width: int = 0) -> str:

    severity = str(severity).upper()

    severity_colors = {
        "LOW": Colors.GREEN,
        "MEDIUM": Colors.YELLOW,
        "HIGH": Colors.RED,
        "CRITICAL": Colors.BOLD + Colors.RED,
    }

    color = severity_colors.get(severity, Colors.WHITE)

    return f"{color}{severity:<{width}}{Colors.RESET}"


def display_log_summary(stats: dict) -> None:

    print_header("LOG ANALYSIS SUMMARY")

    summary = {
        "Total events": stats.get("total_events", 0),
        "Successful logins": stats.get("successful_logins", 0),
        "Failed logins": stats.get("failed_logins", 0),
        "Unknown events": stats.get("unknown_events", 0),
        "Invalid users": stats.get("invalid_users", 0),
        "Sudo events": stats.get("sudo_events", 0),
    }

    for label, value in summary.items():
        print_item(label, value)


def display_severity_breakdown(findings: list[dict]) -> None:

    print_header("SEVERITY BREAKDOWN")

    severity_counts = Counter(
        str(finding.get("severity", "UNKNOWN")).upper()
        for finding in findings
    )

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = severity_counts.get(severity, 0)

        print(f"{format_severity(severity, 10)} {count:>5}")


def display_security_findings(findings: list[dict]) -> None:

    print_header("SECURITY FINDINGS")

    if not findings:
        print(f"{Colors.GREEN}No suspicious activity detected.{Colors.RESET}")
        return

    for index, finding in enumerate(findings, start=1):

        print()
        print(f"{Colors.BOLD}Finding #{index}{Colors.RESET}")

        print_item("Detection", finding.get("title") or "Unknown detection")
        print_item("Severity", format_severity(finding.get("severity") or "UNKNOWN"))
        print_item("Source IP", finding.get("source_ip") or "N/A")
        print_item("Username", finding.get("username") or "N/A")
        print_item("Timestamp", finding.get("timestamp") or "N/A")

        print(
            "Description: "
            f"{finding.get('description') or 'No description available.'}"
        )
        print_line("-")


def display_top_attacker_ips(
    attacker_ips: dict | Counter,
    limit: int = 5
) -> None:

    print_header("TOP ATTACKING IP ADDRESSES")

    if not attacker_ips:
        print("No attacker IP statistics available.")
        return

    print(f"{'IP ADDRESS':<25} {'FAILED ATTEMPTS':>15}")
    print_line("-")

    for ip, count in Counter(attacker_ips).most_common(limit):
        print(f"{ip:<25} {count:>15}")


def display_targeted_usernames(
    targeted_users: dict | Counter,
    limit: int = 5
) -> None:

    print_header("MOST TARGETED USERNAMES")

    if not targeted_users:
        print("No targeted username statistics available.")
        return

    print(f"{'USERNAME':<30} {'ATTEMPTS':>12}")
    print_line("-")

    for username, count in Counter(targeted_users).most_common(limit):
        print(f"{username:<30} {count:>12}")


def display_event_distribution(event_counts: dict) -> None:

    print_header("EVENT DISTRIBUTION")

    if not event_counts:
        print("No event distribution available.")
        return

    for event, count in event_counts.items():
        print_item(str(event), count)


def display_detection_summary(findings: list[dict]) -> None:

    print_header("DETECTION SUMMARY")

    if not findings:
        print("No detection rules triggered.")
        return

    detection_counts = Counter(
        finding.get("title", "Unknown") for finding in findings
    )

    for title, count in detection_counts.most_common():
        print_item(str(title), count)


def generate_cli_report(
    stats: dict,
    findings: list[dict],
    attacker_ips: dict,
    targeted_users: dict,
    event_counts: dict
) -> None:

    print()
    print_line("=")

    print(
        f"{Colors.BOLD}{Colors.CYAN}"
        "       LINUX AUTHENTICATION LOG SECURITY REPORT"
        f"{Colors.RESET}"
    )

    print_line("=")

    print_item(
        "Report generated",
        datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    )

    display_log_summary(stats)
    display_security_findings(findings)
    display_severity_breakdown(findings)
    display_top_attacker_ips(attacker_ips)
    display_targeted_usernames(targeted_users)
    display_event_distribution(event_counts)
    display_detection_summary(findings)

    print()
    print_line("=")

    print(
        f"{Colors.BOLD}{Colors.GREEN}"
        "             END OF SECURITY REPORT"
        f"{Colors.RESET}"
    )

    print_line("=")
