import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("log_analyzer.html_report")

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_TEMPLATE_DIR = BASE_DIR / "templates"
DEFAULT_OUTPUT_PATH = BASE_DIR / "reports" / "report.html"

REPORT_FIELDS = {
    "summary": dict,
    "severity_counts": dict,
    "findings": list,
    "top_attacker_ips": list,
    "targeted_usernames": list
}


class HTMLReportGenerator:

    def __init__(self, template_dir=DEFAULT_TEMPLATE_DIR):
        self.template_dir = Path(template_dir)

        self.environment = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(enabled_extensions=("html", "xml")),
            trim_blocks=True,
            lstrip_blocks=True
        )

    def validate_data(self, report_data):

        if not isinstance(report_data, dict):
            raise TypeError("Report data must be a dictionary")

        for field, expected_type in REPORT_FIELDS.items():
            if field not in report_data:
                raise ValueError(f"Missing required report field: {field}")

            if not isinstance(report_data[field], expected_type):
                raise TypeError(f"Invalid report field: {field}")

    def prepare_data(self, report_data):

        self.validate_data(report_data)

        data = report_data.copy()

        data["generated_at"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        return data

    def generate(self, report_data, output_path=DEFAULT_OUTPUT_PATH):

        try:
            data = self.prepare_data(report_data)

            template = self.environment.get_template("report.html")
            html_content = template.render(**data)

            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(html_content, encoding="utf-8")

            logger.info("HTML report generated: %s", output)

            return output

        except Exception:
            logger.exception("Failed to generate HTML security report")
            raise


if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    sample_data = {
        "summary": {
            "total_events": 1500,
            "successful_logins": 120,
            "failed_logins": 850,
            "unknown_events": 30
        },

        "severity_counts": {
            "LOW": 10,
            "MEDIUM": 5,
            "HIGH": 3,
            "CRITICAL": 1
        },

        "findings": [
            {
                "title": "SSH Brute Force Detected",
                "description": "Multiple failed login attempts.",
                "severity": "HIGH",
                "source_ip": "192.168.1.50",
                "username": "admin",
                "timestamp": "Nov 21 10:30:00"
            }
        ],

        "top_attacker_ips": [
            {"ip": "192.168.1.50", "count": 120},
            {"ip": "10.0.0.15", "count": 65}
        ],

        "targeted_usernames": [
            {"username": "root", "count": 80},
            {"username": "admin", "count": 60}
        ]
    }

    report_path = HTMLReportGenerator().generate(sample_data)

    print(f"Report created: {report_path}")
