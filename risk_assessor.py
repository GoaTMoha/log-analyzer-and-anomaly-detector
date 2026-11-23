from typing import Any


SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}



SEVERITY_MAPPING = {

    "successful_login": "LOW",
    "failed_login": "LOW",
    "session_opened": "LOW",
    "session_closed": "LOW",
    "sudo_usage": "LOW",

    "multiple_failures": "MEDIUM",
    "excessive_sudo_attempts": "MEDIUM",
    "multiple_usernames_one_ip": "MEDIUM",
    "one_username_many_ips": "MEDIUM",
    "suspicious_ip_activity": "MEDIUM",
    "login_outside_business_hours": "MEDIUM",
    "login_after_multiple_failures": "MEDIUM",

    "brute_force": "HIGH",
    "root_login": "HIGH",
    "new_ip_login": "HIGH",
    "invalid_user": "HIGH",
    "unusual_activity": "HIGH",

    "multiple_failed_root_attempts": "CRITICAL",
}



def normalize_event(event: str) -> str:

    if not isinstance(event, str):
        return "unknown"

    return (
        event.strip()
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
    )



def assess_severity(
    event: str,
    count: int = 1,
    username: str = None,
    failed_root_threshold: int = 3
) -> str:


    event = normalize_event(event)

    if (
        event in ("failed_login", "multiple_failures")
        and username == "root"
        and count >= failed_root_threshold
    ):
        return "CRITICAL"

    severity = SEVERITY_MAPPING.get(event)

    if severity:
        return severity

    return "LOW"


def assess_findings(
    findings: list[dict[str, Any]],
    failed_root_threshold: int = 3
) -> list[dict[str, Any]]:

    assessed_findings = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        assessed = finding.copy()

        event = assessed.get("event_type", "unknown")

        count = assessed.get("count", 1)

        username = assessed.get("username")

        assessed["severity"] = assess_severity(
            event=event,
            count=count,
            username=username,
            failed_root_threshold=failed_root_threshold
        )

        assessed_findings.append(assessed)

    return assessed_findings


def calculate_severity_statistics(
    findings: list[dict[str, Any]]
) -> dict[str, int]:

    statistics = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for finding in findings:

        severity = finding.get("severity", "LOW")

        if severity in statistics:
            statistics[severity] += 1

    return statistics


def get_overall_risk(
    statistics: dict[str, int]
) -> str:

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):

        if statistics.get(severity, 0) > 0:
            return severity

    return "LOW"


def sort_findings(
    findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:

    return sorted(
        findings,
        key=lambda finding: SEVERITY_LEVELS.get(
            finding.get("severity", "LOW"),
            0
        ),
        reverse=True
    )

def assess_risk(
    findings: list[dict[str, Any]],
    failed_root_threshold: int = 3
) -> dict[str, Any]:

    assessed = assess_findings(
        findings,
        failed_root_threshold
    )

    assessed = sort_findings(assessed)

    statistics = calculate_severity_statistics(assessed)

    overall_risk = get_overall_risk(statistics)

    return {
        "findings": assessed,
        "severity_statistics": statistics,
        "overall_risk": overall_risk,
        "total_findings": len(assessed)
    }

if __name__ == "__main__":

    sample_findings = [

        {
            "event_type": "successful_login",
            "username": "john",
            "count": 1
        },

        {
            "event_type": "failed_login",
            "username": "admin",
            "count": 2
        },

        {
            "event_type": "multiple_failures",
            "username": "john",
            "count": 8
        },

        {
            "event_type": "brute_force",
            "username": "root",
            "count": 15
        },

        {
            "event_type": "multiple_failed_root_attempts",
            "username": "root",
            "count": 5
        },

        {
            "event_type": "root_login",
            "username": "root",
            "count": 1
        }
    ]

    results = assess_risk(sample_findings)

    print("\n========== SECURITY RISK ASSESSMENT ==========")

    print("\nOverall Risk:", results["overall_risk"])

    print("\nSeverity Statistics:")

    for severity, count in results["severity_statistics"].items():
        print(f"{severity}: {count}")

    print("\nAssessed Security Findings:")

    for finding in results["findings"]:
        print(
            f"{finding['event_type']} | "
            f"{finding['username']} | "
            f"{finding['severity']}"
        )

    print("\nTotal Findings:", results["total_findings"])
