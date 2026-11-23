from collections import defaultdict
from typing import Any

from event_classifier import FAILED_EVENTS, SUCCESS_EVENTS

SUSPICIOUS_KEYWORDS = (
    "unauthorized",
    "permission denied",
    "access denied",
    "privilege escalation",
    "root access",
    "account locked",
    "suspicious"
)


class AnomalyDetector:

    def __init__(
        self,
        failed_login_threshold: int = 5,
        suspicious_ip_threshold: int = 20,
        multiple_ip_threshold: int = 3
    ):
        self.failed_login_threshold = failed_login_threshold
        self.suspicious_ip_threshold = suspicious_ip_threshold
        self.multiple_ip_threshold = multiple_ip_threshold

    def detect(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:

        anomalies = []

        anomalies.extend(self.detect_brute_force(events))
        anomalies.extend(self.detect_suspicious_ips(events))
        anomalies.extend(self.detect_multiple_ip_logins(events))
        anomalies.extend(self.detect_unusual_activity(events))

        return anomalies

    def detect_brute_force(
        self, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        failed_by_ip = defaultdict(list)

        for event in events:
            ip = event.get("source_ip")

            if event.get("event_type") in FAILED_EVENTS and ip:
                failed_by_ip[ip].append(event)

        anomalies = []

        for ip, attempts in failed_by_ip.items():
            if len(attempts) >= self.failed_login_threshold:
                anomalies.append({
                    "title": "Brute Force Attack",
                    "event_type": "brute_force",
                    "source_ip": ip,
                    "count": len(attempts),
                    "timestamp": attempts[-1]["timestamp"],
                    "description": (
                        f"{len(attempts)} failed login attempts "
                        f"detected from IP {ip}."
                    )
                })

        return anomalies

    def detect_suspicious_ips(
        self, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        events_by_ip = defaultdict(list)

        for event in events:
            ip = event.get("source_ip")

            if ip:
                events_by_ip[ip].append(event)

        anomalies = []

        for ip, ip_events in events_by_ip.items():
            if len(ip_events) >= self.suspicious_ip_threshold:
                anomalies.append({
                    "title": "Suspicious IP Activity",
                    "event_type": "suspicious_ip_activity",
                    "source_ip": ip,
                    "count": len(ip_events),
                    "timestamp": ip_events[-1]["timestamp"],
                    "description": (
                        f"IP {ip} generated {len(ip_events)} log events."
                    )
                })

        return anomalies

    def detect_multiple_ip_logins(
        self, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        logins_by_user = defaultdict(list)

        for event in events:
            username = event.get("username")

            if (
                event.get("event_type") in SUCCESS_EVENTS
                and username
                and event.get("source_ip")
            ):
                logins_by_user[username].append(event)

        anomalies = []

        for username, logins in logins_by_user.items():
            ips = sorted({login["source_ip"] for login in logins})

            if len(ips) >= self.multiple_ip_threshold:
                anomalies.append({
                    "title": "Multiple IP Login",
                    "event_type": "one_username_many_ips",
                    "username": username,
                    "source_ips": ips,
                    "count": len(ips),
                    "timestamp": logins[-1]["timestamp"],
                    "description": (
                        f"User {username} logged in from "
                        f"{len(ips)} different IP addresses."
                    )
                })

        return anomalies

    def detect_unusual_activity(
        self, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        anomalies = []

        for event in events:
            message = str(event.get("message", "")).lower()

            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in message:
                    anomalies.append({
                        "title": "Unusual Activity",
                        "event_type": "unusual_activity",
                        "source_ip": event.get("source_ip"),
                        "username": event.get("username"),
                        "timestamp": event.get("timestamp"),
                        "description": (
                            f"Suspicious activity detected: {keyword}"
                        ),
                        "original_event": event
                    })
                    break

        return anomalies
