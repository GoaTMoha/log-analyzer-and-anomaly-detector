from collections import Counter
from datetime import datetime
from typing import Any

from event_classifier import FAILED_EVENTS, SUCCESS_EVENTS

PLACEHOLDER_YEAR = 2000


def parse_syslog_time(timestamp):
    try:
        return datetime.strptime(
            f"{PLACEHOLDER_YEAR} {timestamp}", "%Y %b %d %H:%M:%S"
        )
    except (ValueError, TypeError):
        return None


class LogStatistics:
    def __init__(self, events: list[dict[str, Any]]):
        self.events = events

    def _count_events(self, *event_types: str) -> int:
        return sum(
            1 for event in self.events
            if event.get("event_type") in event_types
        )

    def _failed_events(self) -> list[dict[str, Any]]:
        return [
            event for event in self.events
            if event.get("event_type") in FAILED_EVENTS
        ]

    def _event_times(self, event_types: set[str]):
        for event in self.events:
            if event.get("event_type") in event_types:
                parsed_time = parse_syslog_time(event.get("timestamp"))
                if parsed_time:
                    yield parsed_time

    def total_events(self) -> int:
        return len(self.events)

    def successful_logins(self) -> int:
        return self._count_events(*SUCCESS_EVENTS)

    def failed_logins(self) -> int:
        return self._count_events("FAILED_SSH_LOGIN")

    def invalid_users(self) -> int:
        return self._count_events("INVALID_USERNAME")

    def sudo_events(self) -> int:
        return self._count_events("SUDO_USAGE")

    def unknown_events(self) -> int:
        return self._count_events("UNKNOWN")

    def top_attacking_ips(self, limit: int = 10) -> list[tuple]:
        counter = Counter(
            event.get("source_ip") for event in self._failed_events()
            if event.get("source_ip")
        )
        return counter.most_common(limit)

    def most_targeted_users(self, limit: int = 10) -> list[tuple]:
        counter = Counter(
            event.get("username") for event in self._failed_events()
            if event.get("username")
        )
        return counter.most_common(limit)

    def login_frequency(self) -> dict:
        times = self._event_times(SUCCESS_EVENTS | {"FAILED_SSH_LOGIN"})
        per_hour = Counter(
            time.replace(minute=0, second=0) for time in times
        )
        return {
            hour.strftime("%b %d %H:00"): count
            for hour, count in sorted(per_hour.items())
        }

    def failed_login_trends(self) -> dict:
        times = self._event_times({"FAILED_SSH_LOGIN"})
        per_day = Counter(time.date() for time in times)
        return {
            day.strftime("%b %d"): count
            for day, count in sorted(per_day.items())
        }

    def authentication_methods(self) -> dict:
        methods = Counter(
            event.get("authentication_method") for event in self.events
            if event.get("authentication_method")
        )
        return dict(methods.most_common())

    def event_distribution(self) -> dict:
        distribution = Counter(
            event.get("event_type", "UNKNOWN") for event in self.events
        )
        return dict(distribution.most_common())

    def generate_summary(self) -> dict:
        return {
            "total_events": self.total_events(),
            "successful_logins": self.successful_logins(),
            "failed_logins": self.failed_logins(),
            "unknown_events": self.unknown_events(),
            "invalid_users": self.invalid_users(),
            "sudo_events": self.sudo_events(),
            "top_attacking_ips": self.top_attacking_ips(),
            "most_targeted_users": self.most_targeted_users(),
            "login_frequency": self.login_frequency(),
            "failed_login_trends": self.failed_login_trends(),
            "authentication_methods": self.authentication_methods(),
            "event_distribution": self.event_distribution()
        }
