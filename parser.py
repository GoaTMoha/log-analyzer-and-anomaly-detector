import ipaddress
import re

LINE_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\s\[:]+)(?:\[\d+\])?:\s*"
    r"(?P<message>.*)$"
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

METHOD_PATTERN = re.compile(r"\b(?:Accepted|Failed) ([\w-]+) for ")

USERNAME_PATTERNS = [
    re.compile(r"[Ii]nvalid user (\S+)"),
    re.compile(r"(?:Accepted|Failed) [\w-]+ for (\S+)"),
    re.compile(r"\bfor user ([^\s(]+)"),
    re.compile(r"\buser=(\S+)"),
    re.compile(r"new user: name=([^,\s]+)"),
    re.compile(r"password changed for (\S+)"),
    re.compile(r"^(\S+) : "),
]


def extract_ip(message):

    for match in IP_PATTERN.finditer(message):
        try:
            return str(ipaddress.IPv4Address(match.group()))
        except ValueError:
            continue

    return None


def extract_username(message):

    for pattern in USERNAME_PATTERNS:
        match = pattern.search(message)

        if match:
            return match.group(1)

    return None


def extract_authentication_method(message):

    match = METHOD_PATTERN.search(message)

    if match:
        return match.group(1)

    return None


def parse_line(line):

    match = LINE_PATTERN.match(line)

    if not match:
        return None

    message = match.group("message")

    return {
        "timestamp": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "process": match.group("process"),
        "message": message,
        "username": extract_username(message),
        "source_ip": extract_ip(message),
        "authentication_method": extract_authentication_method(message),
        "raw": line
    }


def parse_log(filename):

    events = []
    invalid_count = 0

    with open(filename, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            event = parse_line(line)

            if event is None:
                invalid_count += 1
            else:
                events.append(event)

    return events, len(events), invalid_count
