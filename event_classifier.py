EVENT_CATEGORIES = [
    "SUCCESSFUL_SSH_LOGIN",
    "FAILED_SSH_LOGIN",
    "INVALID_USERNAME",
    "SUDO_USAGE",
    "SESSION_OPENED",
    "SESSION_CLOSED",
    "AUTHENTICATION_FAILURE",
    "ROOT_LOGIN",
    "USER_CREATION",
    "PASSWORD_CHANGE",
    "UNKNOWN"
]

FAILED_EVENTS = {
    "FAILED_SSH_LOGIN",
    "INVALID_USERNAME",
    "AUTHENTICATION_FAILURE"
}

SUCCESS_EVENTS = {
    "SUCCESSFUL_SSH_LOGIN",
    "ROOT_LOGIN"
}


def classify_event(log_line):

    line = log_line.casefold()

    if "invalid user" in line:
        return "INVALID_USERNAME"

    if (
        "accepted password for root " in line
        or "accepted publickey for root " in line
    ):
        return "ROOT_LOGIN"

    if "failed password" in line or "failed publickey" in line:
        return "FAILED_SSH_LOGIN"

    if "accepted password" in line or "accepted publickey" in line:
        return "SUCCESSFUL_SSH_LOGIN"

    if "authentication failure" in line:
        return "AUTHENTICATION_FAILURE"

    if "password changed" in line or "chauthtok" in line:
        return "PASSWORD_CHANGE"

    if "new user:" in line or "useradd[" in line:
        return "USER_CREATION"

    if "sudo:" in line:
        return "SUDO_USAGE"

    if "session opened" in line:
        return "SESSION_OPENED"

    if "session closed" in line:
        return "SESSION_CLOSED"

    return "UNKNOWN"
