# Log Analyzer and Anomaly Detector

A small Python tool that reads a Linux authentication log (such as `/var/log/auth.log`), finds suspicious activity, and produces two reports: one in the terminal and one as an HTML page.

## What it does

1. **Parses** each log line into fields (time, host, process, message, username, IP address).
2. **Classifies** each line into a category, for example `FAILED_SSH_LOGIN`, `ROOT_LOGIN` or `SUDO_USAGE`.
3. **Detects** suspicious behaviour with four rules:
   - *Brute force*: many failed logins from the same IP.
   - *Suspicious IP activity*: one IP appears in a very large number of events.
   - *Multiple IP login*: one user logs in successfully from many different IPs.
   - *Unusual activity*: messages containing words such as "unauthorized" or "access denied".
4. **Assigns a severity** (LOW, MEDIUM, HIGH or CRITICAL) to each finding.
5. **Calculates statistics**: totals, top attacking IPs, most targeted usernames.
6. **Reports** the results in the terminal and in `reports/report.html`.

Lines that do not look like a log entry are counted and skipped, so a damaged log never crashes the program.

## Requirements

- Python 3.10 or newer
- Jinja2 (used for the HTML report)

```
pip install -r requirements.txt
```

## How to run

```
python main.py                     # analyzes data/sample_auth.log
python main.py /path/to/auth.log   # analyzes your own log file
```

The terminal report is printed on screen. The HTML report is saved to `reports/report.html`; open it in any web browser. Messages about the run are written to `logs/analyzer.log`.

The program exits with code `0` on success and `1` if the log file cannot be read.

## Expected log format

Classic syslog lines, for example:

```
Nov 21 10:15:32 server sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
```

Syslog lines contain no year, so the reports show dates like `Nov 21`. Only IPv4 addresses are recognised.

## Project structure

```
main.py              Entry point: connects all the steps below
parser.py            Turns log lines into dictionaries
event_classifier.py  Gives each line a category
anomaly_detector.py  The four detection rules
risk_assessor.py     Assigns a severity to each finding
statistics.py        Counts and rankings
cli_report.py        Terminal report
html_report.py       Fills the HTML template with the results
config.py            Loads and checks data/config.json
logger.py            Logging to the console and logs/analyzer.log
templates/report.html   The HTML report design (Jinja2 template)
data/config.json        Settings
data/sample_auth.log    Example log to try the tool
reports/                Generated HTML report
logs/                   Program log
```

## Configuration

Settings are in `data/config.json`. If the file is missing or contains an invalid value, the program prints a warning and uses the defaults.

| Setting | Default | Meaning |
|---|---|---|
| `failed_login_threshold` | 5 | Failed logins from one IP before it counts as brute force |
| `multiple_ips_threshold` | 5 | Number of different IPs one user logs in from before it is flagged |
| `report_output` | `reports/` | Folder for the HTML report |
| `log_output` | `logs/analyzer.log` | Program log file |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |
| `html_report` | `true` | Create the HTML report |
| `cli_report` | `true` | Print the terminal report |

The file also contains `brute_force_window_minutes`, `multiple_usernames_threshold`, `root_login_alert`, `business_hours`, `business_hours_detection`, `excessive_sudo_threshold` and `new_ip_detection`. They are read and validated, but no detection rule uses them yet.

## Known limitations

- Only IPv4 addresses are parsed.
- A failed login for an invalid user can be counted twice, because sshd writes two lines for it.
- Only the four detection rules above exist.
