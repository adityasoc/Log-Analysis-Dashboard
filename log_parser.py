import re
from datetime import datetime


def parse_log_line(line):
    """
    Parse a single log line and return structured information.
    Expected format:

    2026-08-21 10:15:23 INFO 192.168.1.10 User login successful
    """

    pattern = (
        r"^(\d{4}-\d{2}-\d{2})\s+"
        r"(\d{2}:\d{2}:\d{2})\s+"
        r"(INFO|WARNING|ERROR|CRITICAL|DEBUG)\s+"
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(.+)$"
    )

    match = re.match(pattern, line.strip())

    if not match:
        return None

    date_part, time_part, level, ip, message = match.groups()

    try:
        timestamp = datetime.strptime(
            f"{date_part} {time_part}",
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "level": level,
        "ip": ip,
        "message": message.strip()
    }


def parse_log_file(file_path):
    """
    Read and parse a complete log file.
    """

    logs = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):

                if not line.strip():
                    continue

                parsed = parse_log_line(line)

                if parsed:
                    parsed["line_number"] = line_number
                    logs.append(parsed)

    except FileNotFoundError:
        print(f"Log file not found: {file_path}")

    except Exception as error:
        print(f"Error reading log file: {error}")

    return logs

if __name__ == "__main__":
    log_file = "data/sample.log"

    logs = parse_log_file(log_file)

    print(f"\nTotal logs parsed: {len(logs)}")

    for log in logs:
        print(
            log["timestamp"],
            "|",
            log["level"],
            "|",
            log["ip"],
            "|",
            log["message"]
        )