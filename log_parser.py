import re
from datetime import datetime


def parse_log_line(line):
    """
    Parse a log line in the format:

    2026-08-12 09:03:21 | WARN | src_ip=192.168.1.50 |
    user=admin | event=LOGIN | status=FAILED | message=Invalid password
    """

    line = line.strip()

    if not line:
        return None

    pattern = (
        r"^(\d{4}-\d{2}-\d{2})\s+"
        r"(\d{2}:\d{2}:\d{2})\s*\|\s*"
        r"(INFO|WARN|WARNING|ERROR|CRITICAL|DEBUG)\s*\|\s*"
        r"src_ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*\|\s*"
        r"user=([^|]+)\s*\|\s*"
        r"event=([^|]+)\s*\|\s*"
        r"status=([^|]+)\s*\|\s*"
        r"message=(.*)$"
    )

    match = re.match(pattern, line)

    if not match:
        return None

    (
        date_part,
        time_part,
        level,
        ip,
        user,
        event,
        status,
        message
    ) = match.groups()

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
        "message": message.strip(),
        "user": user.strip(),
        "event": event.strip(),
        "status": status.strip()
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
