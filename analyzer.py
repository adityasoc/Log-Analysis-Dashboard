from collections import Counter


def analyze_logs(logs):
    """
    Analyze parsed logs and generate security findings.
    """

    findings = []

    # Track failed logins by IP for brute-force detection
    failed_logins = Counter()

    for log in logs:
        if (
            log.get("event", "").upper() == "LOGIN"
            and log.get("status", "").upper() == "FAILED"
        ):
            failed_logins[log["ip"]] += 1

    for log in logs:

        message = log.get("message", "").lower()
        level = log.get("level", "").upper()
        ip = log.get("ip", "")
        event = log.get("event", "").upper()
        status = log.get("status", "").upper()

        # ==========================================
        # CRITICAL - Credential Dumping
        # ==========================================

        if (
            "credential dumping" in message
            or "credential dump" in message
            or "credential dumping tool" in message
        ):
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Credential Dumping",
                "severity": "Critical",
                "score": 10,
                "message": log["message"]
            })

        # ==========================================
        # HIGH - PowerShell Encoded Command
        # ==========================================

        elif (
            "powershell" in message
            and (
                "encoded" in message
                or "command" in message
            )
        ):
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Suspicious PowerShell Activity",
                "severity": "High",
                "score": 8,
                "message": log["message"]
            })

        # ==========================================
        # HIGH - Repeated Failed Login / Brute Force
        # ==========================================

        elif (
            event == "LOGIN"
            and status == "FAILED"
            and failed_logins[ip] >= 3
        ):
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Brute Force / Repeated Failed Login",
                "severity": "High",
                "score": 8,
                "message": log["message"]
            })

        # ==========================================
        # MEDIUM - Single Failed Login
        # ==========================================

        elif (
            event == "LOGIN"
            and status == "FAILED"
        ):
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Failed Login",
                "severity": "Medium",
                "score": 5,
                "message": log["message"]
            })

        # ==========================================
        # MEDIUM - Firewall / Network Denial
        # ==========================================

        elif (
            event == "NETWORK"
            and status == "DENIED"
        ):
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Blocked Network Connection",
                "severity": "Medium",
                "score": 4,
                "message": log["message"]
            })

        # ==========================================
        # HIGH - Unauthorized Access
        # ==========================================

        elif "unauthorized" in message:
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Unauthorized Access",
                "severity": "High",
                "score": 8,
                "message": log["message"]
            })

        # ==========================================
        # MEDIUM - Suspicious Activity
        # ==========================================

        elif "suspicious" in message:
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Suspicious Activity",
                "severity": "Medium",
                "score": 5,
                "message": log["message"]
            })

        # ==========================================
        # CRITICAL - Explicit Critical Log
        # ==========================================

        elif level == "CRITICAL":
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "Critical Security Event",
                "severity": "Critical",
                "score": 10,
                "message": log["message"]
            })

        # ==========================================
        # LOW - Generic Error
        # ==========================================

        elif level == "ERROR":
            findings.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "type": "System Error",
                "severity": "Low",
                "score": 2,
                "message": log["message"]
            })

    return findings


def calculate_ip_risk(findings):
    """
    Calculate risk score for every suspicious IP.
    """

    ip_scores = Counter()
    ip_events = Counter()

    for finding in findings:

        ip = finding["ip"]

        ip_scores[ip] += finding["score"]
        ip_events[ip] += 1

    risk_data = []

    for ip in ip_scores:

        score = ip_scores[ip]
        events = ip_events[ip]

        if score >= 20:
            risk_level = "Critical"

        elif score >= 12:
            risk_level = "High"

        elif score >= 5:
            risk_level = "Medium"

        else:
            risk_level = "Low"

        risk_data.append({
            "ip": ip,
            "score": score,
            "events": events,
            "risk": risk_level
        })

    risk_data.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return risk_data


def get_statistics(logs, findings):
    """
    Generate dashboard statistics.
    """

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    level_counts = Counter(
        log["level"]
        for log in logs
    )

    ip_counts = Counter(
        finding["ip"]
        for finding in findings
    )

    ip_risk = calculate_ip_risk(findings)

    return {
        "total_logs": len(logs),

        "total_findings": len(findings),

        "critical": severity_counts.get(
            "Critical", 0
        ),

        "high": severity_counts.get(
            "High", 0
        ),

        "medium": severity_counts.get(
            "Medium", 0
        ),

        "low": severity_counts.get(
            "Low", 0
        ),

        "top_ips": ip_counts.most_common(),

        "ip_risk": ip_risk,

        "log_levels": dict(level_counts)
    }


if __name__ == "__main__":

    from log_parser import parse_log_file

    log_file = "data/sample.log"

    logs = parse_log_file(log_file)

    findings = analyze_logs(logs)

    statistics = get_statistics(
        logs,
        findings
    )

    print("\n========== SECURITY ANALYSIS ==========")

    print(
        f"Total Logs     : "
        f"{statistics['total_logs']}"
    )

    print(
        f"Total Findings : "
        f"{statistics['total_findings']}"
    )

    print(
        f"Critical       : "
        f"{statistics['critical']}"
    )

    print(
        f"High           : "
        f"{statistics['high']}"
    )

    print(
        f"Medium         : "
        f"{statistics['medium']}"
    )

    print(
        f"Low            : "
        f"{statistics['low']}"
    )

    print("\n========== IP RISK ANALYSIS ==========")

    for item in statistics["ip_risk"]:

        print(
            f"{item['ip']} | "
            f"Risk: {item['risk']} | "
            f"Score: {item['score']} | "
            f"Events: {item['events']}"
        )
