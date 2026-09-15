import pandas as pd


def load_logs():
    return pd.read_csv("data/security_logs.csv")


def detect_threats(df):
    alerts = []

    # Detect brute-force attacks
    failed_logins = df[df["event_type"] == "LOGIN_FAILED"]

    attempts = failed_logins.groupby("source_ip").size()

    for ip, count in attempts.items():

        if count >= 5:
            alerts.append({
                "Threat": "Brute Force Attack",
                "Source IP": ip,
                "Attempts": count,
                "Severity": "Critical",
                "Recommendation": "Enable MFA and account lockout"
            })

    # Detect port scanning
    port_scans = df[df["event_type"] == "PORT_SCAN"]

    scans = port_scans.groupby("source_ip").size()

    for ip, count in scans.items():

        if count >= 3:
            alerts.append({
                "Threat": "Port Scanning",
                "Source IP": ip,
                "Attempts": count,
                "Severity": "High",
                "Recommendation": "Investigate source and restrict exposed services"
            })

    return pd.DataFrame(alerts)