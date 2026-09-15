import socket
import pandas as pd


# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "Web Application"
}


def get_severity(port):

    if port in [21, 23, 445, 3306, 3389]:
        return "High"

    elif port in [22, 80, 8080]:
        return "Medium"

    else:
        return "Low"


def get_recommendation(port, service):

    if port == 22:
        return "Restrict SSH access and use key-based authentication."

    elif port == 80:
        return "Prefer HTTPS and redirect HTTP traffic."

    elif port == 3306:
        return "Restrict database access to authorized hosts."

    elif port == 445:
        return "Restrict SMB access and disable it if unnecessary."

    elif port == 3389:
        return "Restrict RDP access and use strong authentication."

    elif port == 21:
        return "Avoid FTP where possible and use secure alternatives."

    elif port == 23:
        return "Disable Telnet and use SSH instead."

    else:
        return f"Review the configuration of the {service} service."


def scan_localhost():

    results = []

    target = "127.0.0.1"

    for port, service in COMMON_PORTS.items():

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.3)

        result = sock.connect_ex(
            (target, port)
        )

        if result == 0:

            severity = get_severity(port)

            recommendation = get_recommendation(
                port,
                service
            )

            results.append({
                "Host": target,
                "Port": port,
                "Service": service,
                "Status": "OPEN",
                "Severity": severity,
                "Recommendation": recommendation
            })

        sock.close()

    return pd.DataFrame(results)