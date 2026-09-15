from datetime import datetime


def generate_report(logs, alerts, vulnerabilities):

    report = ""

    # --------------------------------
    # REPORT HEADER
    # --------------------------------

    report += "=" * 70 + "\n"
    report += "CYBERSHIELD SECURITY ASSESSMENT REPORT\n"
    report += "=" * 70 + "\n\n"

    report += f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "Assessment Type: Controlled Laboratory Assessment\n"
    report += "System: CyberShield Security Monitoring Platform\n\n"

    # --------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------

    report += "-" * 70 + "\n"
    report += "1. EXECUTIVE SUMMARY\n"
    report += "-" * 70 + "\n\n"

    report += (
        "This report summarizes the results of a controlled cybersecurity "
        "assessment performed using the CyberShield security monitoring "
        "prototype. The assessment includes security log analysis, "
        "threat detection, vulnerability assessment and incident analysis.\n\n"
    )

    report += f"Total Security Events: {len(logs)}\n"
    report += f"Threats Detected: {len(alerts)}\n"

    if not alerts.empty:
        critical = len(
            alerts[alerts["Severity"] == "Critical"]
        )

        high = len(
            alerts[alerts["Severity"] == "High"]
        )

        report += f"Critical Threats: {critical}\n"
        report += f"High Threats: {high}\n"

    report += "\n"

    # --------------------------------
    # THREAT FINDINGS
    # --------------------------------

    report += "-" * 70 + "\n"
    report += "2. THREAT DETECTION FINDINGS\n"
    report += "-" * 70 + "\n\n"

    if alerts.empty:

        report += "No threats were detected.\n\n"

    else:

        for index, row in alerts.iterrows():

            report += f"Incident {index + 1}\n"
            report += f"Threat Type: {row['Threat']}\n"
            report += f"Source IP: {row['Source IP']}\n"
            report += f"Attempts: {row['Attempts']}\n"
            report += f"Severity: {row['Severity']}\n"
            report += (
                f"Recommendation: {row['Recommendation']}\n"
            )

            report += "\n"

    # --------------------------------
    # VULNERABILITY FINDINGS
    # --------------------------------

    report += "-" * 70 + "\n"
    report += "3. VULNERABILITY ASSESSMENT\n"
    report += "-" * 70 + "\n\n"

    if vulnerabilities.empty:

        report += "No vulnerabilities were recorded.\n\n"

    else:

        for index, row in vulnerabilities.iterrows():

            report += f"Finding {index + 1}\n"
            report += f"Host: {row['host']}\n"
            report += f"Port: {row['port']}\n"
            report += f"Service: {row['service']}\n"
            report += f"Severity: {row['severity']}\n"
            report += (
                f"Description: {row['description']}\n"
            )
            report += (
                f"Recommendation: {row['recommendation']}\n"
            )

            report += "\n"

    # --------------------------------
    # SECURITY RECOMMENDATIONS
    # --------------------------------

    report += "-" * 70 + "\n"
    report += "4. SECURITY RECOMMENDATIONS\n"
    report += "-" * 70 + "\n\n"

    recommendations = [
        "Implement multi-factor authentication.",
        "Use account lockout or rate-limiting mechanisms.",
        "Restrict unnecessary network services.",
        "Review exposed ports and services regularly.",
        "Monitor repeated authentication failures.",
        "Maintain centralized security logs.",
        "Perform regular vulnerability assessments.",
        "Document and investigate security incidents."
    ]

    for recommendation in recommendations:

        report += f"- {recommendation}\n"

    report += "\n"

    # --------------------------------
    # CONCLUSION
    # --------------------------------

    report += "-" * 70 + "\n"
    report += "5. CONCLUSION\n"
    report += "-" * 70 + "\n\n"

    report += (
        "The CyberShield prototype successfully demonstrates a basic "
        "cybersecurity monitoring workflow consisting of security log "
        "analysis, rule-based threat detection, vulnerability assessment, "
        "incident classification and security reporting.\n\n"
    )

    report += (
        "The assessment was performed in a controlled laboratory "
        "environment using simulated security events and authorized "
        "local scanning.\n"
    )

    report += "\n" + "=" * 70 + "\n"
    report += "END OF REPORT\n"
    report += "=" * 70 + "\n"

    return report