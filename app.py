import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

from detector import load_logs, detect_threats
from scanner import scan_localhost
from report_generator import generate_report


# Page configuration
st.set_page_config(
    page_title="CyberShield",
    page_icon="🛡️",
    layout="wide"
)


# Load custom CSS
css_file = Path("style.css")

if css_file.exists():
    st.markdown(
        f"<style>{css_file.read_text()}</style>",
        unsafe_allow_html=True
    )
# ==========================================
# PAGE CONFIGURATION
# ==========================================


# ==========================================
# SIDEBAR
# ==========================================

st.sidebar.title("🛡️ CyberShield")
st.sidebar.caption("Security Operations Platform")

st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Dashboard",
        "🔍 Vulnerability Assessment",
        "🚨 Threat Monitoring",
        "⚠️ Incident Response",
        "📄 Security Reports"
    ]
)


# ==========================================
# LOAD DATA
# ==========================================

logs = load_logs()
alerts = detect_threats(logs)


# ==========================================
# DASHBOARD
# ==========================================

if page == "📊 Dashboard":

    st.title("📊 Security Dashboard")

    st.subheader(
        "Cybersecurity Vulnerability Assessment & Security Monitoring System"
    )

    st.caption(
        "Controlled laboratory security monitoring prototype"
    )

    # Metrics
    total_events = len(logs)
    total_alerts = len(alerts)

    critical_alerts = (
        len(alerts[alerts["Severity"] == "Critical"])
        if not alerts.empty else 0
    )

    high_alerts = (
        len(alerts[alerts["Severity"] == "High"])
        if not alerts.empty else 0
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Security Events",
            total_events
        )

    with col2:
        st.metric(
            "Threats Detected",
            total_alerts
        )

    with col3:
        st.metric(
            "Critical Alerts",
            critical_alerts
        )

    with col4:
        st.metric(
            "High Alerts",
            high_alerts
        )

    st.divider()

    # Threat summary
    st.header("🚨 Recent Threats")

    if alerts.empty:
        st.success("No suspicious activity detected.")

    else:
        st.dataframe(
            alerts,
            use_container_width=True
        )

    st.divider()

    # Event chart
    st.header("📊 Security Event Analysis")

    event_counts = (
        logs["event_type"]
        .value_counts()
        .reset_index()
    )

    event_counts.columns = [
        "Event Type",
        "Count"
    ]

    fig = px.bar(
        event_counts,
        x="Event Type",
        y="Count",
        title="Security Events by Type"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ==========================================
# VULNERABILITY ASSESSMENT
# ==========================================

elif page == "🔍 Vulnerability Assessment":

    st.title("🔍 Vulnerability Assessment")

    st.write(
        "Perform a basic exposure assessment of the local "
        "machine by checking commonly used TCP ports."
    )

    st.warning(
        "⚠️ Security scanning is restricted to the local "
        "machine (127.0.0.1) for controlled laboratory testing."
    )

    st.divider()

    # Start scan
    if st.button("🔍 Start Local Security Scan"):

        with st.spinner("Scanning localhost..."):

            scan_results = scan_localhost()

        # Check results
        if not scan_results.empty:
            st.success("Scan completed")
        else:
            st.info("No open ports found.")

            st.session_state["scan_results"] = scan_results


    # Display previous scan results
    if "scan_results" in st.session_state:

        results = st.session_state["scan_results"]

        st.subheader("📊 Scan Summary")

        total_ports = len(results)

        high = len(
            results[
                results["Severity"] == "High"
            ]
        )

        medium = len(
            results[
                results["Severity"] == "Medium"
            ]
        )

        low = len(
            results[
                results["Severity"] == "Low"
            ]
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Open Ports",
                total_ports
            )

        with col2:
            st.metric(
                "High Risk",
                high
            )

        with col3:
            st.metric(
                "Medium Risk",
                medium
            )

        with col4:
            st.metric(
                "Low Risk",
                low
            )

        st.divider()

        st.subheader("🔍 Detected Services")

        st.dataframe(
            results,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        st.subheader("🛡️ Security Recommendations")

        for _, row in results.iterrows():

            if row["Severity"] == "High":

                st.error(
                    f"🔴 Port {row['Port']} — "
                    f"{row['Service']}: "
                    f"{row['Recommendation']}"
                )

            elif row["Severity"] == "Medium":

                st.warning(
                    f"🟠 Port {row['Port']} — "
                    f"{row['Service']}: "
                    f"{row['Recommendation']}"
                )

            else:

                st.info(
                    f"🟢 Port {row['Port']} — "
                    f"{row['Service']}: "
                    f"{row['Recommendation']}"
                )

        # Download scan results
        csv_data = results.to_csv(
            index=False
        )

        st.download_button(
            label="⬇️ Download Scan Results",
            data=csv_data,
            file_name="CyberShield_Local_Scan.csv",
            mime="text/csv"
        )

# ==========================================
# THREAT MONITORING
# ==========================================

elif page == "🚨 Threat Monitoring":

    st.title("🚨 Threat Monitoring")

    st.write(
        "This module analyzes security logs and identifies "
        "potentially suspicious activities."
    )

    st.header("Detected Threats")

    if alerts.empty:

        st.success(
            "No threats detected."
        )

    else:

        st.dataframe(
            alerts,
            use_container_width=True
        )

    st.header("Security Logs")

    st.dataframe(
        logs,
        use_container_width=True
    )


# ==========================================
# INCIDENT RESPONSE
# ==========================================

elif page == "⚠️ Incident Response":

    st.title("⚠️ Incident Response")

    st.subheader("Security Incident Management")

    st.write(
        "This module helps security analysts investigate "
        "detected security incidents and document appropriate "
        "response actions."
    )

    st.divider()

    # Check whether threats were detected
    if alerts.empty:

        st.success("No active security incidents detected.")

    else:

        st.subheader("🚨 Detected Incidents")

        # Create incident numbers
        for index, row in alerts.iterrows():

            incident_number = f"INC-{index + 1:03d}"

            with st.expander(
                f"{incident_number} — {row['Threat']} — {row['Severity']}"
            ):

                # Incident information
                col1, col2, col3 = st.columns(3)

                with col1:
                    st.write("**Incident Type**")
                    st.write(row["Threat"])

                with col2:
                    st.write("**Severity**")
                    st.write(row["Severity"])

                with col3:
                    st.write("**Source IP**")
                    st.write(row["Source IP"])

                st.divider()

                st.write("### 🔎 Investigation")

                st.write(
                    f"The monitoring system detected "
                    f"**{row['Attempts']} suspicious events** "
                    f"associated with source IP "
                    f"**{row['Source IP']}**."
                )

                if row["Threat"] == "Brute Force Attack":

                    st.write(
                        "The activity is consistent with a "
                        "potential brute-force authentication attack."
                    )

                    st.write("**Investigation Points:**")

                    st.write(
                        "• Review failed authentication attempts"
                    )

                    st.write(
                        "• Verify whether the account was successfully accessed"
                    )

                    st.write(
                        "• Check whether other accounts were targeted"
                    )

                    st.write(
                        "• Review the source IP and related activity"
                    )

                elif row["Threat"] == "Port Scanning":

                    st.write(
                        "The activity is consistent with "
                        "potential network reconnaissance."
                    )

                    st.write("**Investigation Points:**")

                    st.write(
                        "• Identify the source of the scan"
                    )

                    st.write(
                        "• Review exposed services"
                    )

                    st.write(
                        "• Determine whether further suspicious activity occurred"
                    )

                    st.write(
                        "• Restrict unnecessary network exposure"
                    )

                st.divider()

                st.write("### 🛡️ Recommended Response")

                st.warning(
                    row["Recommendation"]
                )

                st.write("**Response Actions:**")

                if row["Threat"] == "Brute Force Attack":

                    st.write(
                        "1. Investigate the source IP."
                    )

                    st.write(
                        "2. Review the affected account."
                    )

                    st.write(
                        "3. Reset credentials if necessary."
                    )

                    st.write(
                        "4. Enable multi-factor authentication."
                    )

                    st.write(
                        "5. Implement account lockout/rate limiting."
                    )

                elif row["Threat"] == "Port Scanning":

                    st.write(
                        "1. Investigate the source IP."
                    )

                    st.write(
                        "2. Review exposed network services."
                    )

                    st.write(
                        "3. Disable unnecessary services."
                    )

                    st.write(
                        "4. Apply appropriate firewall restrictions."
                    )

                st.divider()

                st.write("### 📋 Incident Status")

                status = st.selectbox(
                    "Update incident status",
                    [
                        "Open",
                        "Under Investigation",
                        "Contained",
                        "Resolved"
                    ],
                    key=incident_number
                )

                st.info(
                    f"{incident_number} status: **{status}**"
                )

    st.divider()

    st.subheader("Incident Response Lifecycle")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.info("1️⃣ Detection")

    with col2:
        st.info("2️⃣ Investigation")

    with col3:
        st.warning("3️⃣ Containment")

    with col4:
        st.success("4️⃣ Recovery")

# ==========================================
# SECURITY REPORTS
# ==========================================

elif page == "📄 Security Reports":

    st.title("📄 Security Reports")

    st.subheader("Cybersecurity Assessment Report")

    st.write(
        "Generate a security assessment report containing "
        "threat findings, vulnerability information, "
        "recommendations and incident analysis."
    )

    st.divider()

    # Load vulnerability data
    try:
        vulnerabilities = pd.read_csv(
            "data/scan_results.csv"
        )
    except FileNotFoundError:
        vulnerabilities = pd.DataFrame(
            columns=[
                "host",
                "port",
                "service",
                "severity",
                "description",
                "recommendation"
            ]
        )

    # Report summary
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Security Events",
            len(logs)
        )

    with col2:
        st.metric(
            "Threats Detected",
            len(alerts)
        )

    with col3:
        st.metric(
            "Vulnerabilities",
            len(vulnerabilities)
        )

    st.divider()

    # Generate report
    if st.button("📄 Generate Security Report"):

        report = generate_report(
            logs,
            alerts,
            vulnerabilities
        )

        st.success(
            "Security assessment report generated successfully."
        )

        st.text_area(
            "Report Preview",
            report,
            height=500
        )

        st.download_button(
            label="⬇️ Download Security Report",
            data=report,
            file_name="CyberShield_Security_Assessment_Report.txt",
            mime="text/plain"
        )