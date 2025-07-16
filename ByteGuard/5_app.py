# dashboard_live_integrated.py

import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import nmap
import random

# -------------------------------
# Simulated vulnerability database
# -------------------------------

vuln_db = [
    {"cve_id": "CVE-2021-41773", "name": "Apache Path Traversal", "cvss": 7.5},
    {"cve_id": "CVE-2022-22965", "name": "Spring4Shell RCE", "cvss": 9.8},
    {"cve_id": "CVE-2023-23397", "name": "Outlook Elevation of Privilege", "cvss": 9.8},
    {"cve_id": "CVE-2023-20025", "name": "Cisco IOS XE Privilege Escalation", "cvss": 8.6},
    {"cve_id": "CVE-2021-26855", "name": "Exchange SSRF (ProxyLogon)", "cvss": 9.1},
    {"cve_id": "CVE-2022-1388", "name": "F5 BIG-IP iControl RCE", "cvss": 9.8}
]

# -------------------------------
# Page Configuration
# -------------------------------

st.set_page_config(
    page_title="Wi-Fi Security AI Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------
# Custom Header
# -------------------------------

st.markdown("""
    <h1 style='text-align: center; color: #FF4B4B; font-size: 48px;'>
        AI-Powered Wi-Fi Security Scanner
    </h1>
    <p style='text-align: center; color: #666666; font-size: 18px;'>
        Evaluating Wi-Fi Security Risks in Kathmandu Hotels Using AI-Powered Vulnerability Scanning
    </p>
""", unsafe_allow_html=True)

# -------------------------------
# Sidebar Branding
# -------------------------------

with st.sidebar:
    st.markdown("### Project Details")
    st.write("""
    **Project Title:** Evaluate wifi security risks in kathmandu hotels using artificial intelligence powered vulnerability scanning
    
    **Researcher:** Nisha Pandey
    
    **Supervised by:** Manoj Shrestha
    
    This tool evaluates Wi-Fi security risks in Kathmandu hotels using AI-driven scanning and analysis.
    """)

# -------------------------------
# User Option Selection
# -------------------------------

choice = st.radio(
    "Choose how to provide scan data:",
    ("Upload CSV file", "Run live Nmap + simulated OpenVAS scan")
)

df = None

# -------------------------------
# Option 1: Upload CSV
# -------------------------------

if choice == "Upload CSV file":
    uploaded_file = st.file_uploader("Upload your network scan CSV file", type=["csv"])
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.success("✅ File loaded successfully!")

# -------------------------------
# Option 2: Run live scan
# -------------------------------

elif choice == "Run live Nmap + simulated OpenVAS scan":
    target = st.text_input("Enter target IP or network (e.g. 192.168.1.0/24):")
    scan_button = st.button("Run Scan")

    if scan_button and target:
        st.info("🔎 Running Nmap scan... please wait.")
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=target, arguments='-sS -T4')
        except Exception as e:
            st.error(f"Nmap error: {e}")
            nm = None

        if nm:
            records = []

            for host in nm.all_hosts():
                ports = nm[host].all_protocols()
                open_port_count = 0
                services = {
                    "service_http_open": 0,
                    "service_ssh_open": 0,
                    "service_rdp_open": 0
                }

                for proto in ports:
                    for port in nm[host][proto]:
                        open_port_count += 1
                        service_name = nm[host][proto][port]['name']
                        if service_name == 'http':
                            services["service_http_open"] = 1
                        elif service_name == 'ssh':
                            services["service_ssh_open"] = 1
                        elif service_name in ['ms-wbt-server', 'rdp']:
                            services["service_rdp_open"] = 1

                # Simulate OpenVAS vulnerabilities
                has_vulns = random.choice([True, False])
                assigned_vulns = []
                vuln_score = 0.0

                if has_vulns:
                    num_vulns = random.randint(1, 3)
                    assigned_vulns = random.sample(vuln_db, num_vulns)
                    vuln_score = max(v["cvss"] for v in assigned_vulns)
                else:
                    vuln_score = 0.0

                critical_vulns = sum(1 for v in assigned_vulns if v["cvss"] >= 7.0)

                vuln_details = "; ".join(
                    f"{v['cve_id']} ({v['name']}) - CVSS {v['cvss']}"
                    for v in assigned_vulns
                ) if assigned_vulns else ""

                record = {
                    "host": host,
                    "open_ports": open_port_count,
                    "vuln_score": vuln_score,
                    "critical_vulns": critical_vulns,
                    "vuln_details": vuln_details,
                    "service_http_open": services["service_http_open"],
                    "service_ssh_open": services["service_ssh_open"],
                    "service_rdp_open": services["service_rdp_open"],
                    "snort_alert": 0,
                    "device_type": "endpoint",
                    "geo_location_risk": 0,
                    "avg_packet_size": 300.0,
                    "scan_hour": 14
                }

                records.append(record)

            df = pd.DataFrame(records)

            if not df.empty:
                st.success(f"✅ Scan complete! {len(df)} hosts found.")
                st.dataframe(df)
            else:
                st.warning("⚠️ No hosts found during scan.")

# -------------------------------
# Run ML Predictions
# -------------------------------

if df is not None and not df.empty:
    required_cols = [
        "open_ports",
        "vuln_score",
        "critical_vulns",
        "service_http_open",
        "service_ssh_open",
        "service_rdp_open",
        "snort_alert",
        "geo_location_risk",
        "avg_packet_size",
        "scan_hour",
        "device_type"
    ]

    if all(col in df.columns for col in required_cols):
        # Encode device_type
        le = LabelEncoder()
        df["device_type_encoded"] = le.fit_transform(df["device_type"])

        # Prepare features
        X = df[
            [
                "open_ports",
                "vuln_score",
                "critical_vulns",
                "service_http_open",
                "service_ssh_open",
                "service_rdp_open",
                "snort_alert",
                "geo_location_risk",
                "avg_packet_size",
                "scan_hour",
                "device_type_encoded"
            ]
        ]

        # Load trained model
        clf = joblib.load("model_rf_expanded.joblib")

        # Predict risks
        df["predicted_label"] = clf.predict(X)

        st.markdown("""
            <h3 style='color: #FF4B4B;'>🚨 AI Risk Analysis Results</h3>
        """, unsafe_allow_html=True)

        total_hosts = len(df)
        risky_hosts = df[df["predicted_label"] == 1]
        num_risky = len(risky_hosts)

        col1, col2 = st.columns(2)
        col1.metric("🖥️ Total Hosts Scanned", total_hosts)
        col2.metric("⚠️ Risky Hosts Detected", num_risky, f"{(num_risky/total_hosts)*100:.2f}%")

        # Pie chart
        colors = ['#4CAF50', '#FF4B4B']
        labels = ['Safe', 'Risky']
        sizes = [total_hosts - num_risky, num_risky]

        fig1, ax1 = plt.subplots(figsize=(3, 3))
        ax1.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            startangle=90,
            colors=colors
        )
        ax1.axis('equal')
        st.pyplot(fig1)

        # Display risky hosts
        if num_risky > 0:
            st.markdown("""
                <h4 style='color: #FF4B4B;'>⚠️ Risky Hosts Detected</h4>
            """, unsafe_allow_html=True)
            st.dataframe(risky_hosts)
        else:
            st.success("✅ No risky hosts detected. The network appears safe.")

        # Show vulnerabilities
        if "vuln_details" in df.columns:
            st.markdown("""
                <h4 style='color: #FF4B4B;'>🔎 Simulated Vulnerabilities Found</h4>
            """, unsafe_allow_html=True)
            vuln_table = df[df["vuln_details"] != ""][["host", "vuln_details"]]
            if not vuln_table.empty:
                st.dataframe(vuln_table)
            else:
                st.write("No vulnerabilities detected in scan.")

        # Download results
        st.download_button(
            label="⬇️ Download Full Predictions CSV",
            data=df.to_csv(index=False).encode('utf-8'),
            file_name='prediction_results.csv',
            mime='text/csv'
        )

    else:
        st.error("🚫 Missing required columns in the scan data. Please check your upload or scanning parameters.")
