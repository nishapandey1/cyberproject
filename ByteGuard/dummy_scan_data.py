# generate_dummy_scan_data.py

import pandas as pd
import numpy as np
import random

np.random.seed(42)

# Define number of devices (simulate hotel scan)
n_devices = 125

# Simulated CVE database
vuln_db = [
    {"cve_id": "CVE-2021-41773", "name": "Apache Path Traversal", "cvss": 7.5},
    {"cve_id": "CVE-2022-22965", "name": "Spring4Shell RCE", "cvss": 9.8},
    {"cve_id": "CVE-2023-23397", "name": "Outlook Privilege Escalation", "cvss": 9.8},
    {"cve_id": "CVE-2023-20025", "name": "Cisco IOS XE Priv Escalation", "cvss": 8.6},
    {"cve_id": "CVE-2021-26855", "name": "Exchange SSRF (ProxyLogon)", "cvss": 9.1},
    {"cve_id": "CVE-2022-1388", "name": "F5 BIG-IP iControl RCE", "cvss": 9.8}
]

rows = []

for i in range(1, n_devices + 1):
    host = f"192.168.10.{i}"
    open_ports = np.random.randint(1, 40)
    
    # Simulate whether this host has vulnerabilities
    has_vulns = np.random.choice([True, False], p=[0.5, 0.5])
    
    if has_vulns:
        num_vulns = np.random.randint(1, 3)
        assigned_vulns = random.sample(vuln_db, num_vulns)
        vuln_score = max(v["cvss"] for v in assigned_vulns)
        vuln_details = "; ".join(
            f"{v['cve_id']} ({v['name']}) - CVSS {v['cvss']}"
            for v in assigned_vulns
        )
        critical_vulns = sum(1 for v in assigned_vulns if v["cvss"] >= 7.0)
    else:
        vuln_score = 0.0
        vuln_details = ""
        critical_vulns = 0

    row = {
        "host": host,
        "open_ports": open_ports,
        "vuln_score": vuln_score,
        "critical_vulns": critical_vulns,
        "vuln_details": vuln_details,
        "service_http_open": np.random.choice([0, 1], p=[0.6, 0.4]),
        "service_ssh_open": np.random.choice([0, 1], p=[0.7, 0.3]),
        "service_rdp_open": np.random.choice([0, 1], p=[0.9, 0.1]),
        "snort_alert": np.random.choice([0, 1], p=[0.8, 0.2]),
        "device_type": np.random.choice(
            ["server", "router", "endpoint", "IoT"],
            p=[0.3, 0.2, 0.4, 0.1]
        ),
        "geo_location_risk": np.random.choice([0, 1], p=[0.9, 0.1]),
        "avg_packet_size": np.round(
            np.random.normal(loc=300, scale=50), 2
        ),
        "scan_hour": np.random.randint(0, 24)
    }
    
    rows.append(row)

# Create DataFrame
df = pd.DataFrame(rows)

# Save
df.to_csv("hotel_dummy_scan.csv", index=False)
print("Dummy hotel scan data saved to hotel_dummy_scan.csv")
