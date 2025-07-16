# generate_dataset.py

import pandas as pd
import numpy as np

np.random.seed(42)

n_rows = 12000  # more than 10,000

# Hosts
hosts = [f"host_{i}" for i in range(1, n_rows + 1)]

# Random open ports count
open_ports = np.random.randint(1, 100, size=n_rows)

# Vulnerability scores (continuous)
vuln_scores = np.round(np.random.uniform(0, 10, size=n_rows), 2)

# Critical vulnerabilities (counts)
critical_vulns = np.random.poisson(lam=1.5, size=n_rows)  # avg 1.5 critical vulns

# Services
service_http_open = np.random.choice([0, 1], size=n_rows, p=[0.7, 0.3])
service_ssh_open = np.random.choice([0, 1], size=n_rows, p=[0.8, 0.2])
service_rdp_open = np.random.choice([0, 1], size=n_rows, p=[0.9, 0.1])

# Snort alerts
snort_alerts = np.random.choice([0, 1], size=n_rows, p=[0.8, 0.2])

# Device types
device_types = np.random.choice(
    ['server', 'router', 'endpoint', 'IoT'],
    size=n_rows,
    p=[0.3, 0.2, 0.4, 0.1]
)

# Geo-location risk flag (e.g. unusual login location)
geo_location_risk = np.random.choice([0, 1], size=n_rows, p=[0.9, 0.1])

# Average packet size (bytes)
avg_packet_size = np.round(np.random.normal(loc=300, scale=50, size=n_rows), 2)
avg_packet_size = np.clip(avg_packet_size, 100, 1500)  # limit realistic range

# Time of scan
scan_hour = np.random.randint(0, 24, size=n_rows)

# Generate labels
# Host is risky if:
# - vuln_score > 7.0
# - OR critical_vulns > 2
# - OR snort_alert triggered
# - OR geo_location_risk flagged
labels = (
    (vuln_scores > 7.0)
    | (critical_vulns > 2)
    | (snort_alerts == 1)
    | (geo_location_risk == 1)
).astype(int)

# Build DataFrame
df = pd.DataFrame({
    "host": hosts,
    "open_ports": open_ports,
    "vuln_score": vuln_scores,
    "critical_vulns": critical_vulns,
    "service_http_open": service_http_open,
    "service_ssh_open": service_ssh_open,
    "service_rdp_open": service_rdp_open,
    "snort_alert": snort_alerts,
    "device_type": device_types,
    "geo_location_risk": geo_location_risk,
    "avg_packet_size": avg_packet_size,
    "scan_hour": scan_hour,
    "label": labels
})

# Save
df.to_csv("network_dataset_expanded.csv", index=False)
print("Synthetic expanded dataset saved as network_dataset_expanded.csv")
