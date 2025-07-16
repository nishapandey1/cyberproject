# predict.py

import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

# Load expanded dataset
df = pd.read_csv("network_dataset_expanded.csv")

# Encode device_type same as during training
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

# Predict
df["predicted_label"] = clf.predict(X)

# Save predictions
df.to_csv("network_predictions.csv", index=False)
print("Predictions saved in network_predictions.csv")

# Display a few risky hosts
risky_hosts = df[df["predicted_label"] == 1]
print(f"Total risky hosts detected: {len(risky_hosts)}")
print(risky_hosts.head())
