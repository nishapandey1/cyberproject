# train_model.py

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# Load expanded data
df = pd.read_csv("network_dataset_expanded.csv")

# Encode device_type
le = LabelEncoder()
df["device_type_encoded"] = le.fit_transform(df["device_type"])

# Features
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
y = df["label"]

# Split into train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train Random Forest
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Predict on test set
y_pred = clf.predict(X_test)

# Print report
print(classification_report(y_test, y_pred))

# Combine test set with predictions
test_results = X_test.copy()
test_results["actual_label"] = y_test.values
test_results["predicted_label"] = y_pred

# Save to CSV
test_results.to_csv("test_predictions.csv", index=False)
print("Test predictions saved as test_predictions.csv")

# Save model
joblib.dump(clf, "model_rf_expanded.joblib")
print("Model saved as model_rf_expanded.joblib")
