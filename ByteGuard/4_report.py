# report.py

import pandas as pd

# Load predictions
df = pd.read_csv("network_predictions.csv")

# Total hosts
total_hosts = len(df)

# Count risky hosts
risky_hosts = df[df["predicted_label"] == 1]
num_risky = len(risky_hosts)
percent_risky = (num_risky / total_hosts) * 100

# Print summary
print("=== AI-Powered Wi-Fi Security Analysis ===")
print(f"Total hosts analyzed: {total_hosts}")
print(f"Risky hosts detected: {num_risky} ({percent_risky:.2f}%)")

# Recommendations
print("\nRecommended Actions:")

if num_risky > 0:
    print("- Investigate hosts with high vulnerability scores.")
    print("- Review critical services open on risky hosts (HTTP, SSH, RDP).")
    print("- Check unusual geo-locations and Snort alerts.")
    print("- Reduce open ports where not required.")
    print("- Schedule follow-up vulnerability scans.")
else:
    print("- All hosts appear low risk. Maintain regular security scans.")

# Save risky hosts to CSV for further investigation
risky_hosts.to_csv("risky_hosts.csv", index=False)
print("\nSaved list of risky hosts to risky_hosts.csv")

# Save text report
with open("analysis_report.txt", "w") as f:
    f.write("=== AI-Powered Wi-Fi Security Analysis ===\n")
    f.write(f"Total hosts analyzed: {total_hosts}\n")
    f.write(f"Risky hosts detected: {num_risky} ({percent_risky:.2f}%)\n\n")

    f.write("Recommended Actions:\n")

    if num_risky > 0:
        f.write("- Investigate hosts with high vulnerability scores.\n")
        f.write("- Review critical services open on risky hosts (HTTP, SSH, RDP).\n")
        f.write("- Check unusual geo-locations and Snort alerts.\n")
        f.write("- Reduce open ports where not required.\n")
        f.write("- Schedule follow-up vulnerability scans.\n")
    else:
        f.write("- All hosts appear low risk. Maintain regular security scans.\n")

print("Analysis report saved as analysis_report.txt")
