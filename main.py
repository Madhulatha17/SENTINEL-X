import pandas as pd
from pathlib import Path

# --------------------------------------------------
# 1. LOAD SECURITY LOGS
# --------------------------------------------------

PROJECT_FOLDER = Path(__file__).resolve().parent.parent
CSV_FILE = PROJECT_FOLDER / "data" / "security_logs.csv"

data = pd.read_csv(CSV_FILE)

data["Timestamp"] = pd.to_datetime(data["Timestamp"])
data = data.sort_values("Timestamp").reset_index(drop=True)


# --------------------------------------------------
# 2. EVENT RISK SCORES
# --------------------------------------------------

EVENT_SCORES = {
    "Login": 5,
    "File_Access": 15,
    "Privilege_Change": 25,
    "Data_Transfer": 30,
    "Logout": 0
}


# --------------------------------------------------
# 3. CALCULATE USER RISK
# --------------------------------------------------

user_scores = {}

for user in data["User_ID"].unique():

    user_events = data[data["User_ID"] == user]

    score = 0

    for _, event in user_events.iterrows():

        event_type = event["Event_Type"]

        score += EVENT_SCORES.get(event_type, 0)

        # Extra risk for failed login
        if event_type == "Login" and event["Status"] == "Failed":
            score += 10

    # Extra risk if multiple failed logins occurred
    failed_logins = user_events[
        (user_events["Event_Type"] == "Login") &
        (user_events["Status"] == "Failed")
    ]

    if len(failed_logins) >= 2:
        score += 15

    user_scores[user] = min(score, 100)


# --------------------------------------------------
# 4. FIND MOST SUSPICIOUS USER
# --------------------------------------------------

suspicious_user = max(user_scores, key=user_scores.get)

risk_score = user_scores[suspicious_user]

events = data[data["User_ID"] == suspicious_user].copy()

event_types = events["Event_Type"].tolist()

device = events.iloc[0]["Device_ID"]

ip = events.iloc[0]["IP_Address"]


# --------------------------------------------------
# 5. DETERMINE ATTACK STAGE
# --------------------------------------------------

if "Data_Transfer" in event_types:

    current_stage = "Data Exfiltration"

    predicted_stage = "Further Exfiltration / Persistence"

elif "Privilege_Change" in event_types:

    current_stage = "Privilege Escalation"

    predicted_stage = "Data Exfiltration"

elif "File_Access" in event_types:

    current_stage = "Data Collection"

    predicted_stage = "Privilege Escalation"

else:

    current_stage = "Initial Access"

    predicted_stage = "Data Collection"


# --------------------------------------------------
# 6. COLLECT EVIDENCE
# --------------------------------------------------

evidence = []

failed_count = len(
    events[
        (events["Event_Type"] == "Login") &
        (events["Status"] == "Failed")
    ]
)

if failed_count >= 2:
    evidence.append(
        f"{failed_count} failed login attempts detected"
    )

if "File_Access" in event_types:
    evidence.append(
        "Sensitive file access detected"
    )

if "Privilege_Change" in event_types:
    evidence.append(
        "Privilege change detected"
    )

if "Data_Transfer" in event_types:
    evidence.append(
        "Data transfer detected"
    )


# --------------------------------------------------
# 7. COUNTERFACTUAL DEFENSE
# --------------------------------------------------

if "Data_Transfer" in event_types:

    intervention = (
        f"Isolate device {device} before additional "
        "data transfer occurs."
    )

elif "Privilege_Change" in event_types:

    intervention = (
        f"Isolate device {device} and investigate "
        "the privilege change."
    )

else:

    intervention = (
        "Investigate the authentication activity."
    )


# --------------------------------------------------
# 8. THREAT LEVEL
# --------------------------------------------------

if risk_score >= 80:

    threat_level = "CRITICAL"

elif risk_score >= 60:

    threat_level = "HIGH"

elif risk_score >= 30:

    threat_level = "MEDIUM"

else:

    threat_level = "LOW"


# --------------------------------------------------
# 9. DISPLAY SENTINEL-X RESULT
# --------------------------------------------------

print("\n")

print("=" * 60)
print("                 SENTINEL-X")
print("=" * 60)

print("\n🚨 THREAT ANALYSIS")

print("\nAffected User:")
print(suspicious_user)

print("\nDevice:")
print(device)

print("\nIP Address:")
print(ip)

print("\nRisk Score:")
print(risk_score, "/ 100")

print("\nThreat Level:")
print(threat_level)


# --------------------------------------------------
# ATTACK DNA
# --------------------------------------------------

print("\n" + "-" * 60)
print("ATTACK DNA")
print("-" * 60)

for i, event in enumerate(event_types):

    print(event)

    if i < len(event_types) - 1:
        print("   ↓")


# --------------------------------------------------
# ATTACK PROGRESSION
# --------------------------------------------------

print("\n" + "-" * 60)
print("ATTACK PROGRESSION")
print("-" * 60)

print("Current Stage:")
print(current_stage)

print("\nPredicted Next Stage:")
print(predicted_stage)


# --------------------------------------------------
# EVIDENCE
# --------------------------------------------------

print("\n" + "-" * 60)
print("EVIDENCE")
print("-" * 60)

for item in evidence:

    print("✓", item)


# --------------------------------------------------
# COUNTERFACTUAL DEFENSE
# --------------------------------------------------

print("\n" + "-" * 60)
print("COUNTERFACTUAL DEFENSE")
print("-" * 60)

print("Recommended Intervention:")

print(intervention)


# --------------------------------------------------
# COMPLETE
# --------------------------------------------------

print("\n" + "=" * 60)
print("SENTINEL-X ANALYSIS COMPLETE")
print("=" * 60)