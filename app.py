import streamlit as st
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OrdinalEncoder

# ============================================================
# SENTINEL-X
# AI-Powered Attack DNA & Early Intervention Engine
# ============================================================

st.set_page_config(
    page_title="SENTINEL-X",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

CSV_CANDIDATES = [
    BASE_DIR / "data" / "security_logs.csv",
    BASE_DIR / "security_logs.csv",
    BASE_DIR.parent / "data" / "security_logs.csv",
]

CSV_FILE = next((p for p in CSV_CANDIDATES if p.exists()), None)

# ============================================================
# HEADER
# ============================================================

st.title("🛡️ SENTINEL-X")
st.subheader("AI-Powered Attack DNA & Early Intervention Engine")

st.markdown(
    """
**SENTINEL-X** converts scattered security events into an interpretable
attack story using behavioral anomaly detection, entity correlation,
attack-chain reconstruction and evidence-based reasoning.
"""
)

# ============================================================
# LOAD DATA
# ============================================================

if CSV_FILE is None:
    st.error("security_logs.csv was not found.")
    st.info("Expected location: data/security_logs.csv")
    st.stop()

try:
    df = pd.read_csv(CSV_FILE)
except Exception as e:
    st.error(f"Unable to read CSV: {e}")
    st.stop()

# ============================================================
# VALIDATE DATA
# ============================================================

required_columns = [
    "Timestamp",
    "User_ID",
    "Event_Type",
    "Status",
    "Device_ID",
    "IP_Address",
    "Application",
    "Resource",
]

missing = [c for c in required_columns if c not in df.columns]

if missing:
    st.error(f"Missing required columns: {missing}")
    st.stop()

df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
df = df.dropna(subset=["Timestamp"]).sort_values("Timestamp").reset_index(drop=True)

for col in required_columns:
    if col != "Timestamp":
        df[col] = df[col].fillna("Unknown").astype(str)

# ============================================================
# EVENT RISK MODEL
# ============================================================

event_scores = {
    "Login": 5,
    "File_Access": 15,
    "Privilege_Change": 25,
    "Data_Transfer": 30,
    "Logout": 0,
}

df["Rule_Risk"] = df["Event_Type"].map(event_scores).fillna(5)

# Failed activity increases security risk
df.loc[
    df["Status"].str.lower().eq("failed"),
    "Rule_Risk"
] += 10

# ============================================================
# ML FEATURE ENGINEERING
# ============================================================

df["Hour"] = df["Timestamp"].dt.hour
df["DayOfWeek"] = df["Timestamp"].dt.dayofweek

df["User_Frequency"] = df.groupby("User_ID")["User_ID"].transform("count")
df["Device_Frequency"] = df.groupby("Device_ID")["Device_ID"].transform("count")
df["IP_Frequency"] = df.groupby("IP_Address")["IP_Address"].transform("count")

categorical_columns = [
    "Event_Type",
    "Status",
    "Application",
    "Resource",
]

encoder = OrdinalEncoder(
    handle_unknown="use_encoded_value",
    unknown_value=-1
)

encoded = encoder.fit_transform(df[categorical_columns])

encoded_df = pd.DataFrame(
    encoded,
    columns=[f"{c}_Encoded" for c in categorical_columns],
    index=df.index,
)

features = pd.concat(
    [
        encoded_df,
        df[
            [
                "Hour",
                "DayOfWeek",
                "User_Frequency",
                "Device_Frequency",
                "IP_Frequency",
            ]
        ],
    ],
    axis=1,
)

# ============================================================
# ISOLATION FOREST
# ============================================================

if len(df) >= 5:

    contamination = min(
        max(0.15, 2 / len(df)),
        0.30
    )

    model = IsolationForest(
        n_estimators=150,
        contamination=contamination,
        random_state=42
    )

    model.fit(features)

    raw_scores = -model.decision_function(features)

    min_score = raw_scores.min()
    max_score = raw_scores.max()

    if max_score - min_score > 0:
        anomaly_scores = (
            (raw_scores - min_score)
            / (max_score - min_score)
        ) * 100
    else:
        anomaly_scores = np.full(len(df), 25.0)

    df["ML_Anomaly"] = np.clip(
        anomaly_scores,
        0,
        100
    )

    df["ML_Label"] = np.where(
        df["ML_Anomaly"] >= 70,
        "Anomalous",
        "Normal"
    )

else:
    df["ML_Anomaly"] = 25.0
    df["ML_Label"] = "Insufficient Data"

# ============================================================
# HYBRID RISK
# ============================================================

df["Hybrid_Risk"] = (
    0.65 * df["Rule_Risk"]
    + 0.35 * df["ML_Anomaly"]
)

df["Hybrid_Risk"] = np.clip(
    df["Hybrid_Risk"],
    0,
    100
)

# ============================================================
# USER CORRELATION
# ============================================================

user_summary = (
    df.groupby("User_ID")
    .agg(
        Total_Risk=("Hybrid_Risk", "sum"),
        Events=("Event_Type", "count"),
        Max_Risk=("Hybrid_Risk", "max"),
        Anomaly_Average=("ML_Anomaly", "mean"),
    )
    .sort_values("Total_Risk", ascending=False)
)

affected_user = user_summary.index[0]

user_df = df[df["User_ID"] == affected_user].copy()

# Normalize total user risk
user_score_raw = user_summary.loc[
    affected_user,
    "Total_Risk"
]

risk_score = int(
    min(
        100,
        max(
            0,
            user_score_raw / max(len(user_df), 1)
        )
    )
)

# ============================================================
# ATTACK DNA
# ============================================================

attack_sequence = user_df["Event_Type"].tolist()

stage_mapping = {
    "Login": "Initial Access",
    "File_Access": "Data Collection",
    "Privilege_Change": "Privilege Escalation",
    "Data_Transfer": "Data Exfiltration",
    "Logout": "Session Termination",
}

stage_sequence = [
    stage_mapping.get(event, "Unknown Activity")
    for event in attack_sequence
]

# Remove consecutive duplicates
compressed_stages = []

for stage in stage_sequence:
    if not compressed_stages or compressed_stages[-1] != stage:
        compressed_stages.append(stage)

# ============================================================
# CURRENT STAGE + NEXT STAGE
# ============================================================

stage_order = [
    "Initial Access",
    "Data Collection",
    "Privilege Escalation",
    "Data Exfiltration",
    "Session Termination",
]

current_stage = (
    compressed_stages[-1]
    if compressed_stages
    else "Unknown"
)

next_stage_map = {
    "Initial Access": "Data Collection",
    "Data Collection": "Privilege Escalation",
    "Privilege Escalation": "Data Exfiltration",
    "Data Exfiltration": "Further Exfiltration / Persistence",
    "Session Termination": "No Immediate Next Stage",
}

predicted_stage = next_stage_map.get(
    current_stage,
    "Unknown"
)

# ============================================================
# EVIDENCE ENGINE
# ============================================================

evidence = []

failed_logins = user_df[
    (user_df["Event_Type"] == "Login")
    & (user_df["Status"].str.lower() == "failed")
]

file_access = user_df[
    user_df["Event_Type"] == "File_Access"
]

privilege_changes = user_df[
    user_df["Event_Type"] == "Privilege_Change"
]

transfers = user_df[
    user_df["Event_Type"] == "Data_Transfer"
]

if len(failed_logins) > 0:
    evidence.append(
        f"{len(failed_logins)} failed login attempt(s) detected."
    )

if len(file_access) > 0:
    evidence.append(
        f"{len(file_access)} file/resource access event(s) detected."
    )

if len(privilege_changes) > 0:
    evidence.append(
        f"{len(privilege_changes)} privilege change event(s) detected."
    )

if len(transfers) > 0:
    evidence.append(
        f"{len(transfers)} data transfer event(s) detected."
    )

if user_df["ML_Anomaly"].max() >= 70:
    evidence.append(
        "ML anomaly detector identified unusual behavioral activity."
    )

if len(compressed_stages) >= 3:
    evidence.append(
        "Multiple security stages are connected in chronological order."
    )

if not evidence:
    evidence.append(
        "No strong suspicious evidence was identified."
    )

# ============================================================
# CONFIDENCE
# ============================================================

sequence_strength = min(
    len(compressed_stages) * 18,
    100
)

ml_strength = float(
    user_df["ML_Anomaly"].mean()
)

evidence_strength = min(
    len(evidence) * 15,
    100
)

entity_strength = 0

if user_df["Device_ID"].nunique() >= 1:
    entity_strength += 25

if user_df["IP_Address"].nunique() >= 1:
    entity_strength += 25

if user_df["Application"].nunique() >= 1:
    entity_strength += 25

if user_df["Resource"].nunique() >= 1:
    entity_strength += 25

confidence = int(
    np.clip(
        (
            sequence_strength
            + ml_strength
            + evidence_strength
            + entity_strength
        ) / 4,
        0,
        100,
    )
)

# ============================================================
# THREAT LEVEL
# ============================================================

if risk_score >= 80:
    threat_level = "CRITICAL"
elif risk_score >= 60:
    threat_level = "HIGH"
elif risk_score >= 35:
    threat_level = "MEDIUM"
else:
    threat_level = "LOW"

# ============================================================
# TOP DASHBOARD
# ============================================================

st.divider()

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric(
    "Threat Level",
    threat_level
)

c2.metric(
    "Hybrid Risk",
    f"{risk_score}/100"
)

c3.metric(
    "ML Anomaly",
    f"{user_df['ML_Anomaly'].mean():.0f}/100"
)

c4.metric(
    "Confidence",
    f"{confidence}%"
)

c5.metric(
    "Affected User",
    str(affected_user)
)

# ============================================================
# PIPELINE
# ============================================================

st.divider()

st.header("🔬 Detection Pipeline")

pipeline = [
    "Raw Logs",
    "Event Processing",
    "ML Anomaly",
    "Entity Correlation",
    "Attack Reconstruction",
    "Attack DNA",
    "Prediction",
    "Intervention",
]

cols = st.columns(len(pipeline))

for col, step in zip(cols, pipeline):
    col.markdown(
        f"**{step}**"
    )

# ============================================================
# ML EVIDENCE
# ============================================================

st.divider()

st.header("🤖 ML Behavioral Analysis")

ml_display = user_df[
    [
        "Timestamp",
        "Event_Type",
        "Status",
        "ML_Anomaly",
        "ML_Label",
        "Rule_Risk",
        "Hybrid_Risk",
    ]
].copy()

ml_display["ML_Anomaly"] = (
    ml_display["ML_Anomaly"].round(1)
)

ml_display["Rule_Risk"] = (
    ml_display["Rule_Risk"].round(1)
)

ml_display["Hybrid_Risk"] = (
    ml_display["Hybrid_Risk"].round(1)
)

st.dataframe(
    ml_display,
    use_container_width=True,
    hide_index=True
)

st.caption(
    "ML anomaly score is a behavioral anomaly indicator, "
    "not a calibrated probability of attack."
)

# ============================================================
# ENTITY CORRELATION
# ============================================================

st.divider()

st.header("🔗 Entity Correlation")

e1, e2, e3, e4, e5 = st.columns(5)

e1.metric(
    "User",
    str(affected_user)
)

e2.metric(
    "Device",
    str(user_df["Device_ID"].mode().iloc[0])
)

e3.metric(
    "IP Address",
    str(user_df["IP_Address"].mode().iloc[0])
)

e4.metric(
    "Application",
    str(user_df["Application"].mode().iloc[0])
)

e5.metric(
    "Resource",
    str(user_df["Resource"].mode().iloc[0])
)

st.code(
    f"""
User
  ↓
{user_df["Device_ID"].mode().iloc[0]}
  ↓
{user_df["IP_Address"].mode().iloc[0]}
  ↓
{user_df["Application"].mode().iloc[0]}
  ↓
{user_df["Resource"].mode().iloc[0]}
"""
)

# ============================================================
# ATTACK DNA
# ============================================================

st.divider()

st.header("🧬 Attack DNA")

st.subheader("Observed Event Sequence")

st.write(
    " → ".join(attack_sequence)
)

st.subheader("Semantic Attack Sequence")

st.write(
    " → ".join(compressed_stages)
)

# ============================================================
# ATTACK PROGRESSION
# ============================================================

st.divider()

st.header("📈 Attack Progression")

p1, p2 = st.columns(2)

with p1:
    st.metric(
        "Current Stage",
        current_stage
    )

with p2:
    st.metric(
        "Predicted Next Stage",
        predicted_stage
    )

st.progress(
    min(
        len(compressed_stages) / max(len(stage_order), 1),
        1.0
    )
)

# ============================================================
# EVIDENCE
# ============================================================

st.divider()

st.header("🔎 Why is this suspicious?")

for item in evidence:
    st.success("✓ " + item)

# ============================================================
# INTERVENTION
# ============================================================

st.divider()

st.header("🚨 Early Intervention")

if current_stage == "Initial Access":
    recommendation = "Strengthen authentication / temporarily lock the account."
elif current_stage == "Data Collection":
    recommendation = "Restrict sensitive resource access and investigate the endpoint."
elif current_stage == "Privilege Escalation":
    recommendation = "Disable or isolate the affected account/device."
elif current_stage == "Data Exfiltration":
    recommendation = "Block suspicious outbound transfer and isolate the endpoint."
else:
    recommendation = "Continue monitoring and investigate correlated activity."

st.warning(
    f"Recommended intervention: **{recommendation}**"
)

st.caption(
    "This is a recommendation/simulation only. "
    "SENTINEL-X does not execute real security controls."
)

# ============================================================
# WHAT-IF SIMULATION
# ============================================================

st.divider()

st.header("🧪 Counterfactual Defense Simulation")

action = st.selectbox(
    "Select an intervention:",
    [
        "Isolate Device",
        "Block IP",
        "Disable User",
        "Block Data Transfer",
    ]
)

if st.button("Run What-If Simulation"):

    st.info(
        f"Simulating intervention: **{action}**"
    )

    st.write(
        "Without intervention:"
    )

    st.code(
        "Current Stage → "
        + current_stage
        + " → "
        + predicted_stage
    )

    st.write(
        "With intervention:"
    )

    st.success(
        f"{current_stage} → [{action}] → Attack progression interrupted"
    )

# ============================================================
# TIMELINE
# ============================================================

st.divider()

st.header("⏱️ Attack Timeline")

timeline = user_df[
    [
        "Timestamp",
        "Event_Type",
        "Status",
        "Device_ID",
        "IP_Address",
        "ML_Anomaly",
        "Hybrid_Risk",
    ]
].copy()

timeline["ML_Anomaly"] = (
    timeline["ML_Anomaly"].round(1)
)

timeline["Hybrid_Risk"] = (
    timeline["Hybrid_Risk"].round(1)
)

st.dataframe(
    timeline,
    use_container_width=True,
    hide_index=True
)

# ============================================================
# NORMAL VS SUSPICIOUS
# ============================================================

st.divider()

st.header("⚖️ Behavioral Comparison")

normal_events = [
    "Login",
    "File_Access",
    "Logout",
]

suspicious_events = attack_sequence

comparison = pd.DataFrame(
    {
        "Normal Pattern": pd.Series(normal_events),
        "Observed Pattern": pd.Series(suspicious_events),
    }
)

st.dataframe(
    comparison,
    use_container_width=True,
    hide_index=True
)

# ============================================================
# FINAL ANALYSIS
# ============================================================

st.divider()

st.header("🧠 SENTINEL-X Analysis")

st.markdown(
    f"""
**Affected User:** `{affected_user}`

**Threat Level:** `{threat_level}`

**Current Stage:** `{current_stage}`

**Predicted Next Stage:** `{predicted_stage}`

**Hybrid Risk:** `{risk_score}/100`

**ML Behavioral Anomaly:** `{user_df["ML_Anomaly"].mean():.0f}/100`

**Prototype Evidence Confidence:** `{confidence}%`

The system combines deterministic security semantics with behavioral
anomaly detection. Related events are correlated through shared
entities and chronological order to reconstruct an attack chain.

The resulting Attack DNA provides an interpretable representation of
how the activity progressed and identifies an intervention point before
the predicted next stage.
"""
)

st.caption(
    "SENTINEL-X is an evaluation prototype. "
    "Confidence values represent prototype evidence strength and are "
    "not calibrated probabilities."
)

st.success(
    "SENTINEL-X analysis complete."
)
