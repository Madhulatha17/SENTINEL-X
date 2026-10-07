import streamlit as st
import pandas as pd
from pathlib import Path

# ============================================================
# SENTINEL-X
# AI-Powered Attack DNA & Early Intervention Engine
# ============================================================

# -----------------------------
# PROJECT PATH
# -----------------------------

PROJECT_FOLDER = Path(__file__).resolve().parent.parent
CSV_FILE = PROJECT_FOLDER / "data" / "security_logs.csv"


# -----------------------------
# PAGE CONFIG
# -----------------------------

st.set_page_config(
    page_title="SENTINEL-X",
    page_icon="🛡️",
    layout="wide"
)


# -----------------------------
# LOAD SECURITY LOGS
# -----------------------------

@st.cache_data
def load_data():
    data = pd.read_csv(CSV_FILE)
    data["Timestamp"] = pd.to_datetime(data["Timestamp"])
    data = data.sort_values("Timestamp")
    return data


df = load_data()


# ============================================================
# 1. EVENT CORRELATION + RISK ENGINE
# ============================================================

event_scores = {
    "Login": 5,
    "File_Access": 15,
    "Privilege_Change": 25,
    "Data_Transfer": 30,
    "Logout": 0
}

df["Risk"] = df["Event_Type"].map(event_scores).fillna(0)

# Failed login increases risk
df.loc[df["Status"] == "Failed", "Risk"] += 10


# Calculate risk for every user
user_scores = df.groupby("User_ID")["Risk"].sum()

affected_user = user_scores.idxmax()

risk_score = min(
    int(user_scores.max()),
    100
)


# Get events belonging to suspicious user
user_events = df[
    df["User_ID"] == affected_user
].copy()


# ============================================================
# 2. ATTACK DNA
# ============================================================

attack_sequence = user_events[
    "Event_Type"
].tolist()


# ============================================================
# 3. ATTACK STAGE DETECTION
# ============================================================

if "Data_Transfer" in attack_sequence:

    current_stage = "Data Exfiltration"
    predicted_stage = "Further Exfiltration / Persistence"

elif "Privilege_Change" in attack_sequence:

    current_stage = "Privilege Escalation"
    predicted_stage = "Data Exfiltration"

elif "File_Access" in attack_sequence:

    current_stage = "Data Collection"
    predicted_stage = "Privilege Escalation"

else:

    current_stage = "Initial Access"
    predicted_stage = "Data Collection"


# ============================================================
# 4. THREAT LEVEL
# ============================================================

if risk_score >= 80:

    threat_level = "CRITICAL"

elif risk_score >= 60:

    threat_level = "HIGH"

elif risk_score >= 30:

    threat_level = "MEDIUM"

else:

    threat_level = "LOW"


# ============================================================
# 5. EVIDENCE
# ============================================================

failed_logins = len(
    user_events[
        user_events["Status"] == "Failed"
    ]
)

has_file_access = (
    "File_Access" in attack_sequence
)

has_privilege_change = (
    "Privilege_Change" in attack_sequence
)

has_data_transfer = (
    "Data_Transfer" in attack_sequence
)


# ============================================================
# MAIN HEADER
# ============================================================

st.title("🛡️ SENTINEL-X")

st.subheader(
    "AI-Powered Attack DNA & Early Intervention Engine"
)

st.write(
    "SENTINEL-X correlates security events, reconstructs "
    "attack progression, predicts the next stage and "
    "identifies a possible intervention point."
)

st.divider()


# ============================================================
# TOP DASHBOARD
# ============================================================

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "🚨 Threat Level",
        threat_level
    )

with col2:

    st.metric(
        "📊 Risk Score",
        f"{risk_score}/100"
    )

with col3:

    st.metric(
        "📈 Current Stage",
        current_stage
    )

with col4:

    st.metric(
        "👤 Affected User",
        affected_user
    )


st.divider()


# ============================================================
# 6. ATTACK DNA
# ============================================================

st.header("🧬 Attack DNA")

st.write(
    "Observed sequence of suspicious activity:"
)

dna = " → ".join(
    attack_sequence
)

st.code(
    dna,
    language="text"
)


# ============================================================
# 7. ATTACK PROGRESSION
# ============================================================

st.header("📈 Attack Progression")

col1, col2 = st.columns(2)

with col1:

    st.info(
        f"CURRENT STAGE\n\n"
        f"### {current_stage}"
    )

with col2:

    st.warning(
        f"PREDICTED NEXT STAGE\n\n"
        f"### {predicted_stage}"
    )


st.divider()


# ============================================================
# 8. EVIDENCE & EXPLAINABILITY
# ============================================================

st.header("🔎 Evidence & Explanation")

evidence_count = 0

if failed_logins >= 2:

    st.success(
        "✓ Multiple failed login attempts detected"
    )

    evidence_count += 1


if has_file_access:

    st.success(
        "✓ Sensitive file access detected"
    )

    evidence_count += 1


if has_privilege_change:

    st.success(
        "✓ Privilege change detected"
    )

    evidence_count += 1


if has_data_transfer:

    st.success(
        "✓ Data transfer detected"
    )

    evidence_count += 1


st.write(
    f"**{evidence_count} suspicious signals contributed "
    f"to the current assessment.**"
)


st.divider()


# ============================================================
# 9. LIVING ATTACK GRAPH
# ============================================================

st.header("🕸️ Living Attack Graph")

st.write(
    "Relationship between the user, device, IP address, "
    "applications and resources involved in the attack."
)


device = user_events[
    "Device_ID"
].iloc[0]

ip_address = user_events[
    "IP_Address"
].iloc[0]


# Graphviz diagram
dot = f"""
digraph AttackGraph {{

    graph [
        rankdir=LR,
        bgcolor="transparent"
    ];

    node [
        shape=box,
        style="rounded,filled",
        fontname="Arial"
    ];

    User [
        label="👤 USER\\n{affected_user}"
    ];

    Device [
        label="💻 DEVICE\\n{device}"
    ];

    IP [
        label="🌐 IP\\n{ip_address}"
    ];

    User -> Device;
    Device -> IP;
"""


# Applications
applications = list(
    user_events["Application"]
    .dropna()
    .unique()
)

for i, application in enumerate(applications):

    node_id = f"App{i}"

    dot += f"""
    {node_id} [
        label="📱 {application}"
    ];

    IP -> {node_id};
    """


# Resources
resources = list(
    user_events["Resource"]
    .dropna()
    .unique()
)

for i, resource in enumerate(resources):

    if resource == "-":
        continue

    node_id = f"Resource{i}"

    dot += f"""
    {node_id} [
        label="📄 {resource}"
    ];
    """


# Connect applications to resources
for i, resource in enumerate(resources):

    if resource == "-":
        continue

    matching = user_events[
        user_events["Resource"] == resource
    ]

    if matching.empty:
        continue

    application = matching[
        "Application"
    ].iloc[0]

    if application in applications:

        app_index = applications.index(
            application
        )

        dot += f"""
        App{app_index} -> Resource{i};
        """


dot += """
}
"""


st.graphviz_chart(
    dot,
    use_container_width=True
)


st.divider()


# ============================================================
# 10. ATTACK REPLAY
# ============================================================

st.header("🎬 Attack Replay")

st.write(
    "Replay the reconstructed attack sequence."
)


if "replay_started" not in st.session_state:

    st.session_state.replay_started = False


if st.button(
    "▶ Start Attack Replay"
):

    st.session_state.replay_started = True


if st.session_state.replay_started:

    for _, event in user_events.iterrows():

        st.write(
            f"**{event['Timestamp'].strftime('%H:%M:%S')}**"
            f" — {event['Event_Type']}"
        )


st.divider()


# ============================================================
# 11. COUNTERFACTUAL DEFENSE
# ============================================================

st.header("🔀 Counterfactual Defense")

st.write(
    "Simulate where the attack chain could be disrupted."
)

col1, col2, col3, col4 = st.columns(4)


with col1:

    isolate = st.button(
        "🛑 Isolate Device"
    )


with col2:

    block_ip = st.button(
        "🚫 Block IP"
    )


with col3:

    disable_user = st.button(
        "👤 Disable User"
    )


with col4:

    block_transfer = st.button(
        "📦 Block Data Transfer"
    )


if isolate:

    st.success(
        f"SIMULATION: Device {device} isolated."
    )

    st.metric(
        "Simulated Risk",
        "45/100"
    )

    st.write(
        "The simulated intervention breaks the "
        "device-to-data-transfer path."
    )


if block_ip:

    st.success(
        f"SIMULATION: IP {ip_address} blocked."
    )

    st.metric(
        "Simulated Risk",
        "40/100"
    )


if disable_user:

    st.success(
        f"SIMULATION: User {affected_user} disabled."
    )

    st.metric(
        "Simulated Risk",
        "35/100"
    )


if block_transfer:

    st.success(
        "SIMULATION: Data transfer blocked."
    )

    st.metric(
        "Simulated Risk",
        "30/100"
    )


st.caption(
    "⚠️ Counterfactual defense actions are simulated "
    "and do not execute real security controls."
)


st.divider()


# ============================================================
# 12. SECURITY EVENT TIMELINE
# ============================================================

st.header("⏱️ Security Event Timeline")

timeline = user_events[
    [
        "Timestamp",
        "User_ID",
        "Device_ID",
        "IP_Address",
        "Event_Type",
        "Application",
        "Resource",
        "Status"
    ]
].copy()


st.dataframe(
    timeline,
    use_container_width=True,
    hide_index=True
)


st.divider()


# ============================================================
# FINAL SUMMARY
# ============================================================

st.header("🧠 SENTINEL-X Analysis")

st.write(
    f"SENTINEL-X identified **{affected_user}** as the "
    f"highest-risk user with a score of **{risk_score}/100**. "
    f"The observed activity progressed to "
    f"**{current_stage}**."
)

st.write(
    f"The prototype predicts **{predicted_stage}** as the "
    f"next possible stage and recommends intervention "
    f"before additional malicious activity occurs."
)


st.divider()

st.caption(
    "SENTINEL-X — Cyber Threat Intelligence Prototype"
)