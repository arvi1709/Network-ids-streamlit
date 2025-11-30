import streamlit as st
import pandas as pd
import joblib
import random
import datetime
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
from scapy.all import sniff, ARP


# ----------------- CONFIG -----------------
st.set_page_config(
    page_title="Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)

# ----------------- LOAD MODELS -----------------
@st.cache_resource
def load_models():
    binary_model = joblib.load("binary_ids_model.pkl")
    multiclass_model = joblib.load("multiclass_ids_model.pkl")
    return binary_model, multiclass_model

binary_model, multiclass_model = load_models()

# ----------------- SESSION STATE INIT -----------------
if "logs" not in st.session_state:
    st.session_state.logs = []   # each item: {time, type, category, src_ip, dst_ip}
if "arp_alerts" not in st.session_state:
    st.session_state.arp_alerts = []  # list of strings


# ----------------- HELPER FUNCTIONS -----------------
def generate_ip():
    return f"192.168.1.{random.randint(2, 254)}"

def add_log(category: str, is_attack: bool = True):
    now = datetime.datetime.now()
    src_ip = generate_ip()
    dst_ip = "192.168.1.1" if is_attack else generate_ip()

    st.session_state.logs.append({
        "time": now,
        "category": category,
        "is_attack": is_attack,
        "src_ip": src_ip,
        "dst_ip": dst_ip
    })

def get_logs_df() -> pd.DataFrame:
    if not st.session_state.logs:
        return pd.DataFrame(columns=["time", "category", "is_attack", "src_ip", "dst_ip"])
    df = pd.DataFrame(st.session_state.logs)
    df = df.sort_values("time")
    return df


# ----------------- DASHBOARD PAGE -----------------
def dashboard_page():
    st.title("🛡️ Network Intrusion Detection Dashboard")

    logs_df = get_logs_df()

    total_events = len(logs_df)
    total_attacks = int(logs_df["is_attack"].sum()) if total_events > 0 else 0
    arp_alerts = len(st.session_state.arp_alerts)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", str(total_events))
    col2.metric("Attacks Detected", str(total_attacks))
    col3.metric("ARP Spoof Alerts", str(arp_alerts))

    st.markdown("---")

    if total_events == 0:
        st.info("No events logged yet. Run some predictions from the **ML Attack Detection** page.")
        return

    # ---- Line chart: attacks over time ----
    st.subheader("📈 Attack Events Over Time")
    time_df = logs_df.copy()
    time_df["date_minute"] = time_df["time"].dt.floor("T")
    agg = time_df.groupby("date_minute")["is_attack"].sum().reset_index()
    fig_line = px.line(agg, x="date_minute", y="is_attack",
                       labels={"date_minute": "Time", "is_attack": "Number of Attacks"},
                       title="Attacks Detected per Minute")
    st.plotly_chart(fig_line, use_container_width=True)

    st.markdown("---")

    # ---- Bar chart: attack category counts ----
    st.subheader("📊 Attack Categories Distribution")
    attack_only = logs_df[logs_df["is_attack"] == True]
    if not attack_only.empty:
        cat_counts = attack_only["category"].value_counts().reset_index()
        cat_counts.columns = ["category", "count"]
        fig_bar = px.bar(cat_counts, x="category", y="count",
                         title="Attack Category Counts",
                         labels={"category": "Category", "count": "Count"})
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No attack events logged yet for bar chart.")

    st.markdown("---")

    # ---- Network Graph: Source -> Destination IPs ----
    st.subheader("🕸 IP Relationship Graph (Attacker → Target)")

    if not attack_only.empty:
        G = nx.DiGraph()
        for _, row in attack_only.iterrows():
            src = row["src_ip"]
            dst = row["dst_ip"]
            cat = row["category"]
            G.add_node(src, type="src")
            G.add_node(dst, type="dst")
            G.add_edge(src, dst, category=cat)

        # Layout
        pos = nx.spring_layout(G, seed=42, k=0.8)

        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5),
            hoverinfo="none",
            mode="lines"
        )

        node_x = []
        node_y = []
        node_text = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode="markers+text",
            text=node_text,
            textposition="top center",
            marker=dict(size=10),
            hoverinfo="text"
        )

        fig_graph = go.Figure(data=[edge_trace, node_trace],
                              layout=go.Layout(
                                  showlegend=False,
                                  margin=dict(l=0, r=0, t=30, b=0),
                                  title="Attacker → Target IP Graph"
                              ))
        st.plotly_chart(fig_graph, use_container_width=True)
    else:
        st.info("No attack events to show in IP graph.")

    st.markdown("---")

    st.subheader("📋 Event Logs")
    st.dataframe(logs_df[["time", "category", "is_attack", "src_ip", "dst_ip"]].tail(50))


# ----------------- ML ATTACK DETECTION PAGE -----------------
def ml_detection_page():
    st.title("⚙️ Machine Learning Based Attack Detection")

    st.write("Upload a CSV with the **same structure** as UNSW_NB15 testing set.")

    uploaded_file = st.file_uploader("Upload CSV Network Data", type=["csv"])

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.write("### Uploaded Data Preview:")
        st.dataframe(df.head())

        feature_df = df.drop(columns=["id", "attack_cat", "label"], errors="ignore")

        use_multiclass = st.radio(
            "Choose prediction mode:",
            ["Binary: Normal vs Attack", "Multi-class: Normal vs DoS vs Recon"],
            index=1
        )

        if st.button("Run Prediction"):
            if feature_df.empty:
                st.error("No valid feature columns after dropping id/attack_cat/label.")
                return

            if use_multiclass.startswith("Binary"):
                preds = binary_model.predict(feature_df)
                labels = ["Normal" if p == 0 else "Attack" for p in preds]
            else:
                preds = multiclass_model.predict(feature_df)
                labels = preds  # already categories: Normal / DoS / Reconnaissance

            st.write("### Predictions:")
            df_result = df.copy()
            df_result["prediction"] = labels
            st.dataframe(df_result.head(50))

            # Log events into session_state
            for label in labels:
                if label in ["DoS", "Reconnaissance", "Attack"]:
                    cat = "DoS" if "DoS" in label else (
                        "Port Scan (Recon)" if "Recon" in label else "Attack"
                    )
                    add_log(cat, is_attack=True)
                else:
                    add_log("Normal", is_attack=False)

            st.success(f"Prediction complete. {len(labels)} events logged to dashboard.")


# ----------------- ARP SPOOF PAGE -----------------
def run_arp_scan(duration: int = 10):
    """
    Sniff ARP packets for `duration` seconds.
    Returns a list of alert messages if suspicious changes are detected.
    """
    ip_to_mac = {}
    alerts = []

    def detect_arp(packet):
        nonlocal ip_to_mac, alerts
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            if ip in ip_to_mac and ip_to_mac[ip] != mac:
                msg = f"[!!!] Possible ARP Spoof: {ip} was {ip_to_mac[ip]} now {mac}"
                alerts.append(msg)
            else:
                ip_to_mac[ip] = mac

    sniff(filter="arp", prn=detect_arp, store=0, timeout=duration)
    return alerts


def arp_spoof_page():
    st.title("🔍 ARP Spoofing Detection")

    st.write("""
    This page runs a **real ARP spoof scan** on the network interface of this machine.

    - It listens to ARP replies for a short time.
    - If the same IP suddenly maps to a different MAC address, it flags a possible ARP spoof.
    """)

    scan_duration = st.slider("Scan duration (seconds)", min_value=5, max_value=60, value=10, step=5)

    if st.button("Scan my network for ARP spoofing"):
        with st.spinner(f"Scanning for ARP spoofing for {scan_duration} seconds..."):
            try:
                alerts = run_arp_scan(scan_duration)
            except Exception as e:
                st.error(f"Error while sniffing ARP packets: {e}")
                st.info("Make sure you have Scapy installed, Npcap/WinPcap (on Windows), and run with admin/root permissions.")
                return

        if alerts:
            st.error("⚠️ Possible ARP spoofing activity detected!")
            for msg in alerts:
                st.write(msg)
                # also push to global logs for dashboard
                st.session_state.arp_alerts.append(msg)
                add_log("ARP Spoof", is_attack=True)
        else:
            st.success("✅ No ARP spoofing signs detected during this scan.")
            st.session_state.arp_alerts.append(
                f"{datetime.datetime.now()} - Scan OK: No ARP spoofing detected."
            )

    st.markdown("---")

    st.subheader("📜 ARP Scan History")
    if st.session_state.arp_alerts:
        for alert in st.session_state.arp_alerts[-20:]:
            st.write(alert)
    else:
        st.info("No scans performed yet.")

# ----------------- ABOUT PAGE -----------------
def about_page():
    st.title("📖 About the Project")

    st.markdown("""
    ### Network Intrusion Detection System (NIDS) using Machine Learning & ARP Spoof Detection

    **Components:**
    - ✅ Machine Learning Models trained on **UNSW-NB15** dataset
      - Binary model: Normal vs Attack
      - Multi-class model: Normal vs DoS vs Reconnaissance (Port Scan)
    - ✅ Real-time style dashboard with:
      - KPI metrics
      - Line chart of attacks over time
      - Bar chart of attack categories
      - IP relationship network graph
      - Live event logs
    - ✅ ARP Spoofing Detection module (simulated in UI + real Scapy script)

    **Technologies Used:**
    - Python, Scikit-learn, Imbalanced-learn
    - Streamlit (Web UI)
    - Plotly, NetworkX
    - Scapy (for ARP sniffing)
    """)

    st.markdown("""
    **Developed by:** Arvind  
    **Role:** B.Tech CSE (AI & ML) Student  
    **Use Case:** Network Security / Intrusion Detection System Project
    """)


# ----------------- MAIN APP ROUTER -----------------
def main():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Go to",
        ["Dashboard", "ML Attack Detection", "ARP Spoof Detector", "About"],
    )

    if page == "Dashboard":
        dashboard_page()
    elif page == "ML Attack Detection":
        ml_detection_page()
    elif page == "ARP Spoof Detector":
        arp_spoof_page()
    elif page == "About":
        about_page()


if __name__ == "__main__":
    main()
