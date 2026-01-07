
import streamlit as st
import pandas as pd
import joblib
import time
import queue
import threading
from scapy.all import sniff, DNS, DNSQR, IP
from features import extract_features
import plotly.express as px
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

import os

# Load Model
try:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MODEL_PATH = os.path.join(BASE_DIR, 'models', 'random_forest_model.pkl')
    model = joblib.load(MODEL_PATH)
    MODEL_LOADED = True
except Exception as e:
    print(f"Error loading model from {MODEL_PATH if 'MODEL_PATH' in locals() else 'unknown'}: {e}")
    MODEL_LOADED = False
    print("Model not found. Please train the model first.")

# Global Queue for Thread Safety
if 'packet_queue' not in st.session_state:
    st.session_state['packet_queue'] = queue.Queue()
packet_queue = st.session_state['packet_queue']

# Helper Functions for packet processing + predictions
def packet_callback(pkt):
    """
    Callback for Scapy Sniffer. 
    Extracts DNS query and pushes to queue.
    """
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            query_bytes = pkt[DNSQR].qname
            query = query_bytes.decode('utf-8').rstrip('.')
            if query.endswith('.local'):
                return
                
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
            
            packet_data = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'query': query,
                'qtype': pkt[DNSQR].qtype,
                'size': len(pkt)
            }
            packet_queue.put(packet_data)
        except Exception as e:
            pass

def start_sniffing(interface=None):
    """Starts the sniffing thread"""
    sniff(prn=packet_callback, filter="udp port 53", store=0, iface=interface)

def process_packet_queue(max_packets=50):
    """Process packets from queue"""
    new_packets = []
    while not packet_queue.empty() and len(new_packets) < max_packets:
        new_packets.append(packet_queue.get())

    if not new_packets:
        return
    
    df_new = pd.DataFrame(new_packets)
    df_features = extract_features(df_new.copy())
    feature_cols = ['query_length', 'entropy', 'subdomain_count', 'max_label_len', 'ratio_numerical']
    X = df_features[feature_cols]
    preds = model.predict(X)
    probs = model.predict_proba(X)

    df_new['is_malicious'] = preds
    df_new['probability'] = [p[1] for p in probs]

    st.session_state.df_logs = pd.concat([df_new, st.session_state.df_logs]).sort_values(by='timestamp', ascending=False).head(1000)

# --- Streamlit App ---
st.set_page_config(page_title="DNS Guard: Tunneling Detector", page_icon="🛡️", layout="wide")

st.title("DNS Guard: Real-Time Tunneling Detection")

if not MODEL_LOADED:
    st.error("⚠️ Model not found! Please run the training script first.")
    st.info("Run: `python experimentation/src/process_dataset.py` then `python experimentation/src/train_model.py`")
    st.stop()

# Sidebar controls
st.sidebar.header("Configuration")
capture_active = st.sidebar.checkbox("Start Live Capture", value=False)
interface = st.sidebar.text_input("Network Interface (leave empty for default)", "")

# Metrics placeholders
col1, col2, col3 = st.columns(3)
with col1:
    metric_total = st.empty()
with col2:
    metric_malicious = st.empty()
with col3:
    metric_rate = st.empty()

# Data Containers
if 'df_logs' not in st.session_state:
    st.session_state.df_logs = pd.DataFrame(columns=['timestamp', 'src_ip', 'query', 'is_malicious', 'probability'])

if 'sniffer_thread' not in st.session_state:
    st.session_state.sniffer_thread = None

# Chart placeholders
chart_col1, chart_col2 = st.columns(2)
with chart_col1:
    st.subheader("Traffic Analysis")
    chart_placeholder = st.empty()
with chart_col2:
    st.subheader("Entropy Distribution")
    entropy_placeholder = st.empty()

st.subheader("Recent Logs (Malicious Highlighted)")
table_placeholder = st.empty()

# Background Thread for Sniffing
pie_chart_placeholder = st.empty()
if capture_active and st.session_state.sniffer_thread is None:
    t = threading.Thread(target=start_sniffing, args=(interface if interface else None,), daemon=True)
    t.start()
    st.session_state.sniffer_thread = t
    st.success("created passive listener on port 53...")

if capture_active:
    st_autorefresh(interval=10000, key='dns_refresh')
    process_packet_queue()
else:
    if 'sniffer_thread' in st.session_state:
        # We can't easily kill threads in Python, but the loop control handles the UI update stop.
        st.warning("Capture stopped. (Thread may remain active in background)")

queries_len = len(st.session_state.df_logs)
malicious_count = st.session_state.df_logs['is_malicious'].sum()

metric_total.metric("Total Queries", queries_len)
metric_malicious.metric("Malicious Detected", malicious_count, delta_color="inverse")

if not st.session_state.df_logs.empty:
    counts = (
        st.session_state.df_logs["is_malicious"]
        .value_counts()
        .reset_index()
    )
    counts.columns = ["is_malicious", "count"]
    counts["label"] = counts["is_malicious"].map({0: "Benign", 1: "Malicious"})

    fig_pie = px.pie(
        counts,
        values="count",
        names="label",
        title="Threat Distribution",
        color="label",
        color_discrete_map={"Benign": "#00cc96", "Malicious": "#EF553B"},
    )

    pie_chart_placeholder.plotly_chart(fig_pie, use_container_width=True)

table_placeholder.dataframe(
    st.session_state.df_logs[
        ["timestamp", "src_ip", "query", "probability"]
    ],
    use_container_width=True
)
