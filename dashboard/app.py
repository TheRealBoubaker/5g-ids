import streamlit as st
import pandas as pd, json, os, time

STREAM = os.path.expanduser('~/5g-ids/dashboard/stream_results.jsonl')

st.set_page_config(page_title="5G-IDS Live", layout="wide")
st.title("🛰️ Détection d'anomalies 5G — temps réel")

placeholder = st.empty()

def load_data():
    if not os.path.exists(STREAM):
        return pd.DataFrame()
    rows = []
    with open(STREAM) as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return pd.DataFrame(rows)

while True:
    df = load_data()
    with placeholder.container():
        if df.empty:
            st.info("En attente de données... lance replay.py ou live_capture.py")
        else:
            last = df.iloc[-1]
            is_attack = last['pred'] != 0
            if is_attack:
                st.error(f"🔴 ATTAQUE DÉTECTÉE — type: anomalie (classe {last['pred']})  (t={last['t']})")
            else:
                st.success(f"🟢 Trafic normal  (t={last['t']})")

            col1, col2, col3 = st.columns(3)
            col1.metric("Paquets/s (dernière fenêtre)", int(last['pkts']))
            col2.metric("syn_ratio", round(last.get('syn_ratio',0), 3))
            col3.metric("icmp_ratio", round(last.get('icmp_ratio',0), 3))

            st.line_chart(df.set_index('t')[['pkts','syn_ratio','icmp_ratio','udp_ratio']].tail(60))
            st.dataframe(df.tail(15)[['t','source','pred','pkts','syn_ratio','icmp_ratio','udp_ratio']], width='stretch')
    time.sleep(1)
