import subprocess, sys, time, csv, io
from common import load_model, window_from_rows, predict_window, emit, OUT_STREAM

if len(sys.argv) < 2:
    print("usage: python3 replay.py <capture.pcapng> [vitesse x1=temps réel]")
    sys.exit(1)

pcap = sys.argv[1]
speed = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

model = load_model()


print(f"Rejeu de {pcap} (vitesse x{speed})")
open(OUT_STREAM, 'w').close()  # reset du flux pour une démo propre

proc = subprocess.Popen(
    ['tshark','-r',pcap,'-T','fields',
     '-e','frame.time_epoch','-e','frame.len','-e','ip.src',
     '-e','tcp.flags.syn','-e','icmp.type','-e','udp.srcport','-e','tcp.srcport',
     '-E','separator=,','-E','header=y','-E','occurrence=f'],
    stdout=subprocess.PIPE, text=True)

reader = csv.DictReader(proc.stdout)
current_t, buf = None, []
first_pkt_time, replay_start = None, None

for row in reader:
    try:
        ts = float(row['frame.time_epoch'])
    except (ValueError, KeyError):
        continue
    t = int(ts)

    if first_pkt_time is None:
        first_pkt_time, replay_start = ts, time.time()

    if current_t is None:
        current_t = t
    elif t != current_t:
        # ferme la fenêtre précédente, prédit, émet
        res = window_from_rows(buf)
        if res:
            feat = res
            pred, proba = predict_window(model, feat)
            emit(current_t, feat, pred, proba, source='replay')
            flag = '🔴 ATTAQUE' if pred != 0 else '🟢 normal'
            print(f"t={current_t}  pkts={feat['pkts']:4d}  {flag}  ({pred})")
        buf = []
        current_t = t
        # respecte le rythme d'origine de la capture / speed
        target = replay_start + (ts - first_pkt_time) / speed
        delay = target - time.time()
        if delay > 0:
            time.sleep(delay)

    buf.append(row)

if buf:
    res = window_from_rows(buf)
    if res:
        feat = res
        pred, proba = predict_window(model, feat)
        emit(current_t, feat, pred, proba, source='replay')

print("Rejeu terminé.")
