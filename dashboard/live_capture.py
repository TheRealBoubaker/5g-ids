import subprocess, sys, csv, io, time
from common import load_model, window_from_rows, predict_window, emit, OUT_STREAM

CONTAINER = sys.argv[1] if len(sys.argv) > 1 else 'nr_ue'
IFACE = sys.argv[2] if len(sys.argv) > 2 else 'uesimtun0'

model = load_model()


print(f"Capture live sur {CONTAINER}:{IFACE} — Ctrl+C pour arrêter")
open(OUT_STREAM, 'w').close()

cmd = ['docker','exec','-i',CONTAINER,'tshark','-i',IFACE,'-l','-T','fields',
       '-e','frame.time_epoch','-e','frame.len','-e','ip.src',
       '-e','tcp.flags.syn','-e','icmp.type','-e','udp.srcport','-e','tcp.srcport',
       '-E','separator=,','-E','header=y','-E','occurrence=f']

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
header = proc.stdout.readline()
fieldnames = header.strip().split(',')

current_t, buf = None, []
try:
    for line in proc.stdout:
        row = dict(zip(fieldnames, line.strip().split(',')))
        try:
            t = int(float(row['frame.time_epoch']))
        except (ValueError, KeyError):
            continue
        if current_t is None:
            current_t = t
        elif t != current_t:
            res = window_from_rows(buf)
            if res:
                feat = res
                pred, proba = predict_window(model, feat)
                emit(current_t, feat, pred, proba, source='live')
                flag = '🔴 ATTAQUE' if pred != 0 else '🟢 normal'
                print(f"t={current_t}  pkts={feat['pkts']:4d}  {flag}  ({pred})")
            buf, current_t = [], t
        buf.append(row)
except KeyboardInterrupt:
    print("\nArrêt demandé.")
finally:
    proc.terminate()
