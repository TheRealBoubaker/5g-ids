import numpy as np
def _np_default(o):
    if isinstance(o, np.integer): return int(o)
    if isinstance(o, np.floating): return float(o)
    if isinstance(o, np.ndarray): return o.tolist()
    raise TypeError(type(o).__name__)

import os, json
import pandas as pd, numpy as np
import joblib

MODEL_PATH = os.path.expanduser('~/5g-ids/ml/rf_model.joblib')
OUT_STREAM = os.path.expanduser('~/5g-ids/dashboard/stream_results.jsonl')

FEATURE_ORDER = ['pkts','bytes','mean_len','std_len','syn','icmp','udp','tcp',
                  'uniq_src','syn_ratio','icmp_ratio','udp_ratio','tcp_ratio']

def load_model():
    return joblib.load(MODEL_PATH)

def window_from_rows(rows):
    df = pd.DataFrame(rows)
    if df.empty:
        return None
    df['flen'] = pd.to_numeric(df['frame.len'], errors='coerce')
    df['syn']  = pd.to_numeric(df['tcp.flags.syn'], errors='coerce').fillna(0)
    df['icmp'] = pd.to_numeric(df['icmp.type'], errors='coerce').notna().astype(int)
    df['udp']  = pd.to_numeric(df['udp.srcport'], errors='coerce').notna().astype(int)
    df['tcp']  = pd.to_numeric(df['tcp.srcport'], errors='coerce').notna().astype(int)
    pkts = len(df)
    feat = {
        'pkts': pkts,
        'bytes': df['flen'].sum(),
        'mean_len': df['flen'].mean(),
        'std_len': df['flen'].std() if pkts > 1 else 0.0,
        'syn': df['syn'].sum(),
        'icmp': df['icmp'].sum(),
        'udp': df['udp'].sum(),
        'tcp': df['tcp'].sum(),
        'uniq_src': df['ip.src'].nunique(),
    }
    for c in ['syn','icmp','udp','tcp']:
        feat[c + '_ratio'] = feat[c] / feat['pkts'] if feat['pkts'] else 0.0
    return feat

def predict_window(model, feat):
    X = np.log1p(np.array([[feat[c] for c in FEATURE_ORDER]], dtype=float))
    pred = int(model.predict(X)[0])
    proba = None
    if hasattr(model, 'predict_proba'):
        proba = dict(zip([int(c) for c in model.classes_],
                          model.predict_proba(X)[0].round(3).tolist()))
    return pred, proba

def emit(t, feat, pred, proba, source):
    rec = {'t': t, 'source': source, 'pred': pred, 'proba': proba, **feat}
    with open(OUT_STREAM, 'a') as f:
        f.write(json.dumps(rec, default=_np_default) + '\n')
