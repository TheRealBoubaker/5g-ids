import subprocess, glob, os
import pandas as pd, numpy as np

CAP = os.path.expanduser('~/5g-ids/captures')
OUT = os.path.expanduser('~/5g-ids/features/dataset_5g.csv')

def label_of(f):
    b = os.path.basename(f)
    for k in ['normal','floodudp','floodsyn','floodicmp','signaling']:
        if b.startswith(k): return k
    return 'unknown'

def extract(pcap):
    tmp = pcap + '.fields.csv'
    with open(tmp, 'w') as f:
        subprocess.run(['tshark','-r',pcap,'-T','fields',
            '-e','frame.time_epoch','-e','frame.len','-e','ip.src',
            '-e','tcp.flags.syn','-e','icmp.type',
            '-e','udp.srcport','-e','tcp.srcport',
            '-E','separator=,','-E','header=y','-E','occurrence=f'],
            stdout=f)
    df = pd.read_csv(tmp, low_memory=False)
    os.remove(tmp)
    return df

rows = []
for pcap in sorted(glob.glob(f'{CAP}/*.pcapng')):
    lab = label_of(pcap)
    cid = os.path.basename(pcap).replace('.pcapng', '')
    print('->', cid, lab)
    df = extract(pcap)
    if df.empty:
        continue
    df['t']    = df['frame.time_epoch'].astype(float).astype(int)
    df['flen'] = pd.to_numeric(df['frame.len'], errors='coerce')
    df['syn']  = pd.to_numeric(df['tcp.flags.syn'], errors='coerce').fillna(0)
    df['icmp'] = pd.to_numeric(df['icmp.type'], errors='coerce').notna().astype(int)
    df['udp']  = pd.to_numeric(df['udp.srcport'], errors='coerce').notna().astype(int)
    df['tcp']  = pd.to_numeric(df['tcp.srcport'], errors='coerce').notna().astype(int)
    g = df.groupby('t').agg(
        pkts=('flen','size'), bytes=('flen','sum'),
        mean_len=('flen','mean'), std_len=('flen','std'),
        syn=('syn','sum'), icmp=('icmp','sum'),
        udp=('udp','sum'), tcp=('tcp','sum'),
        uniq_src=('ip.src','nunique')).reset_index()
    g['std_len'] = g['std_len'].fillna(0)
    for c in ['syn','icmp','udp','tcp']:
        g[c + '_ratio'] = g[c] / g['pkts']
    g = g.iloc[1:-1].copy()                 # retire fenêtres partielles
    g['label'] = lab
    g['capture_id'] = cid
    print('   ', g.shape[0], 'fenêtres')
    rows.append(g)

data = pd.concat(rows, ignore_index=True)
data.to_csv(OUT, index=False)
print('\nDataset :', data.shape)
print(data.groupby(['label','capture_id']).size())
print('Fichier :', OUT)
