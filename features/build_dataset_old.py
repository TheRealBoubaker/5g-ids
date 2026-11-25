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
    with open(tmp,'w') as f:
        subprocess.run(['tshark','-r',pcap,'-T','fields',
            '-e','frame.time_epoch','-e','frame.len',
            '-e','tcp.flags.syn','-e','icmp.type',
            '-E','separator=,','-E','header=y'], stdout=f)
    df = pd.read_csv(tmp, low_memory=False); os.remove(tmp); return df

rows = []
for pcap in sorted(glob.glob(f'{CAP}/*.pcapng')):
    lab = label_of(pcap); print('->', os.path.basename(pcap), lab)
    df = extract(pcap)
    if df.empty: continue
    df['t'] = df['frame.time_epoch'].astype(float).astype(int)
    df['flen'] = pd.to_numeric(df['frame.len'], errors='coerce')
    df['syn'] = pd.to_numeric(df['tcp.flags.syn'], errors='coerce').fillna(0)
    df['icmp'] = pd.to_numeric(df['icmp.type'], errors='coerce').notna().astype(int)
    g = df.groupby('t').agg(
        pkts=('flen','size'), bytes=('flen','sum'),
        mean_len=('flen','mean'), std_len=('flen','std'),
        syn=('syn','sum'), icmp=('icmp','sum')).reset_index()
    g['std_len'] = g['std_len'].fillna(0)
    g['label'] = lab
    rows.append(g)

data = pd.concat(rows, ignore_index=True)
data.to_csv(OUT, index=False)
print('\nDataset :', data.shape)
print(data['label'].value_counts())
print('Fichier :', OUT)
