import glob, os
import pandas as pd

CAP = os.path.expanduser('~/5g-ids/captures')
OUT = os.path.expanduser('~/5g-ids/features/dataset_5g.csv')

def label_of(b):
    for k in ['normal','floodudp','floodsyn','floodicmp','signaling']:
        if b.startswith(k): return k
    return 'unknown'

rows = []
for csv in sorted(glob.glob(f'{CAP}/*.csv')):
    lab = label_of(os.path.basename(csv))
    df = pd.read_csv(csv, low_memory=False, on_bad_lines='skip')
    df['t'] = pd.to_numeric(df['frame.time_epoch'], errors='coerce')
    df = df.dropna(subset=['t']).copy()
    df['t'] = df['t'].astype('int64')
    df['flen'] = pd.to_numeric(df['frame.len'], errors='coerce').fillna(0)
    df['syn'] = pd.to_numeric(df['tcp.flags.syn'], errors='coerce').fillna(0)
    df['icmp'] = pd.to_numeric(df['icmp.type'], errors='coerce').notna().astype(int)
    g = df.groupby('t').agg(
        pkts=('flen','size'), bytes=('flen','sum'),
        mean_len=('flen','mean'), std_len=('flen','std'),
        syn=('syn','sum'), icmp=('icmp','sum')).reset_index()
    g['std_len'] = g['std_len'].fillna(0); g['label'] = lab
    print(f'{lab:12s} {g.shape[0]} fenetres')
    rows.append(g)

data = pd.concat(rows, ignore_index=True)
data.to_csv(OUT, index=False)
print('\nDataset :', data.shape)
print(data['label'].value_counts())
print('->', OUT)
