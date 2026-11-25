import os, warnings; warnings.filterwarnings('ignore')
import numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
import joblib

ML = os.path.expanduser('~/5g-ids/ml')
df = pd.read_csv(os.path.expanduser('~/5g-ids/features/dataset_5g.csv'))
feat = ['pkts','bytes','mean_len','std_len','syn','icmp']
X = df[feat].values
y = (df['label'] != 'normal').astype(int).values     # 0=normal, 1=anomalie

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

def report(name, yt, yp):
    cm = confusion_matrix(yt, yp, labels=[0,1]); tn,fp,fn,tp = cm.ravel()
    p = precision_score(yt,yp,zero_division=0); r = recall_score(yt,yp,zero_division=0)
    f = f1_score(yt,yp,zero_division=0); fpr = fp/(fp+tn) if (fp+tn) else 0
    print(f'\n=== {name} ===')
    print(f'Precision={p:.3f}  Recall={r:.3f}  F1={f:.3f}  FauxPositifs={fpr:.3f}')
    print('Matrice [[TN FP][FN TP]] :\n', cm)
    return dict(modele=name, precision=round(p,3), recall=round(r,3), f1=round(f,3), fpr=round(fpr,3))

res = []

# 1) Random Forest (supervisé)
rf = RandomForestClassifier(n_estimators=200, random_state=42).fit(Xtr, ytr)
res.append(report('Random Forest', yte, rf.predict(Xte)))
print('Importances :', dict(zip(feat, rf.feature_importances_.round(3))))
joblib.dump(rf, f'{ML}/rf_model.joblib')

# 2) Autoencodeur (non supervisé, appris sur le normal)
sc = StandardScaler().fit(Xtr[ytr==0])
ae = MLPRegressor(hidden_layer_sizes=(16,4,16), max_iter=3000, random_state=42).fit(
        sc.transform(Xtr[ytr==0]), sc.transform(Xtr[ytr==0]))
err = lambda M: ((ae.predict(sc.transform(M)) - sc.transform(M))**2).mean(axis=1)
seuil = np.quantile(err(Xtr[ytr==0]), 0.95)
res.append(report('Autoencodeur', yte, (err(Xte) > seuil).astype(int)))
joblib.dump({'ae':ae,'scaler':sc,'seuil':float(seuil)}, f'{ML}/ae_model.joblib')

# Comparaison
comp = pd.DataFrame(res).set_index('modele')
print('\n========= COMPARAISON =========\n', comp)
comp.to_csv(f'{ML}/comparison.csv')
print('\nModeles sauvegardes dans ~/5g-ids/ml/')
