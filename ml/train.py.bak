import os, warnings; warnings.filterwarnings('ignore')
import joblib
import joblib
import joblib
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPRegressor
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

ML = os.path.expanduser('~/5g-ids/ml')
df = pd.read_csv(os.path.expanduser('~/5g-ids/features/dataset_5g.csv'))
df = df.sort_values(['capture_id', 't']).reset_index(drop=True)
feat = [c for c in df.columns if c not in ('t', 'label', 'capture_id')]
df['y'] = (df['label'] != 'normal').astype(int)

# Split chronologique par capture : 70 % début = train, 30 % fin = test
df['rank'] = df.groupby('capture_id').cumcount() / df.groupby('capture_id')['t'].transform('size')
train, test = df[df['rank'] < 0.7], df[df['rank'] >= 0.7]
print('Train :', len(train), ' Test :', len(test))
print(test['label'].value_counts().to_dict())

# Vérité terrain : à quel point la feature pkts sépare-t-elle déjà les classes ?
print('\n=== pkts par classe (si les plages ne se chevauchent pas, la tâche est triviale) ===')
print(df.groupby('label')['pkts'].agg(['min', 'median', 'max']))

L = lambda d: np.log1p(d[feat].values)          # log1p : calme les écarts d'échelle

def metrics(name, scen, yt, yp):
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    return dict(scenario=scen, modele=name,
                precision=round(precision_score(yt, yp, zero_division=0), 3),
                recall=round(recall_score(yt, yp, zero_division=0), 3),
                f1=round(f1_score(yt, yp, zero_division=0), 3),
                fp=int(fp), n_normal=int(tn + fp), fn=int(fn), n_attack=int(tp + fn))

def run_models(tr, te, scen):
    out = []
    # Random Forest (supervisé)
    rf = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
    rf.fit(L(tr), tr['y'])
    out.append(metrics('RandomForest', scen, te['y'], rf.predict(L(te))))
    # Modèles d'anomalie : entraînés UNIQUEMENT sur le normal du train
    ntr = train[train['y'] == 0]
    iso = IsolationForest(n_estimators=200, contamination='auto', random_state=42).fit(L(ntr))
    out.append(metrics('IsolationForest', scen, te['y'], (iso.predict(L(te)) == -1).astype(int)))
    sc = StandardScaler().fit(L(ntr))
    ae = MLPRegressor(hidden_layer_sizes=(16, 4, 16), max_iter=3000, random_state=42)
    ae.fit(sc.transform(L(ntr)), sc.transform(L(ntr)))
    err = lambda d: ((ae.predict(sc.transform(L(d))) - sc.transform(L(d))) ** 2).mean(axis=1)
    seuil = err(ntr).max() * 1.5                  # seuil simple : 1,5 x l'erreur max du normal
    out.append(metrics('Autoencodeur', scen, te['y'], (err(te) > seuil).astype(int)))
    return out

rf_final = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42).fit(L(train), train['y'])
joblib.dump(rf_final, f'{ML}/rf_model.joblib')
print('Modèle sauvegardé :', f'{ML}/rf_model.joblib')

rf_final = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42).fit(L(train), train['y'])
joblib.dump(rf_final, f'{ML}/rf_model.joblib')
print('Modèle sauvegardé :', f'{ML}/rf_model.joblib')

rf_final = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42).fit(L(train), train['y'])
joblib.dump(rf_final, f'{ML}/rf_model.joblib')
print('Modèle sauvegardé :', f'{ML}/rf_model.joblib')

res = run_models(train, test, 'A_attaques_connues')

# Scénario B : attaque INCONNUE (retirée du train, testée sur toutes ses fenêtres)
for atk in sorted(df.loc[df['y'] == 1, 'label'].unique()):
    tr = train[train['label'] != atk]
    te = pd.concat([test[test['label'] == 'normal'], df[df['label'] == atk]])
    res += run_models(tr, te, f'B_inconnue_{atk}')

comp = pd.DataFrame(res)
print('\n', comp.to_string(index=False))
comp.to_csv(f'{ML}/comparison_v2.csv', index=False)
