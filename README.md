# 5G-IDS : détection d'intrusions réseau 5G par Machine Learning

IDS pour réseau 5G de test : capture du trafic, extraction de features par fenêtre temporelle, entraînement de modèles de détection d'anomalies et dashboard Streamlit en temps réel.

**Attaques :** SYN flood, UDP flood, ICMP flood
**Modèles :** Random Forest, Isolation Forest, Autoencodeur

## Structure

- `capture.sh` : capture du trafic (.pcapng)
- `measure_qos.sh` : mesures de QoS
- `features/` : agrégation des paquets et construction du dataset
- `ml/train.py` : entraînement et évaluation des modèles
- `dashboard/` : application Streamlit (replay et capture live)
- `requirements.txt` : dépendances Python

## Installation

    git clone https://github.com/TheRealBoubaker/5g-ids.git
    cd 5g-ids
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

## Utilisation

Les captures, modèles (.joblib) et gros CSV ne sont pas versionnés, il faut les régénérer :

    ./capture.sh
    python3 features/build_dataset.py
    python3 ml/train.py
    cd dashboard && streamlit run app.py

Dashboard : http://localhost:8501

## Évaluation

Chaque modèle est évalué (précision, rappel, F1) sur les attaques connues et sur une attaque inconnue exclue de l'entraînement (`B_inconnue_*`).

## Avertissement

Projet éducatif. Attaques générées uniquement dans un environnement de test isolé.

## Auteur

Anis Boubaker, @TheRealBoubaker
