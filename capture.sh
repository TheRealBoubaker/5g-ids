#!/bin/bash
# Usage: ./capture.sh <nom_sortie> <duree_s> <commande_a_executer_dans_nr_ue...>
# Exemple: ./capture.sh normal_ping_01 30 ping -I uesimtun0 -c 25 8.8.8.8

NAME=$1; DUR=$2; shift 2
OUT=~/5g-ids/captures/${NAME}.pcapng

echo ">>> Capture $NAME sur uesimtun0 pendant ${DUR}s"
docker exec nr_ue tshark -i uesimtun0 -a duration:${DUR} -w /tmp/${NAME}.pcapng &
TSHARK_BG=$!
sleep 3
echo ">>> Lancement : $@"
docker exec nr_ue "$@"
wait $TSHARK_BG
docker cp nr_ue:/tmp/${NAME}.pcapng ${OUT}
docker exec nr_ue rm -f /tmp/${NAME}.pcapng
echo ">>> Fichier : $OUT"
capinfos -c -d ${OUT} 2>/dev/null | grep -E "Number of packets|Capture duration"
