#!/bin/bash
# usage: ./measure_qos.sh <scenario> <attack: none|syn|udp|icmp> <interval> <n_instances> [n_repeats]
SCEN=$1
ATT=$2
INT=$3
N=$4
REPEATS=${5:-3}
CIBLE=${CIBLE:-192.168.100.1}
OUT=~/5g-ids/qos_results.csv
[ -f "$OUT" ] || echo "scenario,attack,interval,n_instances,rep,loss_pct,rtt_min,rtt_avg,rtt_max,rtt_mdev" > "$OUT"

docker exec nr_ue2 which hping3 >/dev/null || { echo "hping3 manquant dans nr_ue2"; exit 1; }

for r in $(seq 1 $REPEATS); do
  case $ATT in
    syn)
      for i in $(seq 0 $((N-1))); do
        docker exec -d nr_ue2 timeout 20 hping3 -S -p $((80+i)) -c 50000 -i $INT -I uesimtun0 $CIBLE
      done ;;
    udp)
      for i in $(seq 0 $((N-1))); do
        docker exec -d nr_ue2 timeout 20 hping3 --udp -p $((5001+i)) -c 50000 -i $INT -I uesimtun0 $CIBLE
      done ;;
    icmp)
      for i in $(seq 0 $((N-1))); do
        docker exec -d nr_ue2 timeout 20 hping3 --icmp -c 50000 -i $INT -I uesimtun0 $CIBLE
      done ;;
  esac
  [ "$ATT" != "none" ] && sleep 3

  RES=$(docker exec nr_ue ping -c 100 -i 0.1 -I uesimtun0 $CIBLE | tail -2)
  LOSS=$(echo "$RES" | grep -oP '\d+(?=% packet loss)')
  STATS=$(echo "$RES" | grep rtt | sed 's/.*= //; s/ ms//')
  IFS=/ read MIN AVG MAX MDEV <<< "${STATS:-0/0/0/0}"

  echo "$SCEN,$ATT,$INT,$N,$r,$LOSS,$MIN,$AVG,$MAX,$MDEV" | tee -a "$OUT"
  [ "$ATT" != "none" ] && sleep 2   # laisse retomber avant la répétition suivante
done
