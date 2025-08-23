#!/bin/bash
# scripts/live-capture.sh
echo "[*] Starting LIVE capture on interface: $INTERFACE"
docker compose run --rm sensor \
  /bin/bash -c "zeek -i $INTERFACE -C /etc/nsm-configs/zeek/local.zeek & suricata -c /etc/nsm-configs/suricata/suricata.yaml -i $INTERFACE"