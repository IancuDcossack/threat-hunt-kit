#!/bin/bash
# scripts/pcap-analysis.sh
PCAP_FILE=${1:-/opt/pcaps/capture.pcap}

if [ ! -f "$PCAP_FILE" ]; then
    echo "[!] Error: PCAP file $PCAP_FILE not found."
    echo "    Place PCAPs in the ./pcaps/ directory."
    exit 1
fi

echo "[*] Analyzing PCAP: $PCAP_FILE"
docker compose run --rm sensor \
  /bin/bash -c "zeek -C -r $PCAP_FILE && suricata -c /etc/nsm-configs/suricata/suricata.yaml -r $PCAP_FILE"
echo "[+] Analysis complete. Check ./logs/ for Zeek and Suricata outputs."