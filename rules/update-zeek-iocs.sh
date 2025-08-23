#!/bin/bash
# rules/update-zeek-iocs.sh
# Converts ./rules/iocs.txt into a Zeek intelligence dat file.

INPUT_FILE="./rules/iocs.txt"
OUTPUT_FILE="./rules/zeek-iocs.dat"

echo "#fields indicator indicator_type meta.source meta.desc" > $OUTPUT_FILE

process_ioc() {
    local ioc="$1"
    local source="threat-hunt-kit"
    local desc="Manual IOC import"

    # Determine IOC type based on format
    if [[ $ioc =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ioc Intel::ADDR $source \"$desc\"" >> $OUTPUT_FILE
    elif [[ $ioc =~ ^[0-9a-fA-F]{32}$ || $ioc =~ ^[0-9a-fA-F]{40}$ || $ioc =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "$ioc Intel::FILE_HASH $source \"$desc\"" >> $OUTPUT_FILE
    elif [[ $ioc =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "$ioc Intel::DOMAIN $source \"$desc\"" >> $OUTPUT_FILE
    else
        echo "[!] Warning: Could not determine type for IOC: $ioc" >&2
    fi
}

# Read the iocs.txt file, skip comments and empty lines
while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^#.*$ ]] || [[ -z "$line" ]] && continue
    process_ioc "$line"
done < "$INPUT_FILE"

echo "[+] Zeek IOC file updated: $OUTPUT_FILE"