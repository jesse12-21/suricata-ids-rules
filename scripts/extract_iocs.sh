#!/bin/bash
# extract_iocs.sh - Extract IOCs from Suricata alerts for sharing
#
# Parses Suricata EVE JSON output and produces a CSV of unique
# attacker IPs with their triggered signatures, categories, severity,
# first/last seen timestamps, and event counts.
#
# Suitable for sharing IOCs with threat intel platforms or other SOCs.
#
# Usage: ./extract_iocs.sh [path_to_eve.json]
# Example: ./extract_iocs.sh /var/log/suricata/eve.json

set -euo pipefail

EVE_LOG="${1:-/var/log/suricata/eve.json}"
OUTPUT="iocs_$(date +%Y%m%d_%H%M%S).csv"

if [ ! -f "$EVE_LOG" ]; then
    echo "Error: EVE log not found at $EVE_LOG"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Install with: sudo apt install jq"
    exit 1
fi

echo "==========================================="
echo "  Suricata IOC Extractor"
echo "==========================================="
echo "  Input:  $EVE_LOG"
echo "  Output: $OUTPUT"
echo ""

# CSV header
echo "src_ip,signature,category,severity,first_seen,last_seen,count" > "$OUTPUT"

# Extract and aggregate IOC data
jq -r 'select(.event_type=="alert") |
  [.src_ip, .alert.signature, .alert.category, .alert.severity, .timestamp]
  | @csv' "$EVE_LOG" 2>/dev/null | \
awk -F',' '{
  key=$1"|"$2"|"$3"|"$4
  if (!(key in first)) first[key]=$5
  last[key]=$5
  count[key]++
}
END {
  for (k in count) {
    split(k, parts, "|")
    print parts[1]","parts[2]","parts[3]","parts[4]","first[k]","last[k]","count[k]
  }
}' | sort -t',' -k7 -rn >> "$OUTPUT"

ENTRIES=$(($(wc -l < "$OUTPUT") - 1))

echo "Extraction complete."
echo "  Unique IOC entries: $ENTRIES"
echo ""

# Summary of extracted IOCs
if [ "$ENTRIES" -gt 0 ]; then
    echo "----- Top 10 Attacker IPs by Alert Count -----"
    awk -F',' 'NR>1 {ips[$1]+=$7} END {for (ip in ips) print ips[ip], ip}' "$OUTPUT" \
      | sort -rn | head -10

    echo ""
    echo "Full IOC export saved to: $OUTPUT"
else
    echo "No alerts found to extract."
fi

echo ""
echo "==========================================="
