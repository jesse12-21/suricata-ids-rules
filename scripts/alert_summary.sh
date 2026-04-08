#!/bin/bash
# alert_summary.sh - Generate executive summary of Suricata alerts
#
# Parses Suricata's EVE JSON output and produces a human-readable
# summary including alert counts by severity, top signatures, top
# source IPs, and category breakdowns.
#
# Usage: ./alert_summary.sh [path_to_eve.json]
# Example: ./alert_summary.sh /var/log/suricata/eve.json

set -euo pipefail

EVE_LOG="${1:-/var/log/suricata/eve.json}"

if [ ! -f "$EVE_LOG" ]; then
    echo "Error: EVE log not found at $EVE_LOG"
    echo "Usage: $0 [path_to_eve.json]"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Install with: sudo apt install jq"
    exit 1
fi

echo "==========================================="
echo "  Suricata Alert Summary"
echo "==========================================="
echo "  Source:    $EVE_LOG"
echo "  Generated: $(date)"
echo ""

# Total alert counts by severity
TOTAL=$(jq -r 'select(.event_type=="alert")' "$EVE_LOG" 2>/dev/null | wc -l)
HIGH=$(jq -r 'select(.event_type=="alert" and .alert.severity==1)' "$EVE_LOG" 2>/dev/null | wc -l)
MED=$(jq -r 'select(.event_type=="alert" and .alert.severity==2)' "$EVE_LOG" 2>/dev/null | wc -l)
LOW=$(jq -r 'select(.event_type=="alert" and .alert.severity==3)' "$EVE_LOG" 2>/dev/null | wc -l)

echo "Alert Counts by Severity:"
echo "  Total alerts:      $TOTAL"
echo "  High severity:     $HIGH"
echo "  Medium severity:   $MED"
echo "  Low severity:      $LOW"
echo ""

if [ "$TOTAL" -eq 0 ]; then
    echo "No alerts found in log file."
    exit 0
fi

echo "----- Top 10 Alert Signatures -----"
jq -r 'select(.event_type=="alert") | .alert.signature' "$EVE_LOG" 2>/dev/null \
  | sort | uniq -c | sort -rn | head -10

echo ""
echo "----- Top 10 Source IPs -----"
jq -r 'select(.event_type=="alert") | .src_ip' "$EVE_LOG" 2>/dev/null \
  | sort | uniq -c | sort -rn | head -10

echo ""
echo "----- Top 10 Destination IPs -----"
jq -r 'select(.event_type=="alert") | .dest_ip' "$EVE_LOG" 2>/dev/null \
  | sort | uniq -c | sort -rn | head -10

echo ""
echo "----- Alert Categories -----"
jq -r 'select(.event_type=="alert") | .alert.category' "$EVE_LOG" 2>/dev/null \
  | sort | uniq -c | sort -rn

echo ""
echo "----- Time Range -----"
FIRST=$(jq -r 'select(.event_type=="alert") | .timestamp' "$EVE_LOG" 2>/dev/null | head -1)
LAST=$(jq -r 'select(.event_type=="alert") | .timestamp' "$EVE_LOG" 2>/dev/null | tail -1)
echo "  First alert: $FIRST"
echo "  Last alert:  $LAST"

echo ""
echo "==========================================="
