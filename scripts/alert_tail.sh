#!/bin/bash
# alert_tail.sh - Real-time tail of high-severity Suricata alerts
#
# Continuously monitors the Suricata EVE log and displays high and
# medium severity alerts as they occur, formatted for SOC analyst
# consumption.
#
# Usage: ./alert_tail.sh [path_to_eve.json]
# Example: ./alert_tail.sh /var/log/suricata/eve.json
# Press Ctrl+C to stop.

set -euo pipefail

EVE_LOG="${1:-/var/log/suricata/eve.json}"

if [ ! -f "$EVE_LOG" ]; then
    echo "Error: EVE log not found at $EVE_LOG"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Install with: sudo apt install jq"
    exit 1
fi

echo "==========================================="
echo "  Suricata Real-Time Alert Monitor"
echo "==========================================="
echo "  Watching: $EVE_LOG"
echo "  Filter:   High and Medium severity only"
echo "  Press Ctrl+C to stop"
echo ""
echo "TIMESTAMP                    SEV  SRC_IP            DST_IP            SIGNATURE"
echo "------------------------------------------------------------------------------------"

tail -f "$EVE_LOG" | \
  jq -r --unbuffered 'select(.event_type=="alert" and .alert.severity<=2) |
    "\(.timestamp[:19])  [\(.alert.severity)]  \(.src_ip|tostring|.[0:15])  \(.dest_ip|tostring|.[0:15])  \(.alert.signature)"'
