#!/bin/bash

# Använd absolut sökväg baserat på script-placeringen
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/../data"

output="$DATA_DIR/linux_processes.json"
logfile="$DATA_DIR/anomalies.log"

# Skapa data-mappen om den inte finns
mkdir -p "$DATA_DIR"

log() {
  echo "$(date) - $1" | tee -a "$logfile"
}

# Hämta processlista
processes=$(ps -eo comm --no-headers)

# Riskprocesser
risk=("nc" "netcat" "hydra" "john")

# Skapa JSON
echo '{ "processes": [' > "$output"

first=true
for p in $processes; do
  if [ "$first" = true ]; then
    first=false
  else
    echo ',' >> "$output"
  fi
  # Sanitize JSON by escaping special characters
  sanitized_name=$(echo "$p" | sed 's/\\/\\\\/g; s/"/\\"/g')
  echo "  { \"name\": \"$sanitized_name\" }" >> "$output"
done

echo ']}' >> "$output"

# Detektera riskprocesser
for r in "${risk[@]}"; do
  if echo "$processes" | grep -q "$r"; then
    log "VARNING – Riskprocess upptäckt: $r"
  fi
done

log "Linux-kontroll klar."
