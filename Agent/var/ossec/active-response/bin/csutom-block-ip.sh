#!/bin/bash
LOG_FILE="/var/ossec/logs/active-responses.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') custom-block-ip: $*" >> "$LOG_FILE"; }
read -r -t 5 INPUT_JSON
if [ -z "$INPUT_JSON" ]; then
    log "ERROR — no JSON received on stdin"
    exit 1
fi
log "raw_input=$INPUT_JSON"
COMMAND=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('command', ''))
except:
    print('')
" 2>/dev/null)
IP=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    args = d.get('parameters', {}).get('extra_args', [])
    print(args[0] if args else '')
except:
    print('')
" 2>/dev/null)

log "command=$COMMAND ip=$IP"
if [ -z "$IP" ]; then
    log "ERROR — no IP found in extra_args"
    exit 1
fi
if [ "$COMMAND" = "add" ]; then
    if iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
        log "SKIP — $IP already blocked"
    else
        iptables -I INPUT -s "$IP" -j DROP
        iptables -I OUTPUT -d "$IP" -j DROP
        log "SUCCESS — blocked $IP (INPUT+OUTPUT)"
    fi
elif [ "$COMMAND" = "delete" ]; then
    iptables -D INPUT -s "$IP" -j DROP 2>/dev/null
    iptables -D OUTPUT -d "$IP" -j DROP 2>/dev/null
    log "REMOVED block on $IP"
else
    log "ERROR — unknown command '$COMMAND'"
    exit 1
fi
exit 0
