#!/bin/bash
# Configure on this location: /var/ossec/active-response/bin/fim-respond.sh
# Locks critical file with chattr +i
# Triggered by rules 100117 and 100123
LOG_FILE="/var/ossec/logs/active-responses.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: $*" >> "$LOG_FILE"; }
read -r -t 5 INPUT_JSON
if [ -z "$INPUT_JSON" ]; then
    log "ERROR — no JSON received on stdin"
    exit 1
fi
COMMAND=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('command', ''))
except:
    print('')
" 2>/dev/null)
FILE_PATH=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # Wazuh 4.x wraps in 'parameters.alert'
    alert = d.get('parameters', {}).get('alert', d)
    path = alert.get('syscheck', {}).get('path', '')
    print(path)
except:
    print('')
" 2>/dev/null)
RULE_ID=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    alert = d.get('parameters', {}).get('alert', d)
    print(alert.get('rule', {}).get('id', ''))
except:
    print('')
" 2>/dev/null)
AGENT_ID=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    alert = d.get('parameters', {}).get('alert', d)
    print(alert.get('agent', {}).get('id', ''))
except:
    print('')
" 2>/dev/null)
log "command=$COMMAND rule=$RULE_ID agent=$AGENT_ID file=$FILE_PATH"
log "raw_input=$INPUT_JSON"
if [ -z "$FILE_PATH" ]; then
    log "ERROR — could not extract file path from JSON"
    exit 1
fi
if [ "$COMMAND" = "add" ]; then
    log "locking $FILE_PATH with chattr +i"
    chattr +i "$FILE_PATH" 2>> "$LOG_FILE"
    if [ $? -eq 0 ]; then
        log "SUCCESS — $FILE_PATH is now immutable"
    else
        log "FAILED to lock $FILE_PATH (may already be immutable or path missing)"
        exit 1
    fi
elif [ "$COMMAND" = "delete" ]; then
    # timeout=0 in ossec.conf so this branch won't fire, but handle it anyway
    log "restoring mutability on $FILE_PATH"
    chattr -i "$FILE_PATH" 2>> "$LOG_FILE"
    log "done — $FILE_PATH is now mutable"
else
    log "ERROR — unknown command '$COMMAND'"
    exit 1
fi
exit 0
