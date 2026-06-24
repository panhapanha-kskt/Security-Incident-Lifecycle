#Need to configure that file in this location: /var/ossec/active-response/bin/fim-respond.sh
#!/bin/bash
# FIM Respond — Wazuh Active Response
# Locks critical file with chattr +i to prevent further modification
# Triggered by rules 100117 (critical file modified) and 100123 (repeated mods)

LOG_FILE="/var/ossec/logs/active-responses.log"
ACTION=$1     # add or delete
USER=$2       # unused
IP=$3         # unused
ALERT_ID=$4
RULE_ID=$5

echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: action=$ACTION rule=$RULE_ID alert=$ALERT_ID" >> "$LOG_FILE"

if [[ "$ACTION" == /* ]]; then
    FILE_PATH="$ACTION"
    echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: [thehive] locking $FILE_PATH" >> "$LOG_FILE"
    chattr +i "$FILE_PATH" 2>> "$LOG_FILE"
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: SUCCESS — $FILE_PATH is now immutable" >> "$LOG_FILE"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: FAILED to lock $FILE_PATH" >> "$LOG_FILE"
        exit 1
    fi
    exit 0
fi

if [ "$ACTION" = "add" ]; then
    # Read alert JSON from stdin (Wazuh passes it)
    read -t 3 ALERT_JSON

    # Extract file path from syscheck.path in alert JSON
    FILE_PATH=$(echo "$ALERT_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    path = data.get('syscheck', {}).get('path', '')
    print(path)
except:
    print('')
" 2>/dev/null)

    if [ -z "$FILE_PATH" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: ERROR — could not extract file path from alert" >> "$LOG_FILE"
        exit 1
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: locking $FILE_PATH with chattr +i" >> "$LOG_FILE"
    chattr +i "$FILE_PATH" 2>> "$LOG_FILE"

    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: SUCCESS — $FILE_PATH is now immutable" >> "$LOG_FILE"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: FAILED to lock $FILE_PATH" >> "$LOG_FILE"
        exit 1
    fi

elif [ "$ACTION" = "delete" ]; then
    # Timeout expired — restore mutability (only if timeout > 0)
    read -t 3 ALERT_JSON
    FILE_PATH=$(echo "$ALERT_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('syscheck', {}).get('path', ''))
except:
    print('')
" 2>/dev/null)

    if [ -n "$FILE_PATH" ]; then
        chattr -i "$FILE_PATH" 2>> "$LOG_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: restored mutability on $FILE_PATH" >> "$LOG_FILE"
    fi
fi

exit 0
