#!/bin/bash
THEHIVE_URL="https://172.24.80.95:8443"
THEHIVE_KEY="Bearer Your-TheHive-API-Key"
MISP_URL="https://172.24.80.95:9001"
MISP_KEY="Your-MISP-API-Key"
echo "[*] Querying all cases from TheHive..."
CASES_JSON=$(curl -k -XPOST -s \
     -H "Authorization: $THEHIVE_KEY" \
     -H "Content-Type: application/json" \
     "$THEHIVE_URL/api/v1/query" \
     -d '{"query": [{"_name": "listCase"}]}')

if [ -z "$CASES_JSON" ] || [ "$CASES_JSON" == "[]" ]; then
    echo "[-] No cases found or failed to authenticate with TheHive."
    exit 1
fi
TOTAL_CASES=$(echo "$CASES_JSON" | jq '. | length')
echo "[+] Found $TOTAL_CASES cases to sync to MISP."
misp_event_exists_for_case() {
    local case_id="$1"
    local marker="TheHive ID: ${case_id})"
    local search_payload
    search_payload=$(jq -n --arg info "$marker" \
        '{"returnFormat":"json","eventinfo":$info,"metadata":1,"limit":10}')
    local resp
    resp=$(curl -k -XPOST -s \
        -H "Authorization: $MISP_KEY" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        "$MISP_URL/events/restSearch" \
        -d "$search_payload")
    echo "$resp" | jq -r --arg marker "$marker" '
        (.response // .)
        | (if type == "array" then . else (.Event // []) end)
        | map(.Event // .)
        | map(select((.info // "") | contains($marker)))
        | .[0].id // empty
    ' 2>/dev/null
}
for ((i=0; i<$TOTAL_CASES; i++)); do
    CASE_ID=$(echo "$CASES_JSON" | jq -r ".[$i]._id")
    TITLE=$(echo "$CASES_JSON" | jq -r ".[$i].title")
    DESC=$(echo "$CASES_JSON" | jq -r ".[$i].description // \"No description provided\"")
    SEVERITY=$(echo "$CASES_JSON" | jq -r ".[$i].severity // 2")
    echo "--------------------------------------------------------"
    echo "[*] Checking Case ID: $CASE_ID — $TITLE"
    EXISTING_ID=$(misp_event_exists_for_case "$CASE_ID")
    if [ -n "$EXISTING_ID" ] && [ "$EXISTING_ID" != "null" ]; then
        echo "[·] Already synced — MISP Event ID $EXISTING_ID exists for this case. Skipping."
        continue
    fi
    echo "[*] No existing MISP event found — creating new one."
    THREAT_LEVEL=4
    if [ "$SEVERITY" == "3" ] || [ "$SEVERITY" == "HIGH" ]; then THREAT_LEVEL=1; fi
    if [ "$SEVERITY" == "2" ] || [ "$SEVERITY" == "MEDIUM" ]; then THREAT_LEVEL=2; fi
    if [ "$SEVERITY" == "1" ] || [ "$SEVERITY" == "LOW" ]; then THREAT_LEVEL=3; fi
    MISP_PAYLOAD=$(jq -n \
        --arg info "$TITLE (TheHive ID: $CASE_ID)" \
        --arg desc "$DESC" \
        --arg tl "$THREAT_LEVEL" \
        '{
            "Event": {
                "info": $info,
                "threat_level_id": $tl,
                "analysis": "2",
                "distribution": "0",
                "comment": $desc
            }
        }')
    RESPONSE=$(curl -k -XPOST -s -w "\n%{http_code}" \
         -H "Authorization: $MISP_KEY" \
         -H "Accept: application/json" \
         -H "Content-Type: application/json" \
         "$MISP_URL/events/add" \
         -d "$MISP_PAYLOAD")
    HTTP_BODY=$(echo "$RESPONSE" | sed '$d')
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "201" ]; then
        MISP_ID=$(echo "$HTTP_BODY" | jq -r '.Event.id // "Unknown"')
        echo "[+] Success! MISP Event Created with MISP ID: $MISP_ID (HTTP $HTTP_CODE)"
    else
        echo "[-] Failed to push to MISP API (HTTP $HTTP_CODE)"
        echo "[-] Error Details: $HTTP_BODY"
    fi
done
echo "--------------------------------------------------------"
echo "[+] Sync completed (existing cases skipped, new cases created)."
