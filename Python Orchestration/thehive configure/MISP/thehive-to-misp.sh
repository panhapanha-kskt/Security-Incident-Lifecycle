#!/bin/bash
THEHIVE_URL="https://172.24.80.95:8443"
THEHIVE_KEY="Bearer SSZNE7qtAl6iBJNhls4Pvvt/iDuu7e+Y"
MISP_URL="https://172.24.80.95:9001"
MISP_KEY="Co5rx7Fnye9TEfSp1q6cZmIUiKn4XXI2M0Ize6lI" 
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
echo "[+] Found $TOTAL_CASES cases to transfer directly to MISP API."
for ((i=0; i<$TOTAL_CASES; i++)); do
    CASE_ID=$(echo "$CASES_JSON" | jq -r ".[$i]._id")
    TITLE=$(echo "$CASES_JSON" | jq -r ".[$i].title")
    DESC=$(echo "$CASES_JSON" | jq -r ".[$i].description // \"No description provided\"")
    SEVERITY=$(echo "$CASES_JSON" | jq -r ".[$i].severity // 2")
    echo "--------------------------------------------------------"
    echo "[*] Direct Syncing Case ID: $CASE_ID"
    echo "[*] Title: $TITLE"
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
        echo "[+] Success! Direct MISP Event Created with MISP ID: $MISP_ID (HTTP $HTTP_CODE)"
    else
        echo "[-] Failed to push to MISP API (HTTP $HTTP_CODE)"
        echo "[-] Error Details: $HTTP_BODY"
    fi
done
echo "--------------------------------------------------------"
echo "[+] Direct API bulk duplication completed."
