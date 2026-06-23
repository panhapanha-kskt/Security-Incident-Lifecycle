# ASIL — Automated Security Incident Lifecycle
## Cortex + Wazuh + TheHive Integration Setup & Troubleshooting

**Project:** ASIL (Automated Security Incident Lifecycle)  
**Environment:** Techo Startup Center (TSC) SOC Lab  
**Stack:** Wazuh 4.x · TheHive 5 · Cortex 4.0 · MISP · Gmail alerting  
**Infrastructure:**
- Wazuh Manager: `192.168.200.129` (Amazon Linux 2023)
- TheHive + Cortex + MISP: `172.24.80.95` (Docker)
- Kali Agent: `192.168.200.128` (Agent ID: 006)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Cortex Analyzer Fix — VirusTotal filetype Module](#cortex-analyzer-fix--virustotal-filetype-module)
3. [Cortex Responder — WazuhFIM_1_0](#cortex-responder--wazuhfim_1_0)
4. [Cortex Responder — Wazuh_1_0 (IP Block)](#cortex-responder--wazuh_10-ip-block)
5. [Wazuh Active Response — fim-respond.sh](#wazuh-active-response--fim-respondsh)
6. [Wazuh ossec.conf Active Response Config](#wazuh-ossecconf-active-response-config)
7. [Simulation Scenarios](#simulation-scenarios)
8. [Verification](#verification)
9. [Known Issues & Fixes](#known-issues--fixes)

---

## Architecture Overview

```
Attack/Event on Kali Agent (192.168.200.128)
        │
        ▼
Wazuh Agent (Agent-Kali, ID: 006)
        │  detects rule → sends alert to manager
        ▼
Wazuh Manager (192.168.200.129)
        │
        ├──► PATH A (Automatic): fires active-response directly to agent
        │         firewall-drop / fim-respond
        │
        └──► PATH B (Via Integration): custom-w2thive.py
                  │
                  ▼
             TheHive 5 (172.24.80.95:8443)
                  │  case created → SOC analyst triggers responder
                  ▼
             Cortex 4.0 (172.24.80.95:9443)
                  │  WazuhFIM_1_0 / Wazuh_1_0
                  ▼
             Wazuh REST API (192.168.200.129:55000)
                  │  PUT /active-response
                  ▼
             Kali Agent executes fim-respond.sh / firewall-drop
```

---

## Cortex Analyzer Fix — VirusTotal filetype Module

### Problem
```json
{
  "errorMessage": "ModuleNotFoundError: No module named 'filetype'",
  "success": false
}
```

### Root Cause
The `filetype` Python package was listed in `VirusTotal/requirements.txt` but not installed inside the Cortex Docker container.

### Fix
```bash
# Find the Cortex container
docker ps | grep -i cortex

# Install missing package as root inside container
docker exec -it -u root cortex pip install filetype --break-system-packages
```

### Notes
- The container runs as a non-root user by default — `-u root` is required
- `python-magic` and `vt-py` were already installed; only `filetype` was missing
- The Cortex healthcheck shows `(unhealthy)` because it hits `/cortex/api/status` (wrong path) — the correct path is `/api/status`. Cortex is actually healthy; this is a misconfigured healthcheck in `docker-compose.yml`

---

## Cortex Responder — WazuhFIM_1_0

### Purpose
Fires the `fim-respond` active response on a Wazuh agent when a TheHive case is triggered by rule 100117 (critical file modified) or 100123 (repeated modifications).

### Files
```
cortex/neurons/responders/WazuhFIM/
├── WazuhFIM.json
└── wazuh_fim.py
```

### WazuhFIM.json
```json
{
  "name": "WazuhFIM_1_0",
  "version": "1.0",
  "author": "NhaKachh",
  "license": "AGPL-V3",
  "description": "Wazuh FIM Responder — lock critical files on repeated mods",
  "dataTypeList": ["thehive:case"],
  "command": "WazuhFIM/wazuh_fim.py",
  "baseConfig": "WazuhFIM",
  "configurationItems": [
    { "name": "wazuh_manager", "type": "string", "required": true },
    { "name": "wazuh_user",    "type": "string", "required": true },
    { "name": "wazuh_password","type": "string", "required": true }
  ]
}
```

### Issues Encountered & Fixes

| Issue | Error | Fix |
|-------|-------|-----|
| Wrong command path | `Cannot run program "/opt/cortexneurons/responders/python3 wazuh_fim.py"` | Changed `"command"` from `"python3 wazuh_fim.py"` to `"WazuhFIM/wazuh_fim.py"` |
| Script not executable | `error=13, Permission denied` | `docker exec -it -u root cortex chmod +x /opt/cortexneurons/responders/WazuhFIM/wazuh_fim.py` |
| Wrong auth method | Token request failing | Changed `requests.post` to `requests.get` for Wazuh JWT auth endpoint |
| Cortex cached old command | Still running old path after JSON fix | Disable → Enable responder in Cortex UI to flush cache |

### Deploying Updates to Container
```bash
# After editing on host, copy into container
docker cp WazuhFIM.json cortex:/opt/cortexneurons/responders/WazuhFIM/WazuhFIM.json
docker cp wazuh_fim.py  cortex:/opt/cortexneurons/responders/WazuhFIM/wazuh_fim.py

# Fix permissions
docker exec -it -u root cortex chmod +x /opt/cortexneurons/responders/WazuhFIM/wazuh_fim.py

# Restart to pick up JSON changes
docker restart cortex

# Then in Cortex UI: Organization → Responders → WazuhFIM_1_0 → Disable → Enable
```

### wazuh_fim.py — Key Logic
- Authenticates to Wazuh REST API via `GET /security/user/authenticate`
- Fires `fim-respond0` AR command via `PUT /active-response?agents_list=<agent_id>`
- Extracts `file_path` from the TheHive case description (parses raw log line)
- Extracts `rule_id` and `agent_id` from case custom fields
- Only processes rules `100117` and `100123`

### Successful Job Output
```json
{
  "message": "fim-respond AR executed successfully",
  "rule_id": "100117",
  "agent_id": "006",
  "file_path": "/etc/sudoers",
  "wazuh_api_response": {
    "data": {
      "affected_items": ["006"],
      "total_affected_items": 1,
      "total_failed_items": 0
    },
    "message": "AR command was sent to all agents",
    "error": 0
  },
  "success": true
}
```

---

## Cortex Responder — Wazuh_1_0 (IP Block)

### Purpose
Blocks a source IP via `firewall-drop` active response on a Wazuh agent. Triggered manually from a TheHive case that contains a valid Source IP in the description table.

### Requirement
The TheHive case description **must** contain a real Source IP in the markdown table:
```
| Source IP   | 192.168.200.1 |
```
Cases with `Source IP: N/A` (e.g. FIM alerts) will always fail this responder — use WazuhFIM_1_0 for those instead.

### Applicable Rules
Rules that produce a Source IP in the case: `5710`, `5712`, `5503`, `100200`, `100904`, `100901`

### wazuh.py — Key Logic
- Parses Source IP from case description using regex
- Authenticates via `GET /security/user/authenticate`
- Fires `!firewall-drop` AR via `PUT /active-response?agents_list=<agent_id>`
- Tags case with `Wazuh: Blocked IP` on success

---

## Wazuh Active Response — fim-respond.sh

### Location on Agent
```
/var/ossec/active-response/bin/fim-respond.sh
```

### Permissions
```bash
chmod 750 /var/ossec/active-response/bin/fim-respond.sh
chown root:wazuh /var/ossec/active-response/bin/fim-respond.sh
```

### Script
```bash
#!/bin/bash
# FIM Respond — Wazuh Active Response (4.x compatible)
# Locks critical file with chattr +i to prevent further modification
LOG_FILE="/var/ossec/logs/active-responses.log"

# Wazuh 4.x passes everything via stdin as JSON
read -t 5 INPUT_JSON

ACTION=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command',''))" 2>/dev/null)
RULE_ID=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('alert',{}).get('rule',{}).get('id',''))" 2>/dev/null)
FILE_PATH=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('alert',{}).get('syscheck',{}).get('path',''))" 2>/dev/null)

echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: action=$ACTION rule=$RULE_ID file=$FILE_PATH" >> "$LOG_FILE"

if [ "$ACTION" = "add" ]; then
    if [ -z "$FILE_PATH" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: ERROR — no file path in alert" >> "$LOG_FILE"
        exit 1
    fi
    chattr +i "$FILE_PATH" 2>> "$LOG_FILE"
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: SUCCESS — $FILE_PATH is now immutable" >> "$LOG_FILE"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: FAILED to lock $FILE_PATH" >> "$LOG_FILE"
        exit 1
    fi
elif [ "$ACTION" = "delete" ]; then
    if [ -n "$FILE_PATH" ]; then
        chattr -i "$FILE_PATH" 2>> "$LOG_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') fim-respond: restored mutability on $FILE_PATH" >> "$LOG_FILE"
    fi
fi
exit 0
```

### Important Note — Wazuh 4.x AR Input Format
Wazuh 4.x does **not** pass positional arguments to AR scripts. Everything is passed via **stdin as JSON**. Old-style scripts using `$1 $2 $3` positional args will receive empty values. Always read from stdin.

---

## Wazuh ossec.conf Active Response Config

### Manager Side (`/var/ossec/etc/ossec.conf` on Wazuh server)
```xml
<!-- Register fim-respond command -->
<command>
  <name>fim-respond</name>
  <executable>fim-respond.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Auto-fire fim-respond on critical file modification rules -->
<active-response>
  <command>fim-respond</command>
  <location>local</location>
  <rules_id>100117,100123</rules_id>
  <timeout>0</timeout>
</active-response>

<!-- Auto-fire firewall-drop on brute force / attack rules -->
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5712,5763,100200,100904,651,5758,5503</rules_id>
  <timeout>180</timeout>
</active-response>
```

### Agent Side (`/var/ossec/etc/ossec.conf` on Kali)
```xml
<!-- CA verification -->
<active-response>
  <disabled>no</disabled>
  <ca_store>etc/wpk_root.pem</ca_store>
  <ca_verification>yes</ca_verification>
</active-response>

<!-- Firewall drop -->
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>651,5503,5710,5712,5715,5716,5758,5763,100101,100105,100106,100119,100200,100204,100625,100628,100700,100805,100806,100808,100901,100904,100907</rules_id>
  <timeout>180</timeout>
</active-response>

<!-- FIM respond -->
<active-response>
  <disabled>no</disabled>
  <command>fim-respond</command>
  <location>local</location>
  <rules_id>100117,100123</rules_id>
  <timeout>0</timeout>
</active-response>
```

---

## Simulation Scenarios

### Scenario 1 — Critical File Modification (FIM)

**Trigger:**
```bash
# On Kali — unlock first if previously locked
chattr -i /etc/sudoers 2>/dev/null

# Modify the file to trigger rule 100117
touch /etc/sudoers

# Repeat 3 times within 5 minutes to trigger rule 100123
touch /etc/sudoers
touch /etc/sudoers
```

**Detection Chain:**
```
touch /etc/sudoers
    → Wazuh syscheck realtime → rule 100117 (HIGH)
    → PATH A: fim-respond AR fires automatically on agent
    → PATH B: TheHive case created → run WazuhFIM_1_0 in Cortex
    → /etc/sudoers locked with chattr +i
```

**Verify:**
```bash
# On Kali
lsattr /etc/sudoers
# Expected: ----i-------------- /etc/sudoers

chattr -i /etc/sudoers
# Expected: Operation not permitted

tail -f /var/ossec/logs/active-responses.log
```

---

### Scenario 2 — SSH Brute Force (IP Block)

**Trigger:**
```bash
# From WSL/attacker machine against Kali
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.200.128 -t 16 -f

# Or manual rapid failures
for i in {1..15}; do
  ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no \
    -o BatchMode=yes wronguser@192.168.200.128 2>/dev/null
  sleep 0.5
done
```

**Detection Chain:**
```
SSH failures
    → Wazuh rule 5503/5710/5712 fires
    → PATH A: firewall-drop AR fires automatically (180s timeout)
    → PATH B: TheHive case created with Source IP → run Wazuh_1_0 in Cortex
    → attacker IP blocked via iptables DROP
```

**Verify:**
```bash
# On Kali — check iptables
iptables -L INPUT -n | grep <attacker_ip>
# Expected: DROP rule for attacker IP

# From attacker machine — should timeout
ping -c 3 192.168.200.128
ssh root@192.168.200.128

# Block auto-removes after 180 seconds
# Manual unblock:
iptables -D INPUT -s <attacker_ip> -j DROP
```

---

## Verification

### Check Cortex Container Status
```bash
docker ps | grep cortex
docker logs cortex --tail 50
```

### Check Installed Packages in Cortex
```bash
docker exec -it cortex pip list | grep -E "filetype|cortexutils|vt-py|python-magic"
```

### Check Responder Files in Container
```bash
docker exec -it cortex ls -la /opt/cortexneurons/responders/WazuhFIM/
docker exec -it cortex ls -la /opt/cortexneurons/responders/Wazuh/
```

### Check AR Log on Kali
```bash
tail -f /var/ossec/logs/active-responses.log
```

### Check Wazuh Manager AR Log
```bash
grep "fim-respond\|firewall-drop" /var/ossec/logs/active-responses.log
```

### Watch Alerts in Real Time
```bash
tail -f /var/ossec/logs/alerts/alerts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line)
        rid = a['rule']['id']
        if rid in ('5710','5712','100117','100123','100300','100901'):
            src = a.get('data',{}).get('srcip','N/A')
            print(f'RULE {rid} — {a[\"rule\"][\"description\"]} — SRC: {src}')
    except: pass
"
```

---

## Known Issues & Fixes

| Issue | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: No module named 'filetype'` | Package not installed in Cortex container | `docker exec -it -u root cortex pip install filetype --break-system-packages` |
| `Cannot run program "python3 wazuh_fim.py": error=2` | Wrong `command` field in `WazuhFIM.json` | Change to `"WazuhFIM/wazuh_fim.py"` |
| `Permission denied error=13` on wazuh_fim.py | Script not executable | `docker exec -it -u root cortex chmod +x /opt/cortexneurons/responders/WazuhFIM/wazuh_fim.py` |
| Cortex still using old cached command after JSON fix | Cortex caches responder definitions at startup | Disable → Enable responder in Cortex UI |
| `pip install` fails with `OSError: Permission denied /opt/cortex/.local` | Running as non-root user | Use `docker exec -it -u root cortex pip install ...` |
| Cortex shows `(unhealthy)` in `docker ps` | Healthcheck hits `/cortex/api/status` (wrong path) | Cosmetic issue only — Cortex is healthy. Fix healthcheck URL in `docker-compose.yml` to `/api/status` |
| AR script gets empty `action=`, `rule=` values | Old positional-arg style — Wazuh 4.x uses stdin JSON | Rewrite script to `read` from stdin and parse JSON |
| `Wazuh_1_0` responder fails on FIM cases | Source IP is `N/A` in FIM alerts | Use `WazuhFIM_1_0` for FIM rules; `Wazuh_1_0` only works when a real Source IP exists |

---

## Responder Mapping

| Wazuh Rule | Description | Auto AR | Cortex Responder |
|-----------|-------------|---------|-----------------|
| 100117 | Critical file modified | fim-respond (chattr +i) | WazuhFIM_1_0 |
| 100123 | Repeated critical file mods | fim-respond (chattr +i) | WazuhFIM_1_0 |
| 5710 | SSH brute force | firewall-drop | Wazuh_1_0 |
| 5712 | SSH auth failure | firewall-drop | Wazuh_1_0 |
| 5503 | PAM login failed | firewall-drop | Wazuh_1_0 |
| 100200 | AlienVault blacklist hit | firewall-drop | Wazuh_1_0 |
| 100904 | Port scan detected | firewall-drop | Wazuh_1_0 |
| 100901 | SSH brute force confirmed | firewall-drop | Wazuh_1_0 |

---

*ASIL Project - Cambodia Academy of Digital Technology*
