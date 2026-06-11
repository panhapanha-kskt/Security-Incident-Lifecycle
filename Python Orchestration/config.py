# config.py – SOC Interceptor configuration
ALERT_FILE    = "/var/ossec/logs/alerts/alerts.json"
ARCHIVES_FILE = "/var/ossec/logs/archives/archives.json"
LOG_FILE      = "/home/wazuh-user/backup/log/interceptor.log"
DAY_TIMEZONE  = "Asia/Phnom_Penh"

POLL_INTERVAL = 0.1
DEDUP_WINDOW  = 30
BRUTE_FORCE_WINDOW = 300
CORRELATION_WINDOW = 300

FAILED_LOGIN_THRESHOLD = 5
SEVERE_THRESHOLD       = 10
CRITICAL_THRESHOLD     = 20

FAILED_LOGIN_RULES: set[str] = {
    "5503", "5710", "5712", "5715", "5716",
    "100105", "100116", "100901",
}

MIN_SEVERITY = "LOW"

CRITICAL_RULES: dict[str, str] = {
    "100666": "ACTIVE COMPROMISE – Criminal IP Critical + critical file modified",
    "100667": "ACTIVE EXPLOITATION – Criminal IP Critical + reverse shell confirmed",
    "100668": "POST-COMPROMISE MINER – Criminal IP Critical + crypto miner",
    "100650": "TOR + CRITICAL SCORE – TOR exit node with critical inbound risk",
    "100652": "SCANNER + CRITICAL SCORE – Known scanner critical inbound",
    "100654": "DARK WEB + SCANNER – Dark web IP actively scanning",
    "100655": "DARK WEB + CRITICAL SCORE – Dark web IP critical inbound",
    "100656": "SNORT + CRITICAL SCORE – Snort-flagged critical inbound",
    "100663": "INTERNAL HOST TO TOR – C2 channel suspected",
    "100123": "REPEATED CRITICAL FILE MODS – 3+ modifications in 300s",
}

HIGH_RULES: dict[str, str] = {
    "100117": "CRITICAL FILE MODIFIED – /etc/passwd, /etc/shadow, /etc/sudoers",
    "100119": "CRYPTO MINING TOOL – xmrig/minerd/cpuminer in process list",
    "100101": "REVERSE SHELL TOOL – msfconsole/meterpreter/nc -e detected",
    "100204": "NETWORK RELAY TOOL – netcat/ncat/socat in process list",
    "100700": "DDOS ATTACK – Suricata network flood detection",
    "100805": "SQL INJECTION VIA APACHE – union select / drop table",
    "100806": "SQL INJECTION VIA NGINX – union select / or 1=1",
    "100808": "WEB SCANNER – nikto/sqlmap/dirb/gobuster user-agent",
    "100628": "CRIMINAL IP CRITICAL INBOUND – rated Critical by Criminal IP",
    "100105": "MULTIPLE SSH FAILURES – 8 failures from same IP in 60s",
    "100901": "SSH BRUTE FORCE CONFIRMED – 5 failures same IP in 60s",
    "100106": "MULTIPLE FAILED SUDO – 5 priv-esc attempts in 120s",
    "100651": "TOR + DANGEROUS SCORE – TOR node with dangerous inbound",
    "100653": "SCANNER + DANGEROUS SCORE – Scanner with dangerous inbound",
    "100657": "ANONYMOUS VPN + CRITICAL – Anon VPN critical inbound",
    "100662": "OUTBOUND CRITICAL IP – Exfiltration to Critical-rated IP confirmed",
    "100664": "REPEATED DANGEROUS CRIMINAL IP – 3+ hits in 300s",
    "100665": "REPEATED CRITICAL CRIMINAL IP – 3+ hits in 300s",
    "100625": "TOR NODE DETECTED – IP associated with TOR network",
    "100907": "ZEEK SSL – Client connected to expired certificate server",
    "100904": "ZEEK PORT SCAN – 5+ rejected connections in 20s",
}

MEDIUM_RULES: dict[str, str] = {
    "5503":  "PAM authentication failure",
    "5710":  "SSH login attempt for non-existent user",
    "5712":  "SSH failed password for invalid user",
}

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Mapping
#
# Format: rule_id → [technique_ids...]
#
# Technique IDs reference MITRE ATT&CK Enterprise v14:
#   https://attack.mitre.org/
#
# Tactic IDs (TA00xx) are included alongside technique IDs where the tactic
# is the primary context (e.g. TA0011 = Command and Control).
#
# Mapping rationale per rule group:
#
#   File integrity (100117, 100123)
#     T1222  – File and Directory Permissions Modification
#     T1098  – Account Manipulation  (passwd/shadow edits grant persistence)
#     T1136  – Create Account        (new entries in /etc/passwd)
#     TA0005 – Defense Evasion       (hiding tracks via permission changes)
#
#   Credential / privilege-escalation brute force (5503, 5710, 5712, 5715,
#     5716, 100105, 100116, 100901, 100106)
#     T1110  – Brute Force
#     T1078  – Valid Accounts        (goal of brute force)
#     T1548  – Abuse Elevation Control Mechanism  (sudo abuse → 100106)
#     TA0006 – Credential Access
#
#   Reverse shell / C2 tooling (100101, 100663, 100667)
#     T1059  – Command and Scripting Interpreter  (shell spawned)
#     T1071  – Application Layer Protocol         (C2 channel)
#     T1572  – Protocol Tunneling                 (TOR C2)
#     TA0011 – Command and Control
#
#   Network relay tools (100204)
#     T1090  – Proxy
#     T1572  – Protocol Tunneling
#     TA0011 – Command and Control
#
#   Crypto mining (100119, 100668)
#     T1496  – Resource Hijacking
#     TA0040 – Impact
#
#   TOR / anonymisation network (100625, 100650, 100651, 100663)
#     T1090.003 – Proxy: Multi-hop Proxy  (TOR is a multi-hop proxy)
#     T1572     – Protocol Tunneling
#     TA0011    – Command and Control
#
#   Criminal IP / threat-intel inbound (100628, 100652, 100653, 100654,
#     100655, 100656, 100657, 100664, 100665)
#     T1190  – Exploit Public-Facing Application  (inbound exploitation attempt)
#     T1071  – Application Layer Protocol
#     TA0001 – Initial Access
#
#   Outbound exfiltration (100662, 100666)
#     T1041  – Exfiltration Over C2 Channel
#     T1048  – Exfiltration Over Alternative Protocol
#     TA0010 – Exfiltration
#
#   Web attacks – SQL injection (100805, 100806)
#     T1190  – Exploit Public-Facing Application
#     T1505.003 – Server Software Component: Web Shell (post-SQLi foothold)
#     TA0001 – Initial Access
#
#   Web scanner (100808)
#     T1595  – Active Scanning
#     T1592  – Gather Victim Host Information
#     TA0043 – Reconnaissance
#
#   DDoS (100700)
#     T1498  – Network Denial of Service
#     TA0040 – Impact
#
#   Zeek network detections (100904, 100907)
#     T1046  – Network Service Discovery  (port scan → 100904)
#     T1587.003 – Develop Capabilities: Digital Certificates  (expired cert → 100907)
#     TA0007 – Discovery
#
# ─────────────────────────────────────────────────────────────────────────────
MITRE_MAPPING: dict[str, list[str]] = {

    # ── File integrity monitoring ─────────────────────────────────────────
    # /etc/passwd, /etc/shadow, /etc/sudoers modified
    "100117": ["T1222", "T1098", "T1136", "TA0005"],

    # Repeated critical file modifications (3+ in 300 s)
    "100123": ["T1222", "T1098", "TA0005"],

    # ── Credential attacks & privilege escalation ─────────────────────────
    # PAM authentication failure
    "5503":   ["T1110", "T1078", "TA0006"],

    # SSH login attempt for non-existent user
    "5710":   ["T1110", "T1078", "TA0006"],

    # SSH failed password for invalid user
    "5712":   ["T1110", "T1078", "TA0006"],

    # SSH failed (Wazuh native rules referenced in FAILED_LOGIN_RULES)
    "5715":   ["T1110", "T1078", "TA0006"],
    "5716":   ["T1110", "T1078", "TA0006"],

    # Multiple SSH failures – 8 from same IP in 60 s
    "100105": ["T1110", "T1078", "TA0006"],

    # SSH brute force confirmed – 5 failures same IP in 60 s
    "100901": ["T1110", "T1078", "TA0006"],

    # Threshold rule referenced in FAILED_LOGIN_RULES
    "100116": ["T1110", "T1078", "TA0006"],

    # Multiple failed sudo – 5 priv-esc attempts in 120 s
    "100106": ["T1548", "T1078", "TA0004"],

    # ── Reverse shell & C2 tooling ────────────────────────────────────────
    # msfconsole / meterpreter / nc -e detected
    "100101": ["T1059", "T1071", "T1572", "TA0011"],

    # Internal host connecting to TOR (C2 channel suspected)
    "100663": ["T1090.003", "T1572", "T1071", "TA0011"],

    # Criminal IP Critical + reverse shell confirmed (composite)
    "100667": ["T1059", "T1071", "T1572", "TA0011"],

    # ── Network relay tools ───────────────────────────────────────────────
    # netcat / ncat / socat in process list
    "100204": ["T1090", "T1572", "TA0011"],

    # ── Crypto mining ─────────────────────────────────────────────────────
    # xmrig / minerd / cpuminer in process list
    "100119": ["T1496", "TA0040"],

    # Criminal IP Critical + crypto miner (composite)
    "100668": ["T1496", "T1190", "TA0040"],

    # ── TOR / anonymisation network ───────────────────────────────────────
    # IP associated with TOR network (first detection)
    "100625": ["T1090.003", "T1572", "TA0011"],

    # TOR exit node with critical inbound risk
    "100650": ["T1090.003", "T1572", "T1190", "TA0011"],

    # TOR node with dangerous inbound
    "100651": ["T1090.003", "T1572", "T1190", "TA0011"],

    # ── Criminal IP / threat-intel inbound ───────────────────────────────
    # Criminal IP Critical inbound
    "100628": ["T1190", "T1071", "TA0001"],

    # Known scanner – critical inbound
    "100652": ["T1595", "T1190", "TA0001"],

    # Scanner with dangerous inbound
    "100653": ["T1595", "T1190", "TA0001"],

    # Dark web IP actively scanning
    "100654": ["T1595", "T1090.003", "TA0043"],

    # Dark web IP – critical inbound
    "100655": ["T1190", "T1090.003", "TA0001"],

    # Snort-flagged critical inbound
    "100656": ["T1190", "T1071", "TA0001"],

    # Anonymous VPN – critical inbound
    "100657": ["T1090", "T1190", "TA0001"],

    # Repeated dangerous Criminal IP – 3+ hits in 300 s
    "100664": ["T1190", "T1071", "TA0001"],

    # Repeated critical Criminal IP – 3+ hits in 300 s
    "100665": ["T1190", "T1071", "TA0001"],

    # ── Outbound exfiltration ─────────────────────────────────────────────
    # Exfiltration to Critical-rated IP confirmed
    "100662": ["T1041", "T1048", "TA0010"],

    # Criminal IP Critical + critical file modified (composite: compromise + exfil)
    "100666": ["T1041", "T1222", "T1098", "TA0010"],

    # ── Web attacks ───────────────────────────────────────────────────────
    # SQL injection via Apache
    "100805": ["T1190", "T1505.003", "TA0001"],

    # SQL injection via Nginx
    "100806": ["T1190", "T1505.003", "TA0001"],

    # Web scanner (nikto / sqlmap / dirb / gobuster)
    "100808": ["T1595", "T1592", "TA0043"],

    # ── DDoS ──────────────────────────────────────────────────────────────
    # Suricata network flood detection
    "100700": ["T1498", "TA0040"],

    # ── Zeek network detections ───────────────────────────────────────────
    # Zeek port scan – 5+ rejected connections in 20 s
    "100904": ["T1046", "T1595", "TA0007"],

    # Zeek SSL – client connected to expired certificate server
    "100907": ["T1587.003", "T1071.001", "TA0006"],
}