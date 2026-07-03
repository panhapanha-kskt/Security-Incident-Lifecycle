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

MALWARE_HASH_RULES: set[str] = {
    "110002", "110003", "110004",
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

MITRE_MAPPING: dict[str, list[str]] = {
    "100117": ["T1222", "T1098", "T1136", "TA0005"],
    "100123": ["T1222", "T1098", "TA0005"],
    "5503":   ["T1110", "T1078", "TA0006"],
    "5710":   ["T1110", "T1078", "TA0006"],
    "5712":   ["T1110", "T1078", "TA0006"],
    "5715":   ["T1110", "T1078", "TA0006"],
    "5716":   ["T1110", "T1078", "TA0006"],
    "100105": ["T1110", "T1078", "TA0006"],
    "100901": ["T1110", "T1078", "TA0006"],
    "100116": ["T1110", "T1078", "TA0006"],
    "100106": ["T1548", "T1078", "TA0004"],
    "100101": ["T1059", "T1071", "T1572", "TA0011"],
    "100663": ["T1090.003", "T1572", "T1071", "TA0011"],
    "100667": ["T1059", "T1071", "T1572", "TA0011"],
    "100204": ["T1090", "T1572", "TA0011"],
    "100119": ["T1496", "TA0040"],
    "100668": ["T1496", "T1190", "TA0040"],
    "100625": ["T1090.003", "T1572", "TA0011"],
    "100650": ["T1090.003", "T1572", "T1190", "TA0011"],
    "100651": ["T1090.003", "T1572", "T1190", "TA0011"],
    "100628": ["T1190", "T1071", "TA0001"],
    "100652": ["T1595", "T1190", "TA0001"],
    "100653": ["T1595", "T1190", "TA0001"],
    "100654": ["T1595", "T1090.003", "TA0043"],
    "100655": ["T1190", "T1090.003", "TA0001"],
    "100656": ["T1190", "T1071", "TA0001"],
    "100657": ["T1090", "T1190", "TA0001"],
    "100664": ["T1190", "T1071", "TA0001"],
    "100665": ["T1190", "T1071", "TA0001"],
    "100662": ["T1041", "T1048", "TA0010"],
    "100666": ["T1041", "T1222", "T1098", "TA0010"],
    "100805": ["T1190", "T1505.003", "TA0001"],
    "100806": ["T1190", "T1505.003", "TA0001"],
    "100808": ["T1595", "T1592", "TA0043"],
    "100700": ["T1498", "TA0040"],
    "100904": ["T1046", "T1595", "TA0007"],
    "100907": ["T1587.003", "T1071.001", "TA0006"],
}
