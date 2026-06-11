# SOC Attack Simulation Guide
**For official SOC lab use only — controlled environment**

---
### Proof of Concept for SOC Lab
<img width="2559" height="1599" alt="image" src="https://github.com/user-attachments/assets/a51f739b-2e80-426b-992b-f691ca54a385" />

## Prerequisites

### 1. Wazuh Manager
Ensure `thehive-intercept.py` is running on the manager:
```bash
cd /root/Wazuh-Part/thehive-configure
export THEHIVE_KEY="your-key"
export GMAIL_USER="your-gmail"
export GMAIL_PASS="your-app-password"
export ALERT_TO="your-recipient"
python3 thehive-intercept.py
```

### 2. Wazuh Agent (Kali)
Confirm agent is connected:
```bash
sudo systemctl status wazuh-agent
```

### 3. Deploy Zeek First (Required for DNS/Network Simulations)
> ⚠️ **You must deploy and start Zeek before running any network-based simulations.**
> Without Zeek running, DNS and port scan detections will not fire.

```bash
# Check if Zeek is running
sudo zeekctl status

# If not running, deploy first
sudo zeekctl deploy

# Confirm logs are being written
ls /opt/zeek/logs/current/
```

---

## Monitoring Setup

Open 3 terminals before starting any simulation:

**Terminal 1 — Python interceptor (manager):**
```bash
cd /root/Wazuh-Part/thehive-configure
python3 thehive-intercept.py
```

**Terminal 2 — Raw alerts (manager):**
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

**Terminal 3 — Active response log (Kali agent):**
```bash
sudo tail -f /var/ossec/logs/active-responses.log
```

---

## CRITICAL Simulations

### SIM-C1 — SSH Brute Force (Rule 100901)
**MITRE:** T1110, T1078, TA0006
**Triggers:** `FAILED_LOGIN_RULES` → escalation → `100901`

```bash
# On Kali agent
hydra -L /tmp/userlist.txt -P /tmp/passlist.txt ssh://127.0.0.1 -t 4 -V
```

Wordlists if not created:
```bash
cat > /tmp/userlist.txt << 'WEOF'
root
admin
user
test
kali
ubuntu
guest
oracle
postgres
ftp
WEOF

cat > /tmp/passlist.txt << 'WEOF'
123456
password
admin
root
test123
qwerty
letmein
welcome
abc123
toor
WEOF
```

**Expected:**
```
RULE: 100901  Level: 12  CRITICAL
SSH BRUTE FORCE CONFIRMED — 5 failures same IP in 60s
→ TheHive case created
→ Gmail alert sent
→ firewall-drop blocks 127.0.0.1
```

---

### SIM-C2 — Repeated Critical File Modifications (Rule 100123)
**MITRE:** T1222, T1098, TA0005
**Triggers:** 3x rule `100117` within 300s → `100123`

```bash
# On Kali agent — run 3 times within 5 minutes
sudo touch /etc/passwd && sleep 5
sudo touch /etc/passwd && sleep 5
sudo touch /etc/passwd
```

**Expected:**
```
RULE: 100117  Level: 12  HIGH    ← first touch
RULE: 100117  Level: 12  HIGH    ← second touch
RULE: 100123  Level: 15  CRITICAL ← third touch triggers correlation
REPEATED CRITICAL FILE MODS — 3+ modifications in 300s
```

---

### SIM-C3 — BRUTE_THEN_ROOT Correlation (Correlator)
**MITRE:** T1110 + T1548, TA0006
**Triggers:** `100901` + `100106` on same agent within 300s

```bash
# Step 1 — Run SSH brute force (SIM-C1 above)
hydra -L /tmp/userlist.txt -P /tmp/passlist.txt ssh://127.0.0.1 -t 4 -V &

# Step 2 — Immediately trigger sudo failures
for i in {1..6}; do sudo -k; sudo -u nobody whoami 2>/dev/null; done
```

**Expected:**
```
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
[CORRELATION ALERT]  CRITICAL  BRUTE_THEN_ROOT
DETAIL: SSH brute-force confirmed + privilege escalation attempt
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
```

---

## HIGH Simulations

### SIM-H1 — Critical File Modified (Rule 100117)
**MITRE:** T1222, T1098, T1136

```bash
# On Kali agent
sudo touch /etc/passwd
sudo touch /etc/shadow
sudo touch /etc/sudoers
Noted: for perform critical alert: touch /etc/passwd for 2 or 3 times between 3 minutes.
```

**Expected:**
```
RULE: 100117  Level: 12  HIGH
CRITICAL FILE MODIFIED — /etc/passwd, /etc/shadow, /etc/sudoers
→ TheHive case created
→ Gmail alert sent
```

---

### SIM-H2 — Crypto Mining Tool Detected (Rule 100119)
**MITRE:** T1496, TA0040

```bash
# On Kali agent — fake xmrig binary
cp /bin/sleep /tmp/xmrig
/tmp/xmrig 120 &
sleep 65  # wait for syscollector scan
kill %1
rm /tmp/xmrig
```

**Expected:**
```
RULE: 100119  Level: 12  HIGH
CRYPTO MINING TOOL — xmrig/minerd/cpuminer detected
```

---

### SIM-H3 — Reverse Shell Tool Detected (Rule 100101)
**MITRE:** T1059, T1071, TA0011

```bash
# On Kali agent — fake meterpreter binary
cp /bin/nc /tmp/meterpreter
/tmp/meterpreter -h 2>/dev/null &
sleep 65  # wait for syscollector
kill %1 2>/dev/null
rm /tmp/meterpreter
```

**Expected:**
```
RULE: 100101  Level: 12  HIGH
REVERSE SHELL TOOL — msfconsole/meterpreter/nc -e detected
```

---

### SIM-H4 — Zeek Port Scan (Rule 100904)
> ⚠️ **Requires Zeek deployed and running. Run `zeekctl deploy` first.**

**MITRE:** T1046, T1595, TA0007

```bash
# On Kali agent
nmap -sS --max-retries 0 -p 1-1000 127.0.0.1
```

**Expected:**
```
RULE: 100904  Level: 10  HIGH
Zeek: Multiple rejected connections (5+ in 20s - possible port scan)
```

---

### SIM-H5 — Auditd Promiscuous Mode (Rule 80710)
**MITRE:** T1040

```bash
# On Kali agent — Zeek naturally triggers this when it starts
sudo ip link set eth0 promisc on
sleep 5
sudo ip link set eth0 promisc off
```

**Expected:**
```
RULE: 80710  Level: 10  HIGH
Auditd: Device enables promiscuous mode
```

---

## MEDIUM Simulations

### SIM-M1 — SSH Login Attempt Non-existent User (Rule 5710)
**MITRE:** T1110, T1078, TA0006

```bash
# On Kali agent
ssh nonexistentuser@127.0.0.1
ssh fakeadmin@127.0.0.1
ssh testuser123@127.0.0.1
```

**Expected:**
```
RULE: 5710  Level: 5  MEDIUM
SSH login attempt for non-existent user
```

---

### SIM-M2 — PAM Authentication Failure (Rule 5503)
**MITRE:** T1110, T1078

```bash
# On Kali agent
ssh root@127.0.0.1  # enter wrong password 3 times
```

**Expected:**
```
RULE: 5503  Level: 5  MEDIUM
PAM: User login failed
```

---

### SIM-M3 — FIM File Modified in /tmp (Rule 550)
**MITRE:** T1565.001

```bash
# On Kali agent
echo "simulation" > /tmp/sim_test.txt
echo "modified" >> /tmp/sim_test.txt
rm /tmp/sim_test.txt
```

**Expected:**
```
RULE: 554  LOW   — File added
RULE: 550  MEDIUM — Integrity checksum changed
RULE: 553  MEDIUM — File deleted
```

---

### SIM-M4 — Zeek DNS Query (Rule 100910)
> ⚠️ **Requires Zeek deployed and running. Run `zeekctl deploy` first.**

**MITRE:** T1071.004

```bash
# On Kali agent
dig virustotal.com
dig google.com
dig github.com
```

**Expected:**
```
RULE: 100910  Level: 5  LOW
Zeek: DNS Query virustotal.com attempted from source ip
```

---

## Cleanup After Simulations

```bash
# Remove test files
rm -f /tmp/userlist.txt /tmp/passlist.txt
rm -f /tmp/xmrig /tmp/meterpreter
rm -f /tmp/malware_test_*
rm -f /tmp/sim_test.txt

# Check if firewall-drop blocked 127.0.0.1
sudo iptables -L -n | grep "127.0.0.1"

# Remove firewall block if needed
sudo iptables -D INPUT -s 127.0.0.1 -j DROP 2>/dev/null
sudo iptables -D FORWARD -s 127.0.0.1 -j DROP 2>/dev/null
```

---

## Expected Full Pipeline Per Simulation

| Simulation | Rule | Severity | TheHive | Gmail | AR Block |
|---|---|---|---|---|---|
| SIM-C1 SSH Brute Force | 100901 | CRITICAL | ✅ | ✅ | ✅ |
| SIM-C2 Repeated File Mods | 100123 | CRITICAL | ✅ | ✅ | ✅ |
| SIM-C3 Brute+Root Correlation | CORR | CRITICAL | ✅ | ✅ | ✅ |
| SIM-H1 Critical File Modified | 100117 | HIGH | ✅ | ✅ | ✅ |
| SIM-H2 Crypto Miner | 100119 | HIGH | ✅ | ✅ | ✅ |
| SIM-H3 Reverse Shell Tool | 100101 | HIGH | ✅ | ✅ | ✅ |
| SIM-H4 Zeek Port Scan | 100904 | HIGH | ✅ | ✅ | ✅ |
| SIM-H5 Promiscuous Mode | 80710 | HIGH | ✅ | ✅ | ✅ |
| SIM-M1 SSH Non-existent User | 5710 | MEDIUM | ✅ | ✅ | ✅ |
| SIM-M2 PAM Auth Failure | 5503 | MEDIUM | ✅ | ✅ | ✅ |
| SIM-M3 FIM File Modified | 550 | MEDIUM | ✅ | ✅ | — |
| SIM-M4 Zeek DNS Query | 100910 | LOW | — | — | — |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| CRITICAL not firing | Check `grep -n "100901" /var/ossec/etc/rules/local_rules.xml` |
| Zeek rules not firing | Run `sudo zeekctl deploy` first |
| AR not blocking | Check `sudo iptables -L -n` |
| TheHive not receiving | Check `THEHIVE_KEY` env var is exported |
| Gmail not sending | Check `GMAIL_USER`, `GMAIL_PASS`, `ALERT_TO` env vars |
| Rules not loaded | Run `sudo systemctl restart wazuh-manager` |

---

