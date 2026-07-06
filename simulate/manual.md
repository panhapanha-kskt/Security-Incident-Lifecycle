# Wazuh SOC — Manual Testing Guide

Manual, step-by-step commands for testing each attack scenario without running
`simulate.sh` end-to-end. Useful for isolating one thing at a time or debugging
a specific stage of the pipeline (FIM → TheHive case → Active Response).

**Pipeline reminder:** Kali Agent (FIM/log detection) → Wazuh Manager → TheHive
case created → `thehive_responder.py` dispatches Active Response → AR script
runs **on whichever agent triggered the alert** (could be Kali `011`, or the
manager itself as agent `000` if the manager's own logs triggered the rule).

---

## Before you start

Make sure both of these are running:

**On `wazuh-server`:**
```bash
export THEHIVE_KEY="..."
export WAZUH_API_PASS="..."
python3 thehive-intercept.py
```

**On Kali agent:**
```bash
systemctl status wazuh-agent
```

Keep a second terminal open on whichever machine you expect the AR to fire on,
tailing the AR log live:
```bash
tail -f /var/ossec/logs/active-responses.log
```

---

## ⚠️ Important: know which machine will block the IP

The Active Response runs on the **agent that generated the alert**, not
necessarily the machine you're testing from.

- If you inject fake SSH failures **into Kali's own `/var/log/auth.log`**,
  Kali (agent `011`) detects it → AR fires on **Kali**.
- If you SSH *from* Kali *into* the `wazuh-server` and fail a login there,
  the **manager itself** (agent `000`) detects it → AR fires on the
  **wazuh-server**, not Kali. Check `iptables` on the correct box accordingly.

Look at the agent name/ID in the interceptor's alert line before hunting for
the iptables rule on the wrong machine:
```
2026-07-06  10:09:33 UTC  MED  5710  wazuh-server(000)  192.168.200.128  SSH login attempt...
                                      ^^^^^^^^^^^^^^^^^
                                      this is the agent that will run the AR
```

---

## Scenario 1 — Reverse Shell Tool (Rule 100101)

**Run on: Kali agent**

```bash
# Clear any stale block first
iptables -D INPUT -s 192.168.200.128 -j DROP 2>/dev/null
iptables -D OUTPUT -d 192.168.200.128 -j DROP 2>/dev/null

# Create the fake tool (FIM detects this file appearing in /tmp)
cat > /tmp/msfconsole << 'EOF'
#!/bin/bash
echo "wazuh_sim: fake msfconsole process running"
sleep 60
EOF
chmod +x /tmp/msfconsole

# Launch it so syscollector also sees the running process
/tmp/msfconsole &
echo "PID: $!"
```

**Watch for the result:**
```bash
watch -n 1 'iptables -L INPUT -n | grep 192.168.200.128; iptables -L OUTPUT -n | grep 192.168.200.128'
```
```bash
tail -f /var/ossec/logs/active-responses.log
```

**Cleanup:**
```bash
kill %1 2>/dev/null
rm -f /tmp/msfconsole
```

---

## Scenario 2 — Critical File Modified (Rules 100117 / 100123)

**Run on: Kali agent**

```bash
# Unlock in case a previous run left it immutable
chattr -i /etc/sudoers 2>/dev/null
chattr -i /etc/passwd  2>/dev/null

# First touch — triggers rule 100117 (single mod, HIGH)
touch /etc/sudoers
```

**Watch for the lock:**
```bash
watch -n 1 'lsattr /etc/sudoers'
```

**To also test escalation rule 100123 (3+ mods within 300s), repeat 3 more times:**
```bash
for i in 2 3 4; do
    chattr -i /etc/sudoers 2>/dev/null
    touch /etc/sudoers
    echo "# test_marker iter=$i ts=$(date +%s)" >> /etc/passwd
    sleep 2
done
```

**Check the AR log directly:**
```bash
grep "fim-respond" /var/ossec/logs/active-responses.log | tail -5
```

**Cleanup:**
```bash
chattr -i /etc/sudoers 2>/dev/null
chattr -i /etc/passwd  2>/dev/null
sed -i '/test_marker/d' /etc/passwd
```

---

## Scenario 3 — SSH Brute Force (Rules 5710 / 5712)

**Run on: Kali agent** (to keep the AR on Kali — see warning above about
where you inject the failed logins)

```bash
# Clear any stale block
iptables -D INPUT -s 104.28.155.126 -j DROP 2>/dev/null
iptables -D OUTPUT -d 104.28.155.126 -j DROP 2>/dev/null

# Inject fake auth failures directly into Kali's own auth.log
echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[9999]: Invalid user admin from 104.28.155.126 port 54321" >> /var/log/auth.log
echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[9999]: Invalid user Administrator from 104.28.155.126 port 54321" >> /var/log/auth.log
echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[9999]: Failed password for invalid user backup from 104.28.155.126 port 54321 ssh2" >> /var/log/auth.log
```

**Watch for the result:**
```bash
watch -n 1 'iptables -L INPUT -n | grep 104.28.155.126; iptables -L OUTPUT -n | grep 104.28.155.126'
```

**Cleanup:**
```bash
iptables -D INPUT -s 104.28.155.126 -j DROP 2>/dev/null
iptables -D OUTPUT -d 104.28.155.126 -j DROP 2>/dev/null
```

---

## Full cleanup (all scenarios at once)

```bash
rm -f /tmp/msfconsole
chattr -i /etc/sudoers 2>/dev/null; chattr -i /etc/passwd 2>/dev/null
sed -i '/test_marker/d' /etc/passwd
iptables -D INPUT -s 192.168.200.128 -j DROP 2>/dev/null
iptables -D OUTPUT -d 192.168.200.128 -j DROP 2>/dev/null
iptables -D INPUT -s 104.28.155.126 -j DROP 2>/dev/null
iptables -D OUTPUT -d 104.28.155.126 -j DROP 2>/dev/null
```

Or, if using the full simulation script:
```bash
sudo ./simulate.sh --cleanup
```

---

## Verifying on the server side (`thehive-intercept.py`)

Check the interceptor picked up the alert and attempted the responder:
```bash
grep -E "100101|100117|100123|5710|5712" /home/wazuh-user/backup/log/interceptor.log | tail -20
```

If you've enabled AR confirmation (`AR_CONFIRM_RESULTS=true` +
`WAZUH_INDEXER_PASS` set), check whether it was actually confirmed on the
agent, not just dispatched:
```bash
grep -E "CONFIRMED|NOT confirmed|INDEXER" /home/wazuh-user/backup/log/interceptor.log | tail -20
```

---

## Common gotchas

| Symptom | Likely cause |
|---|---|
| No iptables block on Kali after SSH brute-force test | You tested by SSHing *into* the server — AR fired on `wazuh-server` (agent `000`), not Kali. Check the server's iptables instead. |
| `[WARNING] agent_ip fallback` in interceptor log | Expected for local-only detections (e.g. rule 100101) with no `srcip` — not an error. |
| `custom-block-ip` returns error 1652 from the API | Command must be prefixed with `!` when dispatched manually (e.g. `"command":"!custom-block-ip"`). |
| AR dispatched but block never appears | Check `active-response/bin/custom-block-ip` exists as a symlink on **whichever agent actually needs to run it** (Kali `011` and the manager `000` each need their own copy/symlink). |
| Confirmation says "NOT confirmed" with empty error | Query ran fine but found zero matches — check the indexer's actual field names (`full_log`, `agent.id`) match what `_poll_ar_execution_confirmed()` expects. |
