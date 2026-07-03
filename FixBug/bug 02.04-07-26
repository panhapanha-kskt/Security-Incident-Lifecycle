# Wazuh SOC → TheHive + Gmail Unified Engine (ASIL)

**Project:** CBSA Group 7 Blue Team — Wazuh SOC Defense Platform
**Maintainer:** Tith Sopanha (with Kosal Karuna, Cho Davon)
**Host:** `wazuh-server`

A real-time security alert interceptor that tails Wazuh alerts, classifies
severity, correlates related events, creates incident cases in TheHive,
posts observables to Cortex analyzers, triggers automated active response,
and sends HTML email notifications via Gmail.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Data Flow](#data-flow)
3. [Components](#components)
4. [Directory Layout](#directory-layout)
5. [Environment Variables](#environment-variables)
6. [Running the Engine](#running-the-engine)
7. [Troubleshooting Log — Alerts Not Reaching TheHive](#troubleshooting-log--alerts-not-reaching-thehive)
8. [Known Gotchas / Lessons Learned](#known-gotchas--lessons-learned)
9. [Verification Checklist](#verification-checklist)

---

## Architecture Overview

There are **two separate entry points** in this project — don't confuse them:

| Script | Alert Source | Use Case |
|---|---|---|
| `intercept.py` | Tails `alerts.json` + `archives.json` directly (`MultiTailer`) | Standalone terminal monitor, no TheHive/Gmail integration |
| `gmail_alert.py` | Also uses `MultiTailer` directly | Standalone Gmail-only alerting, for testing |
| `thehive-intercept.py` | **Push-socket architecture** via `PushListener` (Unix domain socket at `/run/asil/push.sock`) | **Production engine** — full TheHive + Gmail + Cortex responder pipeline |

The production engine (`thehive-intercept.py`) does **not** read `alerts.json`
itself. It depends entirely on a separate Wazuh **integration script**
(`custom-asil.py`) being invoked by `wazuh-integratord` for every new alert,
which then pushes the alert JSON over a Unix socket into `thehive-intercept.py`.

```
alerts.json / archives.json
        │
        ▼
 wazuh-integratord   (built-in Wazuh daemon, runs as `wazuh` user)
        │  invokes on every new alert
        ▼
 /var/ossec/integrations/custom-asil.py
        │  pushes alert JSON over Unix socket
        ▼
 /run/asil/push.sock  (created by PushListener, owned root:wazuh)
        │
        ▼
 thehive-intercept.py (PushListener → build_alert → classify →
                        correlate → TheHive case → Cortex observables →
                        active-response responder → Gmail email)
```

---

## Data Flow

1. **Wazuh manager** writes a new alert to `alerts.json` (or `archives.json`
   for non-rule-matched raw events).
2. **`wazuh-integratord`** detects the new line and invokes
   `/var/ossec/integrations/custom-asil` (shell wrapper) →
   `custom-asil.py <alert_file_path>` as the `wazuh` user.
3. **`custom-asil.py`** reads and validates the alert JSON, then attempts to
   push it over `/run/asil/push.sock` (3 retries, 0.3s backoff). If all 3
   attempts fail, it spools the alert to `/run/asil/spool/<timestamp>.json`
   as a last-resort so no alert is silently lost.
4. **`PushListener`** (running inside `thehive-intercept.py`, started as
   root via systemd) accepts the socket connection, reads newline-delimited
   JSON lines, and queues them.
5. **`thehive-intercept.py`** main loop pulls from the queue, calls
   `build_alert()` (shared with `intercept.py`) to normalize the raw Wazuh
   JSON into an internal alert dict, then runs it through:
   - Day-boundary / date filter
   - Brute-force escalation (`_escalate_brute_force`)
   - Minimum severity gate (`MIN_SEVERITY`)
   - Dedup (`rule_id|agent_id|srcip|file_path`, `DEDUP_WINDOW` seconds)
   - Terminal display (`show_compact` or `show` with `--verbose`)
   - **TheHive case creation** (`TheHiveCaseManager.process_alert`)
   - **Cortex observable extraction + analyzer triggering**
     (`attach_observables` → `ObservableExtractor`)
   - **Cortex active-response responder** (`_get_responder` →
     `run_responder`, routes through TheHive first, falls back to direct
     Wazuh Active Response API)
   - **Gmail HTML alert email** (`GmailAlerter.send`)
   - **Correlation engine** (`Correlator.add` / `.check()` — detects
     multi-stage attack chains like `BRUTE_THEN_ROOT`, `MINER_DROPPED`, etc.
     and creates a separate correlation case)

---

## Components

### Core classification & display
| File | Purpose |
|---|---|
| `config.py` | Central config: file paths, thresholds, rule→severity maps, MITRE ATT&CK mapping |
| `classifier.py` | `classify_rule()`, `level_to_severity()`, `get_mitre()` |
| `display.py` | ANSI-colored terminal output (`show`, `show_compact`, `show_correlation`, `show_stats`, daily/shutdown summaries) |
| `correlator.py` | In-memory, agent-aware signature correlation (e.g. TOR + reverse shell within 5 min) |
| `intercept.py` | `build_alert()` (shared alert normalizer), `MultiTailer`/`FileTailer`, standalone terminal-only entry point |

### TheHive + Cortex integration (`thehive-configure/`)
| File | Purpose |
|---|---|
| `thehive-intercept.py` | **Main production entry point.** Push-socket based. |
| `push_listener.py` | Unix domain socket server (`/run/asil/push.sock`) — receives alerts pushed by `custom-asil.py` |
| `thehive_client.py` | Thin `requests`-based TheHive v1 API wrapper (`ping`, `create_case`) |
| `thehive_config.py` | TheHive URL, API key (from env), dedup/severity thresholds |
| `thehive_manager.py` | `TheHiveCaseManager` — enforces min severity + dedup before creating cases, builds case title/description/tags |
| `thehive_observable.py` | Extracts IPs / user-agents / file hashes from alerts, posts as TheHive observables, triggers Cortex analyzers (VirusTotal, Shodan, MISP), fires active-response responders |
| `thehive_responder.py` | Cortex responder trigger logic — tries TheHive-routed action API first, falls back to calling Wazuh's own Active Response REST API directly |
| `gmail_alert.py` | `GmailAlerter` — HTML email builder + SMTP sender, importable or standalone-testable |
| `ioc_detector.py` | Standalone/offline IOC batch classifier for `alerts.json` (not part of the live pipeline, useful for retrospective analysis) |

### Wazuh-side integration (outside this repo, on `wazuh-server`)
| File | Purpose |
|---|---|
| `/var/ossec/integrations/custom-asil` | Shell wrapper invoked by `wazuh-integratord` |
| `/var/ossec/integrations/custom-asil.py` | Reads alert file, pushes JSON to `/run/asil/push.sock`, spools to `/run/asil/spool/` on failure |

---

## Directory Layout

```
/home/wazuh-user/Wazuh-Part/
├── classifier.py
├── config.py
├── correlator.py
├── display.py
├── intercept.py
├── gmail_alert.py
└── thehive-configure/
    ├── thehive-intercept.py     ← systemd service entry point
    ├── push_listener.py
    ├── thehive_client.py
    ├── thehive_config.py
    ├── thehive_manager.py
    ├── thehive_observable.py
    ├── thehive_responder.py
    ├── ioc_detector.py
    └── gmail_alert.py

/var/ossec/integrations/
├── custom-asil                  ← shell wrapper (invoked by wazuh-integratord)
└── custom-asil.py                ← pusher script

/var/ossec/logs/
├── alerts/alerts.json
├── archives/archives.json
├── ossec.log                     ← check here for integratord errors
└── wazuh-asil-integration.log    ← RECOMMENDED location for pusher's own log

/run/asil/                        ← tmpfs, recreated on every service start
├── push.sock                     ← root:wazuh, srw-rw----
└── spool/                        ← fallback storage if socket push fails
```

---

## Environment Variables

Set these before starting `thehive-intercept.py` (typically via
`/etc/systemd/system/thehive-intercept.service` `Environment=` directives
or an `EnvironmentFile=`):

| Variable | Required | Purpose |
|---|---|---|
| `THEHIVE_KEY` | **Yes** | TheHive API bearer token |
| `WAZUH_API_PASS` | Recommended | Password for direct Wazuh Active Response API fallback |
| `WAZUH_API_URL` | No (default `https://192.168.200.129:55000`) | Wazuh Manager API |
| `WAZUH_API_USER` | No (default `wazuh-wui`) | Wazuh API username |
| `GMAIL_USER` | No | Gmail sender address (enables email alerting) |
| `GMAIL_PASS` | No | Gmail **App Password** (not account password) |
| `ALERT_TO` | No | Email recipient |
| `CASE_DEDUP_SEC` | No (default 600) | Seconds between duplicate TheHive cases for same rule+srcip |
| `CASE_MIN_SEVERITY` | No (default `MEDIUM`) | Minimum severity to create a TheHive case |
| `THEHIVE_VERIFY_SSL` | No (default `false`) | Verify TheHive's TLS cert |
| `CORTEX_URL` | No (default `https://172.24.80.95:9443`) | Cortex instance |
| `CORTEX_KEY` | No | Cortex API key (used for direct responder fallback) |
| `ASIL_PUSH_SOCKET` | No (default `/run/asil/push.sock`) | Override socket path |

> ⚠️ **Security note:** credentials currently appear hardcoded as example
> values in `thehive-intercept.py`'s `--help`/fatal-error text and in
> `thehive_responder.py` (`_CORTEX_KEY` default). Treat this repo as
> containing secrets and rotate keys before any wider sharing / commit
> history exposure.

---

## Running the Engine

### As a systemd service (production)
```bash
systemctl start thehive-intercept
systemctl status thehive-intercept
journalctl -u thehive-intercept -f
```

### Manually, for debugging
```bash
cd /home/wazuh-user/Wazuh-Part/thehive-configure
python3 thehive-intercept.py --verbose          # full per-alert detail
python3 thehive-intercept.py --dry-run          # no TheHive/Gmail API calls
python3 thehive-intercept.py --debug            # verbose debug logging to file
```

> **Note:** `--replay` has **no effect** on `thehive-intercept.py` — the
> push-socket architecture has no file to replay from. Use
> `intercept.py --replay` against `alerts.json`/`archives.json` directly
> for historical backtesting.

### Quick health check commands
```bash
# Is the socket alive and correctly owned?
ls -l /run/asil/push.sock

# Is the pusher able to run without errors?
sudo -u wazuh python3 /var/ossec/integrations/custom-asil.py /path/to/one/alert.json

# Is wazuh-integratord invoking it successfully?
tail -f /var/ossec/logs/ossec.log | grep -i asil

# Is the pusher logging any push/spool failures?
tail -f /var/ossec/logs/wazuh-asil-integration.log

# Did any alerts get stuck in the spool fallback (socket was down)?
ls -la /run/asil/spool/
```

---

## Troubleshooting Log — Alerts Not Reaching TheHive

This section documents a real debugging session where simulated attacks
(Kali `script.sh`, rule `100101` — reverse shell tool detection) were not
resulting in TheHive cases, despite the alert clearly appearing in
`alerts.json`. Kept here as a reference for the same class of failure in
the future.

### Symptom
`thehive-intercept.py` started cleanly (TheHive connected, Gmail enabled,
day-boundary initialized) but sat idle — `Total alerts: 0` at shutdown —
even while `alerts.json` clearly contained fresh rule `100101` events.

### Root Cause Chain (5 layered issues, found in order)

**1. Wrong mental model of the architecture**
Initially assumed `thehive-intercept.py` tailed `alerts.json` like
`intercept.py` does. It doesn't — it uses `PushListener`, a Unix socket
server, and depends on an external pusher (`custom-asil.py`, invoked by
`wazuh-integratord`) to feed it. **Lesson: confirm which tailer class a
script actually instantiates before assuming file-based ingestion.**

**2. Pusher crashing on logging setup**
```
wazuh-integratord: ERROR: While running custom-asil -> integrations.
Output: PermissionError: [Errno 13] Permission denied: '/var/log/wazuh-asil-integration.log'
```
`custom-asil.py` was configured to log to `/var/log/wazuh-asil-integration.log`.
`/var/log` is `root:root drwxr-xr-x` — the `wazuh` user (uid 991) cannot
create files there. Because the crash happened at `logging.basicConfig()`
time, **the script died before it ever reached the socket-push code** —
so `/run/asil/push.sock` was never even created.

Ruled out along the way (each confirmed *not* the cause, in this order):
- SELinux → `getenforce` returned `Permissive`; `ausearch`/audit log had
  zero denials referencing this path (only unrelated `.wazuh-starter.sh`
  AVCs).
- systemd sandboxing (`ProtectSystem=`, `ReadWritePaths=`) →
  `systemctl cat wazuh-manager` showed no hardening directives at all.
- chroot jail → ruled out because the error was `PermissionError`
  (errno 13), not `FileNotFoundError` (errno 2) — a chrooted process
  looking for `/var/ossec/var/log/...` would get "no such file", not
  "permission denied", since that mirrored path didn't exist.
- ACLs / immutable attributes → `lsattr`/`getfacl` both clean.
- Read-only `/var/log` mount → `mount`/`findmnt` showed nothing.

**Actual cause:** plain, ordinary Unix DAC permissions on `/var/log`
combined with the fact that `touch`+`chown` fixes can be silently undone
by log rotation, and that a manual `sudo -u wazuh` shell test is *not*
equivalent to how the real daemon (`wazuh-integratord`, spawned by
`wazuh-manager` at boot) resolves paths — small differences in umask,
environment, or timing between the two runs made the "it works when I
run it by hand" result misleading.

**Fix:** moved the pusher's log file into `/var/ossec/logs/`, a directory
Wazuh's own daemons already own and write to (`wazuh:wazuh drwxrwx---`),
matching the pattern already used elsewhere in this project
(`config.py`'s `LOG_FILE`).

**3. Stale/empty pushes during the fix (Connection refused)**
```
[WARNING] push attempt 1/3 failed: [Errno 111] Connection refused
```
Once logging worked, real errors became visible for the first time. Some
were simply because `thehive-intercept.py` had been manually stopped
(`systemctl stop`) or Ctrl+C'd during debugging at the exact moment an
alert fired — nothing was listening on the socket. **Not a bug** — just
confirms the socket-listener needs to be continuously running (via
systemd) for production use.

**4. Spool fallback also failing**
```
[CRITICAL] push AND spool both failed — alert dropped: [Errno 13] Permission denied: '/run/asil/spool'
```
`PushListener.start()` runs as root (via systemd) and creates `/run/asil`
with default `os.makedirs()` permissions (`root:root drwxr-xr-x`). It only
explicitly `chown`s the **socket file** to group `wazuh` — not the
**directory** itself. So `wazuh` could connect to the socket, but could
not `mkdir /run/asil/spool` when the socket push failed, since it had no
write permission on the parent directory.

**Fix:** patched `push_listener.py`'s `start()` to also `chown`/`chmod`
the socket's parent directory:
```python
os.chown(d, -1, gid)
os.chmod(d, 0o770)
```

**5. Self-inflicted `TabError` while applying fix #4**
A manual/editor-based edit mixed a tab character with spaces on the three
new lines, producing:
```
TabError: inconsistent use of tabs and spaces in indentation
```
which crash-looped the systemd service entirely (worse than the original
bug — now *nothing* worked, not even old behavior).

**Fix:** re-applied the same three-line patch programmatically via a
small Python script (`open`/`read`/`str.replace`/`write`), guaranteeing
pure-space indentation matching the rest of the file, then verified with:
```bash
grep -Pn '\t' push_listener.py   # confirm zero tabs remain
python3 -m py_compile push_listener.py   # confirm valid syntax before restart
```

### Final Working State
- `/run/asil` → `drwxrwx--- root wazuh` (persists correctly across service restarts because it's now set in code, not just manually)
- `/run/asil/push.sock` → `srw-rw---- root wazuh`
- `custom-asil.py` logs to `/var/ossec/logs/wazuh-asil-integration.log`
- `thehive-intercept.py` service stable, no crash traceback
- End-to-end: simulated rule `100101` → FIM/syscheck detection → `custom-asil.py` push → `PushListener` queue → `build_alert()` → TheHive case created → Cortex observables posted → `Wazuh_1_0` responder fires `firewall-drop` (agent-IP fallback since no `srcip` for a local tool) → Gmail HTML alert sent

---

## Known Gotchas / Lessons Learned

1. **Two different tailers exist in this codebase** (`MultiTailer` vs
   `PushListener`) with the *same* `read_new_lines()` interface — easy to
   assume one when the code actually uses the other. Always check the
   `import` and instantiation lines in `main()` before debugging ingestion.

2. **`/run` is tmpfs.** Anything under `/run/asil/` (the socket, its
   directory permissions, the spool folder) is wiped on every reboot and
   fully recreated by `PushListener.start()`. Any manual `chmod`/`chown`
   fix applied directly on the shell will **not** survive a restart of the
   `thehive-intercept` service — the fix must live in `push_listener.py`
   itself to be durable.

3. **`/var/log` is root-owned and not safe for Wazuh integration scripts
   to log to.** Prefer `/var/ossec/logs/` for anything invoked by
   `wazuh-integratord`, since it already runs as the unprivileged `wazuh`
   user and that directory tree is already correctly permissioned for it.

4. **`errno` matters when diagnosing permission-shaped errors.**
   `PermissionError` (13) vs `FileNotFoundError` (2) tell you very
   different things about *where* the process thinks it's looking —
   useful for quickly ruling out chroot/namespace theories.

5. **A working manual test (`sudo -u wazuh python3 script.py`) does not
   guarantee the real service will succeed.** systemd services, cron, and
   daemon-spawned children can have different umasks, environments, and
   working directories than an interactive shell — always verify via the
   actual invocation path (`journalctl -u <service>`, or the daemon's own
   log) before concluding a fix worked.

6. **When hand-editing indentation-sensitive files under time pressure,
   apply patches programmatically** (Python `str.replace`, `sed` with
   care, or `str_replace`-style tools) rather than free-typing into an
   editor that might auto-indent with a different character than the rest
   of the file uses. Always `python3 -m py_compile` before restarting a
   service that depends on the file.

7. **`--replay` is a no-op on `thehive-intercept.py`.** If you need to
   replay historical alerts through the classification/correlation logic
   for testing, use `intercept.py --replay` instead — it tails the actual
   JSON files from the beginning.

---

## Verification Checklist

Use this after any change to the pusher/socket layer:

- [ ] `getenforce` — confirm SELinux mode (if `Enforcing`, check `ausearch -m avc -ts recent`)
- [ ] `systemctl status thehive-intercept` — service active, no traceback
- [ ] `ls -ld /run/asil` — should be `drwxrwx--- root wazuh` (or your service's UID)
- [ ] `ls -l /run/asil/push.sock` — should be `srw-rw---- root wazuh`, fresh timestamp matching last service start
- [ ] `python3 -m py_compile push_listener.py` — no syntax errors
- [ ] `grep -Pn '\t' push_listener.py` — confirm no stray tabs after any manual edit
- [ ] `sudo -u wazuh python3 /var/ossec/integrations/custom-asil.py <sample_alert.json>` — exits 0
- [ ] `tail -f /var/ossec/logs/wazuh-asil-integration.log` — no `Connection refused` or `Permission denied` during a live test
- [ ] `tail -f /var/ossec/logs/ossec.log \| grep -i asil` — no `ERROR: Unable to run integration`
- [ ] `ls -la /run/asil/spool/` — empty (nothing needed to fall back)
- [ ] TheHive UI — new case appears for the test alert
- [ ] `journalctl -u thehive-intercept -n 30` — `Total alerts` counter incrementing, `hive_cases` > 0
