# MISP Pipeline — Scheduled Run Configuration

This document explains how the `MISP_Pipeline.sh` script (TheHive → MISP
export / enrich / publish) is scheduled to run automatically on
`wazuh-server`, and how to change the schedule.

> **Note:** This setup uses **systemd timers**, not traditional crontab.
> Systemd timers are the modern equivalent — same purpose (run a job on a
> schedule) but with better logging (`journalctl`), dependency ordering, and
> automatic catch-up after downtime. A plain-crontab equivalent is included
> at the bottom for reference.

---

## 1. What's involved

| File | Purpose |
|---|---|
| `/etc/systemd/system/misp-pipeline.service` | Defines **what** to run (the actual pipeline script) |
| `/etc/systemd/system/misp-pipeline.timer` | Defines **when** to run it (the schedule) |

The service and timer are separate on purpose: the `.service` can be run
manually at any time for testing, while the `.timer` is what triggers it
automatically.

**Script location:**
```
/home/wazuh-user/Wazuh-Part/thehive-configure/MISP/MISP_Pipeline.sh
```

**Logs written by the pipeline itself:**
```
/home/wazuh-user/Wazuh-Part/thehive-configure/MISP/logs/misp_pipeline_<timestamp>.log
```

---

## 2. The service file

```ini
# /etc/systemd/system/misp-pipeline.service

[Unit]
Description=MISP export/enrich/publish pipeline (TheHive → MISP)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/wazuh-user/Wazuh-Part/thehive-configure/MISP
ExecStart=/bin/bash /home/wazuh-user/Wazuh-Part/thehive-configure/MISP/MISP_Pipeline.sh
User=root
TimeoutStartSec=180
```

- `Type=oneshot` — runs once and exits (not a long-running daemon).
- `Wants=`/`After=network-online.target` — waits for networking before
  running, since the pipeline talks to TheHive and MISP over HTTPS.
- `TimeoutStartSec=180` — kills the job if it hangs past 3 minutes.

You generally **do not need to edit this file** unless the script path
changes or you need to adjust the timeout.

---

## 3. The timer file (the schedule)

```ini
# /etc/systemd/system/misp-pipeline.timer

[Unit]
Description=Run MISP pipeline daily at 12PM Phnom Penh time (UTC+7)

[Timer]
OnCalendar=*-*-* 05:00:00
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
```

### Key fields

| Field | Meaning |
|---|---|
| `OnCalendar` | The schedule, in **server local time** (this server runs UTC — check with `timedatectl`) |
| `RandomizedDelaySec` | Adds up to N seconds of random jitter so the job doesn't fire at the exact same second every time |
| `Persistent=true` | If the server is down/rebooting at the scheduled time, the job runs as soon as it's back up instead of being skipped |

### ⚠️ Timezone gotcha

This server's local time **is UTC** (confirmed via `timedatectl` →
`Time zone: n/a (UTC, +0000)`). Phnom Penh is **UTC+7**. So:

| You want it to run at... | Set `OnCalendar` to... |
|---|---|
| 12:00 PM (noon) Phnom Penh | `05:00:00` |
| 8:00 AM Phnom Penh | `01:00:00` |
| 6:00 PM Phnom Penh | `11:00:00` |
| Midnight Phnom Penh | `17:00:00` (previous day, UTC) |

General rule: **Phnom Penh time − 7 hours = UTC time** to put in `OnCalendar`.

### Common `OnCalendar` patterns

```
OnCalendar=*:0/5              # every 5 minutes
OnCalendar=hourly              # every hour, on the hour
OnCalendar=daily                # every day at midnight UTC
OnCalendar=*-*-* 05:00:00      # every day at 05:00 UTC (= noon Phnom Penh)
OnCalendar=Mon *-*-* 05:00:00  # every Monday at 05:00 UTC
```

---

## 4. How to change the schedule

1. Overwrite the timer file with the new schedule:
   ```bash
   sudo tee /etc/systemd/system/misp-pipeline.timer > /dev/null << 'EOF'
   [Unit]
   Description=Run MISP pipeline daily at 12PM Phnom Penh time (UTC+7)

   [Timer]
   OnCalendar=*-*-* 05:00:00
   RandomizedDelaySec=60
   Persistent=true

   [Install]
   WantedBy=timers.target
   EOF
   ```

2. Reload systemd and restart the timer:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart misp-pipeline.timer
   ```

3. Confirm the new schedule took effect:
   ```bash
   systemctl list-timers misp-pipeline.timer
   ```
   Check the `NEXT` column — it should show the correct upcoming run time
   in UTC.

---

## 5. How to run it

### Automatically (normal operation)
Once the timer is enabled, nothing needs to be done — it runs on its own
schedule indefinitely, including after reboots.

Enable it (only needs to be done once, already done on this server):
```bash
sudo systemctl enable --now misp-pipeline.timer
```

### Manually (for testing, outside the schedule)
Run the service directly — this does **not** affect or reset the timer:
```bash
sudo systemctl start misp-pipeline.service
```

### Check if the timer is active and when it runs next
```bash
systemctl list-timers misp-pipeline.timer
```
Look at the `NEXT` and `LEFT` columns. `LAST` shows when the *unit file*
was last reloaded/restarted — not necessarily the last real execution.

### Check logs of actual runs
```bash
# Live tail
journalctl -u misp-pipeline.service -f

# Last 20 log lines from any past run
journalctl -u misp-pipeline.service -n 20 --no-pager

# Runs within a specific time window (times are UTC, 24h format)
journalctl -u misp-pipeline.service --since "05:00" --until "05:10"
```

A successful run looks like:
```
[+] Export done — 7 case(s) checked, 7 new event(s) created, 10 published, 0 failed.
    Full log: /home/wazuh-user/Wazuh-Part/thehive-configure/MISP/logs/misp_pipeline_<timestamp>.log
```

### Disable the automatic schedule (if ever needed)
```bash
sudo systemctl disable --now misp-pipeline.timer
```
This stops future automatic runs but does not delete the unit files.

---

## 6. Crontab equivalent (reference only)

If this were configured with crontab instead, the equivalent entry
(run as root, daily at 05:00 UTC = 12PM Phnom Penh) would be:

```bash
sudo crontab -e
```
```cron
0 5 * * * /bin/bash /home/wazuh-user/Wazuh-Part/thehive-configure/MISP/MISP_Pipeline.sh >> /home/wazuh-user/Wazuh-Part/thehive-configure/MISP/logs/cron.log 2>&1
```

Cron field order: `minute hour day-of-month month day-of-week`.

**Why the systemd timer is preferable here:**
- Logs go to `journalctl` automatically (searchable, timestamped, rotated) —
  no manual log redirection needed.
- `Persistent=true` catches up missed runs after downtime; vanilla cron does not.
- Easier to check status (`systemctl list-timers`) vs. parsing crontab by hand.

---

## 7. Known issue to watch

`free -h` on this server has shown **0B swap** despite prior notes indicating
a 4GB swapfile was configured. On a box already running close to its memory
limit, a daily job spawning a Python/bash pipeline is a plausible OOM risk
if swap isn't actually active. Verify before relying on this long-term:

```bash
swapon --show
```

If empty, the swapfile needs to be re-added (and confirmed persistent via
`/etc/fstab`, since it may have been lost on a reboot).
