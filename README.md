# Wazuh SOC Automation Platform

A real-time Security Operations Center (SOC) pipeline built on top of Wazuh that
intercepts alerts as they're generated, classifies and correlates them, opens
incident cases in TheHive, triggers automated response actions through Cortex,
syncs indicators to MISP, and emails analysts — all with minimal manual
intervention.

> **Team:** Blue Team Operations Center 

> **Stack:** Wazuh · TheHive · Cortex · MISP · Python · Docker

---

## Overview

Out of the box, Wazuh generates alerts but doesn't do much with them — no
correlation across events, no case management, no automated containment, no
threat-intel enrichment. This project closes that gap by building a custom
pipeline that sits between Wazuh and the rest of the SOC toolchain:

<img width="1920" height="1080" alt="Timeline(2)" src="https://github.com/user-attachments/assets/07500887-2d4f-4fb7-9263-9558aa9b309b" />

---

## Technologies

**Detection & Data Collection**
- Wazuh Manager + Agent (FIM/syscheck, rootcheck, syscollector, active response)

**Custom Pipeline**
- Python 3 (asyncio-free, threaded push listener + polling loop)
- Unix domain sockets for low-latency alert delivery (Wazuh integration → interceptor)
- Disk-based spooling for delivery resilience during downtime

**Case Management & Orchestration**
- TheHive 5 (case/alert management)
- Cortex 3 (analyzer & responder orchestration)
- MISP (threat intelligence platform, auto-enriched with MITRE ATT&CK galaxy/taxonomy tags)

**Infrastructure**
- Docker / Docker Compose (TheHive, Cortex, MISP, Elasticsearch, Cassandra, MariaDB, Nginx reverse proxies)
- Bash (pipeline orchestration, sync scripts)

**Notifications**
- Gmail SMTP (HTML-formatted incident emails with severity theming)

---

## Features

- **Real-time alert interception** — a custom Wazuh integration pushes every
  alert to a Unix socket instead of relying on slow file tailing; if the
  listener is down, alerts are spooled to disk and replayed on startup.
- **Severity classification** — rules are mapped to CRITICAL / HIGH / MEDIUM /
  LOW / INFO based on both explicit rule tables and dynamic Wazuh rule levels.
- **MITRE ATT&CK mapping** — every classified rule carries technique and
  tactic IDs, with rationale documented per rule group (credential access,
  C2, exfiltration, web attacks, etc.).
- **Brute-force escalation** — failed-login rules are tracked per source IP in
  a sliding time window and automatically escalate severity as the failure
  count crosses configurable thresholds.
- **In-memory correlation engine** — detects multi-stage attack chains (e.g.
  TOR node + reverse shell, brute force + privilege escalation, port scan +
  SQLi) within a rolling time window, per agent, and fires a dedicated
  correlation alert.
- **Automated case creation** — qualifying alerts and correlation events open
  structured TheHive cases with full context (agent, IPs, MITRE tags, raw
  log), tagged and deduplicated to avoid case spam.
- **Automatic observable extraction & enrichment** — IPs, user-agents, and
  file hashes are pulled from alerts (including regex fallback scanning of
  raw logs) and posted to TheHive as observables, which trigger Cortex
  analyzers (VirusTotal, MISP, Shodan) automatically.
- **Automated active response** — FIM violations lock the affected file
  (`chattr +i`) and network-based threats trigger `firewall-drop` on the
  Wazuh agent, dispatched through Cortex responders with a direct
  Wazuh-API fallback if the TheHive-routed path fails.
- **MISP synchronization** — every TheHive case is mirrored to MISP in
  real time, with rule-specific enrichment templates (attributes, MITRE
  galaxy tags, TLP/Admiralty/CIRCL taxonomy tags) and TLP-aware distribution
  levels, plus a scheduled backfill script as a safety net.
- **HTML email alerts** — CRITICAL/HIGH/MEDIUM alerts generate themed HTML
  emails with a full incident summary, MITRE links, and an analyst checklist,
  deduplicated per rule/source-IP.
- **Day-boundary rollover** — daily counters, dedup caches, and correlation
  state reset automatically at local midnight, with a printed/logged daily
  summary beforehand.
- **Dry-run & replay modes** — alerts can be replayed from the beginning of
  the log for backtesting, or the whole pipeline can run in dry-run mode with
  no external API calls.

---

## The Process

1. **Started with the detection layer.** Configured Wazuh's FIM, active
   response, and a local ruleset on top of the default rules — covering
   brute-force detection, reverse shells, crypto miners, SQL injection, and
   file-integrity violations, each mapped to MITRE ATT&CK.
2. **Replaced file-tailing with a push architecture.** The original design
   polled `alerts.json`/`archives.json` on an interval; this was reworked
   into a custom Wazuh integration script that pushes each alert over a Unix
   socket the moment it fires, with disk spooling so nothing is lost if the
   listener is temporarily down.
3. **Built the classification and correlation core.** Wrote the rule tables,
   severity logic, and a lightweight in-memory correlator that tracks
   recently-fired rules per agent and matches them against known attack
   chain "signatures."
4. **Wired up TheHive as the case-management layer.** Built a case manager
   with severity gating and time-window deduplication so the same incident
   doesn't spawn dozens of duplicate cases.
5. **Layered in Cortex for observables and response.** Extracted IPs,
   user-agents, and hashes from each alert, posted them as TheHive
   observables, and triggered the relevant Cortex analyzers automatically.
   Then added responders so certain rule classes trigger real
   containment actions (not just enrichment).
6. **Connected MISP for threat-intel sharing.** Originally this ran on a
   cron-driven bash/Python pipeline; it was later moved to fire synchronously
   right after case creation, with the cron job kept as a backfill safety net.
7. **Added Gmail alerting last**, as a human-facing layer on top of the
   automated pipeline, with dedup so analysts aren't flooded.
8. **Hardened iteratively.** Went through several rounds of fixing real
   issues found under load: responders being skipped when observables were
   duplicates, SMTP failures being silently swallowed instead of counted,
   MITRE severity scales running in opposite directions between TheHive and
   MISP, and dedup keys not accounting for file paths (which suppressed
   distinct FIM alerts on different files).

---

## What I Learned

- **Designing for partial failure matters more than the happy path.** Most of
  the real engineering effort went into what happens when TheHive is
  unreachable, Cortex times out, SMTP rejects a login, or MISP is down —
  making sure one component's outage never crashes the pipeline or silently
  drops an alert.
- **Push beats poll for real-time systems.** Moving from file tailing to a
  Unix-socket push listener (with spool-to-disk fallback) meaningfully
  reduced detection latency and taught me a lot about socket handling,
  threading, and backpressure (bounded queues, drop counters).
- **Severity scales are not universal.** TheHive, MISP, and Wazuh each encode
  severity/threat-level differently, and two of them run in *opposite*
  directions. Assuming they line up is an easy, dangerous mistake.
- **Dedup keys need to match the granularity of the thing you're deduping.**
  An early dedup key based only on `(rule_id, agent, srcip)` silently
  swallowed legitimate FIM alerts on different files — the fix was
  including the file path in the key.
- **Correlation logic is deceptively simple to describe and easy to get
  wrong in practice** — decisions like "does a rule expire from the
  correlation window the instant it ages out, or on the next event?" have
  real detection consequences.
- **Enrichment pipelines need idempotency.** Because the real-time MISP sync
  and the scheduled backfill script both run, everything had to be written
  so re-running against the same case/event is a safe no-op, not a
  duplicate.
- **Secrets management is a first-class concern, not an afterthought** —
  working through this project surfaced just how easily API keys end up
  hardcoded in scripts, config files, and error messages during fast
  iteration, and why environment variables plus a rotation habit matter.

---

## Overall Growth

This project moved me from "I can write a script that reacts to one alert"
to "I can design a multi-service pipeline that has to stay correct under
concurrency, partial outages, and adversarial timing." Specific growth areas:

- Comfort with **asynchronous/concurrent Python** (threading, queues, sockets)
  in a context where losing an alert has real consequences.
- A much better working knowledge of the **SOC toolchain** (Wazuh, TheHive,
  Cortex, MISP) and how they're meant to interoperate versus how they
  actually interoperate in practice.
- Practical experience mapping detections to **MITRE ATT&CK**, not just as a
  reference chart but as structured data flowing through a pipeline.
- Stronger instincts around **defensive coding** — return-value contracts
  that distinguish "skipped" from "failed," explicit exception types instead
  of bare `except: return False`, and counters for every failure mode so
  nothing fails silently.
- A better sense of **operational security** hygiene — separating config
  from secrets, and understanding how quickly credentials get scattered
  across a codebase if you're not deliberate about it from day one.

---

## How Can It Be Improved?

- **Centralize secrets** in a proper secrets manager (Vault, AWS Secrets
  Manager, or at minimum a `.env` file that's git-ignored everywhere)
  instead of environment variables sprinkled with occasional hardcoded
  fallbacks — and rotate every credential that's ever been hardcoded.
- **Add automated tests** for the classifier, correlator, and dedup logic —
  currently correctness is verified manually against live traffic, which
  makes regressions easy to miss.
- **Replace in-memory state with persistent storage** (Redis, SQLite) for
  dedup caches, correlation windows, and brute-force counters, so a process
  restart doesn't silently reset detection state.
- **Add a proper metrics/observability layer** (Prometheus + Grafana) instead
  of periodic `print()` stats — would make trends (email failure rate,
  responder success rate, MISP sync lag) visible over time instead of only
  in scrollback.
- **Horizontal scaling** — the interceptor is currently a single process;
  splitting classification/correlation from the delivery integrations (Hive,
  Cortex, MISP, Gmail) into separate workers behind a queue would make the
  system more resilient to a slow downstream API blocking the whole loop.
- **Tighten the correlation signature set** — right now it's a small,
  hand-picked list; this could be extended to a configurable rule format
  (or backed by a proper correlation engine) so new attack chains don't
  require code changes.
- **TLS everywhere** — several internal service calls currently run with SSL
  verification disabled for convenience in the lab; production use would
  need real certificates and verification enabled throughout.
- **Multi-node Wazuh cluster** — the current deployment runs as a single
  Wazuh node; clustering would remove that single point of failure.

---

## Running the Project

> This is a lab/portfolio deployment. The instructions below assume Docker
> and Docker Compose are already installed, and that you have your own
> Wazuh manager + agent already enrolled.

### 1. Bring up the backend stack

```bash
# TheHive stack (Cassandra, Elasticsearch, TheHive, Nginx)
cd docker/prod1-thehive
docker compose up -d

# Cortex stack (Elasticsearch, Cortex, Nginx)
cd ../prod1-cortex
docker compose up -d

# MISP stack
cd ../../misp-docker
docker compose up -d
```

Configure the TheHive ↔ Cortex and TheHive ↔ MISP connectors in
`thehive/config/application.conf`, and register the Cortex analyzers/
responders you need (VirusTotal, MISP, Shodan, and the custom Wazuh
responders) from the Cortex UI.

### 2. Configure environment variables

Never hardcode credentials — export them before starting the interceptor:

```bash
export THEHIVE_KEY="<thehive-api-key>"
export WAZUH_API_PASS="<wazuh-api-password>"
export GMAIL_USER="<sender-gmail-address>"
export GMAIL_PASS="<gmail-app-password>"
export ALERT_TO="<recipient-address>"
export CORTEX_KEY="<cortex-api-key>"
export MISP_API_KEY="<misp-api-key>"
```

### 3. Wire up the Wazuh integration

The `custom-asil` integration script (in `/var/ossec/integrations/`) pushes
alerts to the interceptor over a Unix socket. Confirm it's referenced in
`ossec.conf` under `<integration>` and restart the manager:

```bash
systemctl restart wazuh-manager
```

### 4. Run the interceptor

```bash
cd thehive-configure
python3 thehive-intercept.py            # live mode
python3 thehive-intercept.py --verbose  # full per-alert detail
python3 thehive-intercept.py --dry-run  # no external API calls, terminal only
```

### 5. Watch it work

- Trigger a test event (e.g. a few failed SSH logins, or modify
  `/etc/sudoers` on the monitored agent).
- Watch the terminal for the classified alert.
- Check TheHive for the case, Cortex for the analyzer/responder jobs, MISP
  for the synced event, and your inbox for the email alert.

### 6. (Optional) Run the MISP backfill

```bash
cd thehive-configure/MISP
./MISP_Pipeline.sh
```

---

## Video 📺

[https://drive.google.com/file/d/1QgBoHXI4n_66M-m2b80HNFpVm90nFnmI/view](https://drive.google.com/file/d/1Ebi4WiNt23jXchxehC9v1sV3YHfIGBl1/view?usp=sharing)
