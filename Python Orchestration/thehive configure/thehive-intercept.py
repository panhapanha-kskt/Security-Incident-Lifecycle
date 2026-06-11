#!/usr/bin/env python3
"""
thehive-intercept.py – Unified Wazuh SOC → TheHive + Gmail Engine
═══════════════════════════════════════════════════════════════════

FIX SUMMARY (vs original):
  1. Imports GmailAlerter from gmail_alert.py — Gmail is now called from
     inside this loop instead of being a completely separate process.
  2. Added GMAIL env-var guard matching the existing THEHIVE_KEY pattern.
  3. GmailAlerter.send() is called right after every successful TheHive
     case creation AND for every alert that passes severity/dedup gates,
     so email fires even when the TheHive API is unreachable.
  4. Added email_sent / email_err counters to _fresh_counters().
  5. GmailAlerter.cleanup() / reset() called on the same cycle as the
     other periodic-maintenance helpers — one shared cleanup cadence.
  6. Updated daily summary, stats banner, and shutdown log to include
     email counters.

Required environment variables:
  THEHIVE_KEY          TheHive API key

Optional environment variables (Gmail alerting):
  GMAIL_USER           Gmail sender address
  GMAIL_PASS           Gmail App Password
  ALERT_TO             Recipient address

Other optional environment variables:
  CASE_DEDUP_SEC       Case dedup window in seconds (default: 600)
  CASE_MIN_SEVERITY    Minimum severity for case creation (default: MEDIUM)
  THEHIVE_VERIFY_SSL   'true' to verify SSL certs (default: false)
  THEHIVE_TIMEOUT      HTTP timeout in seconds (default: 15)
  THEHIVE_RETRIES      HTTP retry count (default: 2)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import argparse
import json
import logging
import os
import signal
import time
from collections import deque
from datetime import date, datetime, timedelta
from typing import Optional, Union
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from classifier import SEVERITY_ORDER, safe_level
from config import (
    ALERT_FILE,
    ARCHIVES_FILE,
    BRUTE_FORCE_WINDOW,
    CRITICAL_THRESHOLD,
    DAY_TIMEZONE,
    DEDUP_WINDOW,
    FAILED_LOGIN_RULES,
    FAILED_LOGIN_THRESHOLD,
    LOG_FILE,
    MIN_SEVERITY,
    POLL_INTERVAL,
    SEVERE_THRESHOLD,
)
from correlator import Correlator
from display import (
    C,
    show,
    show_correlation,
    show_daily_summary,
    show_shutdown,
    show_stats,
)
from interceptor import MultiTailer, build_alert
from thehive_config import (
    CASE_DEDUP_SEC,
    CASE_MIN_SEVERITY,
    THEHIVE_RETRIES,
    THEHIVE_TIMEOUT,
    THEHIVE_URL,
    THEHIVE_VERIFY_SSL,
)
from thehive_client import TheHiveClient
from thehive_manager import TheHiveCaseManager
from thehive_responder import run_responder

# FIX 1: import GmailAlerter — safe because gmail_alert.py no longer
# reads env vars at module level (they're loaded inside _load_gmail_config).
from gmail_alert import GmailAlerter

# ── API keys / credentials ────────────────────────────────────────────────────

# TheHive key — required
_THEHIVE_KEY: str = os.environ.get("THEHIVE_KEY", "").strip()

# FIX 2: Gmail credentials — optional; all three must be set to enable email
_GMAIL_USER:    str  = os.environ.get("GMAIL_USER", "").strip()
_GMAIL_PASS:    str  = os.environ.get("GMAIL_PASS", "").strip()
_GMAIL_TO:      str  = os.environ.get("ALERT_TO",   "").strip()
_GMAIL_ENABLED: bool = bool(_GMAIL_USER and _GMAIL_PASS and _GMAIL_TO)

# ── Cortex responder name ─────────────────────────────────────────────────────
WAZUH_RESPONDER_NAME: str = "Wazuh_1_0"   # ← set your exact Cortex responder name


# ── Counters ──────────────────────────────────────────────────────────────────

def _fresh_counters() -> dict:
    return {
        "total":        0,
        "CRITICAL":     0,
        "HIGH":         0,
        "MEDIUM":       0,
        "LOW":          0,
        "INFO":         0,
        "skipped":      0,
        "src_alerts":   0,
        "src_archives": 0,
        # TheHive case stats
        "hive_cases":   0,   # cases successfully created
        "hive_skipped": 0,   # dedup-skipped case creations
        # Cortex responder stats
        "hive_resp_ok":  0,
        "hive_resp_err": 0,
        # FIX 4: Gmail stats
        "email_sent": 0,
        "email_err":  0,
    }


# ── Brute-force tracker ───────────────────────────────────────────────────────

class _BruteForceTracker:
    """Sliding-window failed-login counter keyed by source IP."""

    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = {}

    def record(self, srcip: str) -> None:
        now = time.monotonic()
        self._buckets.setdefault(srcip, deque()).append(now)
        self._evict(srcip, now)

    def count(self, srcip: str) -> int:
        now    = time.monotonic()
        cutoff = now - BRUTE_FORCE_WINDOW
        q = self._buckets.get(srcip)
        return sum(1 for t in (q or []) if t >= cutoff)

    def _evict(self, srcip: str, now: float) -> None:
        cutoff = now - BRUTE_FORCE_WINDOW
        q = self._buckets.get(srcip)
        if q:
            while q and q[0] < cutoff:
                q.popleft()

    def cleanup(self) -> None:
        now = time.monotonic()
        for ip in list(self._buckets):
            self._evict(ip, now)
            if not self._buckets[ip]:
                del self._buckets[ip]

    def reset(self) -> None:
        self._buckets.clear()


def _escalate_brute_force(alert: dict, tracker: _BruteForceTracker) -> dict:
    rule_id = alert.get("rule_id", "")
    srcip   = alert.get("srcip", "")

    if rule_id not in FAILED_LOGIN_RULES or not srcip:
        return alert

    tracker.record(srcip)
    count = tracker.count(srcip)

    if count >= CRITICAL_THRESHOLD:
        alert["severity"] = "CRITICAL"
        alert["level"]    = 13
        alert["reason"]   = (
            f"CRITICAL BRUTE-FORCE – {count} failures from {srcip} "
            f"in {BRUTE_FORCE_WINDOW}s"
        )
    elif count >= SEVERE_THRESHOLD:
        alert["severity"] = "HIGH"
        alert["level"]    = 10
        alert["reason"]   = (
            f"HIGH BRUTE-FORCE – {count} failures from {srcip} "
            f"in {BRUTE_FORCE_WINDOW}s"
        )
    elif count >= FAILED_LOGIN_THRESHOLD:
        alert["severity"] = "MEDIUM"
        alert["level"]    = 7
        alert["reason"]   = (
            f"MEDIUM BRUTE-FORCE – {count} failures from {srcip} "
            f"in {BRUTE_FORCE_WINDOW}s"
        )
    return alert


# ── Alert dedup ───────────────────────────────────────────────────────────────

class _AlertDedup:
    """Suppress repeated (rule, agent, srcip, file_path) tuples within DEDUP_WINDOW."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def is_duplicate(self, alert: dict) -> bool:
        key = (
            f"{alert.get('rule_id','?')}|"
            f"{alert.get('agent_id','?')}|"
            f"{alert.get('srcip','')}|"
            f"{alert.get('file_path','')}"
        )
        now  = time.monotonic()
        last = self._seen.get(key)
        if last is not None and (now - last) < DEDUP_WINDOW:
            return True
        self._seen[key] = now
        return False

    def cleanup(self) -> None:
        now    = time.monotonic()
        cutoff = now - DEDUP_WINDOW
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

    def reset(self) -> None:
        self._seen.clear()


# ── Day-boundary tracker ──────────────────────────────────────────────────────

class _DayBoundary:
    def __init__(self, tz_name: str) -> None:
        try:
            self._tz = ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            logging.warning(f"Timezone '{tz_name}' not found — falling back to UTC")
            self._tz = ZoneInfo("UTC")

        self._day: date               = datetime.now(self._tz).date()
        self._session_start: datetime = datetime.now(self._tz)

        print(
            f"\n{C.CYAN}{C.BOLD}Day-boundary active  │  "
            f"date={self._day}  │  tz={tz_name}{C.RESET}\n"
        )
        logging.info(f"DAY-BOUNDARY start  day={self._day}  tz={tz_name}")

    @property
    def active_day(self) -> date:
        return self._day

    @property
    def session_start(self) -> datetime:
        return self._session_start

    def rolled_over(self) -> bool:
        today = datetime.now(self._tz).date()
        if today != self._day:
            self._session_start = datetime.now(self._tz)
            self._day = today
            logging.info(f"DAY-BOUNDARY rollover  new_day={self._day}")
            return True
        return False

    def alert_is_today(self, ts_str: str) -> bool:
        import re
        if not ts_str:
            return True
        ts = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', str(ts_str))
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.astimezone(self._tz).date() == self._day
        except (ValueError, AttributeError):
            return True

    def seconds_until_midnight(self) -> float:
        now      = datetime.now(self._tz)
        tomorrow = datetime.combine(
            self._day + timedelta(days=1),
            datetime.min.time(),
            tzinfo=self._tz,
        )
        return max(0.0, (tomorrow - now).total_seconds())


# ── Argument parsing ──────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Wazuh SOC → TheHive + Gmail Unified Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Required environment variable:\n"
            "  THEHIVE_KEY          TheHive API key\n\n"
            "Optional environment variables (Gmail):\n"
            "  GMAIL_USER           Gmail sender address\n"
            "  GMAIL_PASS           Gmail App Password\n"
            "  ALERT_TO             Recipient address\n\n"
            "Other optional environment variables:\n"
            "  CASE_DEDUP_SEC       Case dedup window in seconds (default: 600)\n"
            "  CASE_MIN_SEVERITY    Minimum severity for case creation (default: MEDIUM)\n"
            "  THEHIVE_VERIFY_SSL   'true' to verify SSL certs (default: false)\n"
            "  THEHIVE_TIMEOUT      HTTP timeout in seconds (default: 15)\n"
            "  THEHIVE_RETRIES      HTTP retry count (default: 2)\n"
        ),
    )
    p.add_argument("--replay",  action="store_true",
                   help="Replay existing files from the beginning (default: tail mode)")
    p.add_argument("--debug",   action="store_true",
                   help="Enable verbose debug logging")
    p.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="Display alerts but do NOT call the TheHive or Gmail APIs")
    return p.parse_args()


# ── Logging setup ─────────────────────────────────────────────────────────────

def _setup_logging(debug: bool) -> None:
    log_path = Path(LOG_FILE).parent / "thehive_interceptor.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)

    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG if debug else logging.INFO)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s – %(message)s",
        "%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root.addHandler(ch)


# ── Signal handling ───────────────────────────────────────────────────────────

_shutdown_requested: bool = False

def _handle_signal(signum, frame) -> None:
    global _shutdown_requested
    _shutdown_requested = True


# ── Cortex responder helper ───────────────────────────────────────────────────

def _run_responder_and_log(
    client,
    case_id: str,
    ctrs:    dict,
    label:   str = "alert",
) -> None:
    """Trigger the Cortex responder on a TheHive case."""
    try:
        result = run_responder(
            client         = client,
            case_id        = case_id,
            responder_name = WAZUH_RESPONDER_NAME,
            poll_result    = False,
        )

        if result["status"] == "triggered":
            ctrs["hive_resp_ok"] += 1
            print(
                f"  {C.TEAL}[RESPONDER]{C.RESET} case={case_id}"
                f"  responder={WAZUH_RESPONDER_NAME}"
                f"  action_id={result['action_id']}"
                f"  ({label})"
            )
            logging.info(
                f"Responder triggered  case={case_id}"
                f"  action_id={result['action_id']}  label={label}"
            )
        else:
            ctrs["hive_resp_err"] += 1
            print(
                f"  {C.ORANGE}[RESPONDER WARN]{C.RESET} case={case_id}"
                f"  status={result['status']}"
                f"  error={result['error']}"
                f"  ({label})"
            )
            logging.warning(
                f"Responder not triggered  case={case_id}"
                f"  status={result['status']}  error={result['error']}"
            )

    except Exception as exc:
        ctrs["hive_resp_err"] += 1
        logging.error(f"run_responder raised unexpectedly case={case_id}: {exc}")


# FIX 3: Gmail send helper ────────────────────────────────────────────────────

def _send_email_and_log(
    gmail:  GmailAlerter,
    alert:  dict,
    ctrs:   dict,
    label:  str = "alert",
) -> None:
    """
    Call gmail.send() and update counters.
    Only called when _GMAIL_ENABLED is True and dry_run is False.
    """
    try:
        sent = gmail.send(alert)
        if sent:
            ctrs["email_sent"] += 1
            logging.info(
                f"Email sent  rule={alert.get('rule_id','?')}"
                f"  sev={alert.get('severity','?')}"
                f"  src={alert.get('srcip','')}  label={label}"
            )
        # send() returns False for dedup/severity skip — not an error,
        # so we don't increment email_err here.
    except Exception as exc:
        ctrs["email_err"] += 1
        logging.error(f"GmailAlerter.send raised unexpectedly: {exc}")
        print(f"  {C.RED}[EMAIL ERROR]{C.RESET} {exc}")


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args()
    _setup_logging(args.debug)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    # ── SEC-1: TheHive API key guard ──────────────────────────────────────
    if not _THEHIVE_KEY:
        print(
            f"\n  {C.RED}[FATAL]{C.RESET} You don't export your crendential yet!!"
            f"\n  {C.RED}[FATAL]{C.RESET} Please Copy that and Paste.\n"
            f"export THEHIVE_KEY=\"OsI8EYIrkrecKmH7tq0pUAt24l9Sp9P9\"\n",
            f"export GMAIL_USER=\"sop98886@gmail.com\"\n",
            f"export GMAIL_PASS=\"ctjh sfoc unju esss\"\n",
            f"export ALERT_TO=\"tithsopanha0@gmail.com\"\n",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"\n{C.CYAN}{C.BOLD}"
        f"╔{'═'*66}╗\n"
        f"║{'  WAZUH SOC → THEHIVE + GMAIL UNIFIED ENGINE':^66}║\n"
        f"║{'  Wazuh Threat-Hunting  +  Incident Management':^66}║\n"
        f"╚{'═'*66}╝{C.RESET}"
    )

    dry = args.dry_run
    if dry:
        print(f"  {C.YELLOW}[DRY-RUN MODE]{C.RESET} No TheHive or Gmail API calls will be made.\n")

    # ── Build TheHive client ──────────────────────────────────────────────
    try:
        client = TheHiveClient(
            url        = THEHIVE_URL,
            api_key    = _THEHIVE_KEY,
            verify_ssl = THEHIVE_VERIFY_SSL,
            timeout    = THEHIVE_TIMEOUT,
            retries    = THEHIVE_RETRIES,
        )
    except ValueError as exc:
        print(f"  {C.RED}[FATAL]{C.RESET} {exc}", file=sys.stderr)
        sys.exit(1)

    manager = TheHiveCaseManager(
        client,
        dry_run           = dry,
        case_min_severity = CASE_MIN_SEVERITY,
        case_dedup_sec    = CASE_DEDUP_SEC,
    )

    if not dry:
        print(f"  {C.STEEL}[*] Connecting to TheHive at {THEHIVE_URL}…{C.RESET}")
        if client.ping():
            print(f"  {C.GREEN}[+] TheHive connected.{C.RESET}\n")
            logging.info(f"TheHive connected: {THEHIVE_URL}")
        else:
            print(
                f"  {C.RED}[!] Cannot reach TheHive at {THEHIVE_URL}{C.RESET}\n"
                f"      Check THEHIVE_KEY, network, and SSL certificate.\n"
                f"      Running in terminal-only mode — no cases will be created.\n"
            )
            logging.error("TheHive unreachable — cases will not be created")

    # FIX 2: Gmail setup — instantiated here so there is exactly one
    # GmailAlerter in the process.  When disabled it still exists but
    # send() returns False immediately with no network calls.
    gmail: GmailAlerter | None = None
    if not dry:
        if _GMAIL_ENABLED:
            gmail = GmailAlerter(dedup_sec=EMAIL_DEDUP_SEC_UNIFIED)
            print(
                f"  {C.GREEN}[+] Gmail alerting enabled{C.RESET}"
                f"  →  {_GMAIL_TO}\n"
            )
            logging.info(f"Gmail alerting enabled  to={_GMAIL_TO}")
        else:
            print(
                f"  {C.GRAY}[~] Gmail alerting disabled{C.RESET}"
                f"  (set GMAIL_USER, GMAIL_PASS, ALERT_TO to enable)\n"
            )

    for path, label in [(ALERT_FILE, "alerts"), (ARCHIVES_FILE, "archives")]:
        if not Path(path).exists():
            print(
                f"  {C.ORANGE}[WARN]{C.RESET} {label} file not found: "
                f"{C.CYAN}{path}{C.RESET} — waiting for wazuh-manager…"
            )

    tail_mode   = not args.replay
    min_sev_val = SEVERITY_ORDER.get(MIN_SEVERITY, 2)

    tailer     = MultiTailer(tail_mode=tail_mode)
    correlator = Correlator()
    day        = _DayBoundary(DAY_TIMEZONE)
    dedup      = _AlertDedup()
    bf_tracker = _BruteForceTracker()
    ctrs       = _fresh_counters()
    cycle      = 0

    logging.info(
        f"Unified Interceptor started  "
        f"min_sev={MIN_SEVERITY}  tail={tail_mode}  "
        f"case_min_sev={CASE_MIN_SEVERITY}  "
        f"case_dedup={CASE_DEDUP_SEC}s  "
        f"gmail={'on' if _GMAIL_ENABLED else 'off'}  "
        f"dry={dry}"
    )

    try:
        while not _shutdown_requested:

            # ── Day-boundary rollover ─────────────────────────────────────
            if day.rolled_over():
                yesterday = day.active_day - timedelta(days=1)
                show_daily_summary(yesterday, day.session_start, ctrs, DAY_TIMEZONE)
                logging.info(
                    f"DAILY-SUMMARY  date={yesterday}  total={ctrs['total']}"
                    f"  CRIT={ctrs['CRITICAL']}  HIGH={ctrs['HIGH']}"
                    f"  hive_cases={ctrs['hive_cases']}"
                    f"  hive_resp_ok={ctrs['hive_resp_ok']}"
                    f"  hive_resp_err={ctrs['hive_resp_err']}"
                    f"  email_sent={ctrs['email_sent']}"
                    f"  email_err={ctrs['email_err']}"
                )
                ctrs = _fresh_counters()
                dedup.reset()
                bf_tracker.reset()
                correlator.reset()
                manager.reset()
                if gmail:
                    gmail.reset()   # FIX 5: reset Gmail dedup on day boundary
                cycle = 0
                print(
                    f"\n{C.CYAN}{C.BOLD}"
                    f"── New day: {day.active_day}  [{DAY_TIMEZONE}] ──"
                    f"{C.RESET}\n"
                )

            got_events = False

            for source, line in tailer.read_new_lines():
                if len(line) > 512_000:
                    logging.warning(
                        f"Oversized line ({len(line)}B) from {source} — skipped"
                    )
                    continue

                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    logging.debug(f"Bad JSON from {source}: {line[:120]}")
                    continue

                if not isinstance(raw, dict):
                    continue

                alert = build_alert(raw, source)
                if alert is None:
                    continue

                got_events = True
                rule_id  = alert["rule_id"]
                agent_id = alert.get("agent_id", "000")

                # ── Date filter ───────────────────────────────────────────
                if not day.alert_is_today(alert["timestamp"]):
                    ctrs["skipped"] += 1
                    continue

                # ── Brute-force escalation ────────────────────────────────
                alert = _escalate_brute_force(alert, bf_tracker)

                # ── Severity gate ─────────────────────────────────────────
                if SEVERITY_ORDER.get(alert["severity"], 0) < min_sev_val:
                    ctrs["skipped"] += 1
                    continue

                # ── Dedup ─────────────────────────────────────────────────
                if dedup.is_duplicate(alert):
                    ctrs["skipped"] += 1
                    continue

                sev = alert["severity"]
                ctrs["total"] += 1
                ctrs[sev]      = ctrs.get(sev, 0) + 1
                ctrs["src_alerts" if source == "alerts" else "src_archives"] += 1

                # ── Terminal display ──────────────────────────────────────
                show(alert)

                # ── TheHive: create case ──────────────────────────────────
                case_id = manager.process_alert(alert)

                if isinstance(case_id, str) and case_id:
                    ctrs["hive_cases"] += 1
                    if not dry:
                        _run_responder_and_log(client, case_id, ctrs, label="alert")

                elif case_id is False:
                    ctrs["hive_skipped"] += 1

                # FIX 3: Gmail — called for every alert that passes the
                # severity/dedup gates above, regardless of whether TheHive
                # accepted or dedup-skipped it.  GmailAlerter has its own
                # internal dedup (EMAIL_DEDUP_SEC_UNIFIED) so it won't
                # re-send within its own cooldown window.
                if gmail and not dry:
                    _send_email_and_log(gmail, alert, ctrs, label="alert")

                # ── Correlation engine ────────────────────────────────────
                if rule_id != "ARCHIVE":
                    correlator.add(rule_id, agent_id)
                    corr = correlator.check()
                    if corr:
                        show_correlation(corr)
                        logging.info(
                            f"CORRELATION {corr['name']}  "
                            f"sev={corr['severity']}  agent={agent_id}"
                        )

                        corr_id = manager.process_correlation(corr, agent_id)

                        if isinstance(corr_id, str) and corr_id:
                            ctrs["hive_cases"] += 1
                            if not dry:
                                _run_responder_and_log(
                                    client, corr_id, ctrs, label="correlation"
                                )
                                # Also email on correlation cases
                                if gmail:
                                    # Build a synthetic alert dict for the email
                                    corr_alert = {
                                        "severity":    corr["severity"],
                                        "level":       13 if corr["severity"] == "CRITICAL" else 10,
                                        "rule_id":     f"CORR:{corr['name']}",
                                        "description": corr["description"],
                                        "reason":      corr["description"],
                                        "agent_id":    agent_id,
                                        "agent_name":  alert.get("agent_name", "N/A"),
                                        "agent_ip":    alert.get("agent_ip", ""),
                                        "srcip":       alert.get("srcip", ""),
                                        "dstip":       alert.get("dstip", ""),
                                        "timestamp":   alert.get("timestamp", ""),
                                        "location":    alert.get("location", ""),
                                        "mitre":       [],
                                        "source":      source,
                                        "full_log":    "",
                                    }
                                    _send_email_and_log(
                                        gmail, corr_alert, ctrs, label="correlation"
                                    )

                        elif corr_id is False:
                            ctrs["hive_skipped"] += 1

                logging.info(
                    f"ALERT  src={source}  rule={rule_id}  sev={sev}"
                    f"  lvl={alert['level']}  agent={agent_id}"
                    f"  ip={alert.get('srcip','')}"
                    f"  desc={alert['description'][:80]}"
                )

            # ── Periodic maintenance ──────────────────────────────────────
            cycle += 1
            if cycle % 100 == 0:
                dedup.cleanup()
                bf_tracker.cleanup()
                manager.cleanup()
                if gmail:
                    gmail.cleanup()   # FIX 5: clean Gmail dedup on same cadence

            # FIX 6: stats banner includes email counters
            if cycle % 300 == 0:
                show_stats(day.active_day, ctrs, day.seconds_until_midnight())
                print(
                    f"  {C.TEAL}[INTEGRATION STATS]{C.RESET}"
                    f"  hive_cases={ctrs['hive_cases']}"
                    f"  hive_dedup={ctrs['hive_skipped']}"
                    f"  responder_ok={ctrs['hive_resp_ok']}"
                    f"  responder_err={ctrs['hive_resp_err']}"
                    f"  email_sent={ctrs['email_sent']}"
                    f"  email_err={ctrs['email_err']}"
                )

            if not got_events:
                time.sleep(POLL_INTERVAL)

    finally:
        show_shutdown(day.active_day, day.session_start, ctrs, DAY_TIMEZONE)
        logging.info(
            f"Unified Interceptor stopped"
            f"  total={ctrs['total']}"
            f"  CRIT={ctrs['CRITICAL']}"
            f"  HIGH={ctrs['HIGH']}"
            f"  hive_cases={ctrs['hive_cases']}"
            f"  hive_skipped={ctrs['hive_skipped']}"
            f"  hive_resp_ok={ctrs['hive_resp_ok']}"
            f"  hive_resp_err={ctrs['hive_resp_err']}"
            f"  email_sent={ctrs['email_sent']}"
            f"  email_err={ctrs['email_err']}"
        )
        sys.exit(0)


# ── Unified email dedup window ────────────────────────────────────────────────
# Mirrors CASE_DEDUP_SEC so email and TheHive stay in sync.
# Override by setting EMAIL_DEDUP_SEC env var.
EMAIL_DEDUP_SEC_UNIFIED: int = int(os.environ.get("EMAIL_DEDUP_SEC", CASE_DEDUP_SEC))


if __name__ == "__main__":
    main()