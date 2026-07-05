#!/usr/bin/env python3
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
    show_compact,
    show_correlation,
    show_daily_summary,
    show_shutdown,
    show_stats,
)
from intercept import MultiTailer, build_alert
from thehive_config import (
    CASE_DEDUP_SEC,
    CASE_MIN_SEVERITY,
    THEHIVE_RETRIES,
    THEHIVE_TIMEOUT,
    THEHIVE_URL,
    THEHIVE_VERIFY_SSL,
)
from thehive_observable import attach_observables
from thehive_client import TheHiveClient
from thehive_manager import TheHiveCaseManager
from thehive_responder import run_responder
from gmail_alert import GmailAlerter

# ── Unified email dedup window ────────────────────────────────────────────────
EMAIL_DEDUP_SEC_UNIFIED: int = int(os.environ.get("EMAIL_DEDUP_SEC", CASE_DEDUP_SEC))

# ── API keys / credentials ────────────────────────────────────────────────────
_THEHIVE_KEY: str = os.environ.get("THEHIVE_KEY", "").strip()

_GMAIL_USER:    str  = os.environ.get("GMAIL_USER", "").strip()
_GMAIL_PASS:    str  = os.environ.get("GMAIL_PASS", "").strip()
_GMAIL_TO:      str  = os.environ.get("ALERT_TO",   "").strip()
_GMAIL_ENABLED: bool = bool(_GMAIL_USER and _GMAIL_PASS and _GMAIL_TO)
_VERBOSE: bool = False
# ── Cortex responder names ────────────────────────────────────────────────────
# NOTE: These names are used ONLY as a local switch in thehive_responder.py.
# thehive_responder.py bypasses Cortex entirely and calls the Wazuh REST API
# directly, so Cortex's version-suffix behaviour (e.g. appending _1_0) does
# NOT affect anything here.
_RESPONDER_NETWORK: str = "Wazuh_1_0"
_RESPONDER_FIM:     str = "WazuhFIM_1_0"

# ── Rule → Cortex responder routing ──────────────────────────────────────────
_FIM_RULES: set[str] = {
    "100117", "100123",
    "550",    "553",    "554",
}

_NETWORK_RULES: set[str] = {
    "5503",   "5710",   "5712",
    "5715",   "5716",   "5758",
    "5763",
    "651",
    "100105", "100200",
    "100901", "100904",
    "100628", "100650", "100651",
    "100652", "100653", "100654",
    "100655", "100656", "100657",
    "100662", "100663",
    "100664", "100665",
    "100666", "100667", "100668",
    "100700",
    "100805", "100806", "100808",
    "100907",
    "100101",
}


def _get_responder(rule_id: str) -> Optional[str]:
    if rule_id in _FIM_RULES:
        return _RESPONDER_FIM
    if rule_id in _NETWORK_RULES:
        return _RESPONDER_NETWORK
    return None


# ── Counters ──────────────────────────────────────────────────────────────────
def _fresh_counters() -> dict:
    return {
        "total":          0,
        "CRITICAL":       0,
        "HIGH":           0,
        "MEDIUM":         0,
        "LOW":            0,
        "INFO":           0,
        "skipped":        0,
        "src_alerts":     0,
        "src_archives":   0,
        "hive_cases":     0,
        "hive_skipped":   0,
        "hive_resp_ok":   0,
        "hive_resp_skip": 0,   # FIX-1: new counter for "skipped" (no srcip)
        "hive_resp_err":  0,
        "email_sent":     0,
        "email_err":      0,
    "push_dropped":   0,
    }


# ── Brute-force tracker ───────────────────────────────────────────────────────
class _BruteForceTracker:
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
            "Required environment variables:\n"
            "  THEHIVE_KEY          TheHive API key\n"
            "  WAZUH_API_PASS       Wazuh Manager API password\n\n"
            "Optional environment variables (Gmail):\n"
            "  GMAIL_USER           Gmail sender address\n"
            "  GMAIL_PASS           Gmail App Password\n"
            "  ALERT_TO             Recipient address\n\n"
            "Other optional environment variables:\n"
            "  WAZUH_API_URL        Wazuh Manager URL (default: https://192.168.200.129:55000)\n"
            "  WAZUH_API_USER       Wazuh API username (default: wazuh-wui)\n"
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
    p.add_argument("--verbose", action="store_true",
                   help="Show full per-alert detail + case/responder/email confirmations "
                        "(default: compact one-line per alert, full detail still logged)")
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
    case_id:        str,
    ctrs:           dict,
    label:          str = "alert",
    responder_name: str = _RESPONDER_NETWORK,
) -> None:

    try:
        result = run_responder(
            client         = client,
            case_id        = case_id,
            responder_name = responder_name,
            poll_result    = False,
        )
        status = result.get("status", "failed")

        if status == "triggered":
            ctrs["hive_resp_ok"] += 1
            if _VERBOSE:
                print(
                    f"  {C.TEAL}[RESPONDER]{C.RESET} case={case_id}"
                    f"  responder={responder_name}"
                    f"  action_id={result['action_id']}"
                    f"  ({label})"
                )
            logging.info(
                f"Responder triggered  case={case_id}"
                f"  action_id={result['action_id']}  label={label}"
            )

        elif status == "skipped":
            ctrs["hive_resp_skip"] = ctrs.get("hive_resp_skip", 0) + 1
            if _VERBOSE:
                print(
                    f"  {C.GRAY}[RESPONDER SKIP]{C.RESET} case={case_id}"
                    f"  responder={responder_name}"
                    f"  reason={result.get('error','no reason given')}"
                    f"  ({label})"
                )
            logging.info(
                f"Responder skipped (expected)  case={case_id}"
                f"  reason={result.get('error','')}  label={label}"
            )

        else:
            ctrs["hive_resp_err"] += 1
            if _VERBOSE:
                print(
                    f"  {C.ORANGE}[RESPONDER WARN]{C.RESET} case={case_id}"
                    f"  status={status}"
                    f"  error={result.get('error','')}"
                    f"  ({label})"
                )
            logging.warning(
                f"Responder failed  case={case_id}"
                f"  status={status}  error={result.get('error','')}  label={label}"
            )

    except Exception as exc:
        ctrs["hive_resp_err"] += 1
        logging.error(f"run_responder raised unexpectedly case={case_id}: {exc}")


# ── Gmail send helper ─────────────────────────────────────────────────────────
def _send_email_and_log(
    gmail: GmailAlerter,
    alert: dict,
    ctrs:  dict,
    label: str = "alert",
) -> None:
    try:
        sent = gmail.send(alert)
        if sent:
            ctrs["email_sent"] += 1
            logging.info(
                f"Email sent  rule={alert.get('rule_id','?')}"
                f"  sev={alert.get('severity','?')}"
                f"  src={alert.get('srcip','')}  label={label}"
            )
    except Exception as exc:
        ctrs["email_err"] += 1
        logging.error(f"GmailAlerter.send raised unexpectedly: {exc}")
        print(f"  {C.RED}[EMAIL ERROR]{C.RESET} {exc}")


# ── Main loop ─────────────────────────────────────────────────────────────────
def main() -> None:
    args = _parse_args()
    _setup_logging(args.debug)

    global _VERBOSE
    _VERBOSE = args.verbose
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    if not _THEHIVE_KEY:
        # FIX-2: Do not print real credentials in the error hint.
        print(
            f"\n  {C.RED}[FATAL]{C.RESET} THEHIVE_KEY not set. Export credentials first:\n"
            f"\n"
            f"  export THEHIVE_KEY=\"your-thehive-api-key"\n"
            f"  export WAZUH_API_PASS=\"your-wazuh-api-key\"\n"
            f"  export GMAIL_USER=\"sop98886@gmail.com\"\n"
            f"  export GMAIL_PASS=\"your-gmail-pass\"\n"
            f"  export ALERT_TO=\"tithsopanha0@gmail.com\"\n",
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
        verbose           = _VERBOSE
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

    gmail: Optional[GmailAlerter] = None
    if not dry:
        if _GMAIL_ENABLED:
            gmail = GmailAlerter(dedup_sec=EMAIL_DEDUP_SEC_UNIFIED, verbose=_VERBOSE)
            print(f"  {C.GREEN}[+] Gmail alerting enabled{C.RESET}  →  {_GMAIL_TO}\n")
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
    if args.replay:
        print(
            f"  {C.ORANGE}[WARN]{C.RESET} --replay has no effect with the "
            f"push-socket architecture (PushListener has no file to replay "
            f"from). Use intercept.py --replay against alerts.json/archives.json "
            f"directly if you need to backtest historical data.\n"
        )
        logging.warning("--replay flag passed but PushListener ignores it — no-op")
    min_sev_val = SEVERITY_ORDER.get(MIN_SEVERITY, 2)

    from push_listener import PushListener
    tailer     = PushListener()
    tailer.start()
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
                    f"  hive_resp_skip={ctrs.get('hive_resp_skip',0)}"
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
                    gmail.reset()
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
                if _VERBOSE:
                    show(alert)
                else:
                    show_compact(alert)

                # ── TheHive: create case ──────────────────────────────────
                case_id = manager.process_alert(alert)

                if isinstance(case_id, str) and case_id:
                    ctrs["hive_cases"] += 1

                    if not dry:
                        # ── Step 1: post observables + trigger analyzers ───
                        obs_result = attach_observables(
                            client,
                            case_id,
                            alert,
                            default_tlp = 2,   # AMBER
                            default_pap = 2,   # AMBER
                        )
                        logging.info(
                            f"Observables added  case={case_id}  rule={rule_id}  "
                            f"added={obs_result['added']}  "
                            f"ioc={obs_result['ioc_count']}  "
                            f"hash={obs_result['hash_count']}  "
                            f"skipped={obs_result['skipped']}  "
                            f"failed={obs_result['failed']}"
                        )

                        # FIX-4: Removed the 5s sleep that waited for analyzers
                        # before firing responders.  Analyzers run independently
                        # in Cortex; the responder goes directly to Wazuh API
                        # and doesn't depend on analyzer results at all.

                        # ── Step 2: trigger Wazuh active response ──────────
                        chosen_responder = _get_responder(rule_id)
                        if chosen_responder:
                            _run_responder_and_log(
                                client,
                                case_id,
                                ctrs,
                                label          = f"rule:{rule_id}",
                                responder_name = chosen_responder,
                            )

                elif case_id is False:
                    ctrs["hive_skipped"] += 1

                # ── Gmail alert ───────────────────────────────────────────
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
                                # Correlation cases always use the network responder.
                                # If no srcip is available, run_responder() returns
                                # status="skipped" which _run_responder_and_log
                                # now handles correctly (FIX-1).
                                _run_responder_and_log(
                                    client, corr_id, ctrs,
                                    label          = "correlation",
                                    responder_name = _RESPONDER_NETWORK,
                                )
                                if gmail:
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
                    gmail.cleanup()
                ctrs["push_dropped"] = tailer.dropped_count


            if cycle % 300 == 0:
                show_stats(day.active_day, ctrs, day.seconds_until_midnight())
                print(
                    f"  {C.TEAL}[INTEGRATION STATS]{C.RESET}"
                    f"  hive_cases={ctrs['hive_cases']}"
                    f"  hive_dedup={ctrs['hive_skipped']}"
                    f"  responder_ok={ctrs['hive_resp_ok']}"
                    f"  responder_skip={ctrs.get('hive_resp_skip',0)}"
                    f"  responder_err={ctrs['hive_resp_err']}"
                    f"  email_sent={ctrs['email_sent']}"
                    f"  email_err={ctrs['email_err']}"
                    f"  push_dropped={ctrs.get('push_dropped',0)}"
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
            f"  hive_resp_skip={ctrs.get('hive_resp_skip',0)}"
            f"  hive_resp_err={ctrs['hive_resp_err']}"
            f"  email_sent={ctrs['email_sent']}"
            f"  email_err={ctrs['email_err']}"
        )


if __name__ == "__main__":
    main()
