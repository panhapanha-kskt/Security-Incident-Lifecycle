from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from collections import deque
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from classifier import SEVERITY_ORDER, classify_rule, get_mitre, safe_level
from config import (
    ALERT_FILE,
    ARCHIVES_FILE,
    BRUTE_FORCE_WINDOW,
    CORRELATION_WINDOW,
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
    sanitize,
    show,
    show_compact,
    show_correlation,
    show_daily_summary,
    show_shutdown,
    show_stats,
)
# ── Argument parsing 
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SOC Real-Time Alert Interceptor for Wazuh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--replay",
        action="store_true",
        help="Replay existing file content from the beginning (default: tail mode – skip history)",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Log every skipped alert with the reason it was skipped",
    )
    p.add_argument(
    "--verbose",
    action="store_true",
    help="Show full per-alert detail block (default: compact one-line per alert)",
    )
    return p.parse_args()
# ── Logging setup
def _setup_logging(debug: bool) -> None:
    log_path = Path(LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)

    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG if debug else logging.INFO)
    fh.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    root.addHandler(fh)
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root.addHandler(ch)
# ── Timezone 
def _load_tz() -> ZoneInfo:
    try:
        return ZoneInfo(DAY_TIMEZONE)
    except ZoneInfoNotFoundError:
        logging.warning(f"DAY_TIMEZONE '{DAY_TIMEZONE}' not found – falling back to UTC")
        return ZoneInfo("UTC")
DAY_TZ: ZoneInfo = _load_tz()
def _now_local() -> datetime:
    return datetime.now(DAY_TZ)
def _today_local() -> date:
    return _now_local().date()
def _parse_alert_date(ts_str: str) -> Optional[date]:
    if not ts_str:
        return None
    import re
    ts = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', str(ts_str))
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(DAY_TZ).date()
    except (ValueError, AttributeError):
        return None
class DayBoundary:
    def __init__(self) -> None:
        self._day: date = _today_local()
        self._session_start: datetime = _now_local()
        print(
            f"\n{C.CYAN}{C.BOLD}Day-boundary active  │  "
            f"date={self._day}  │  tz={DAY_TIMEZONE}{C.RESET}\n"
        )
        logging.info(f"DAY-BOUNDARY start day={self._day} tz={DAY_TIMEZONE}")
    @property
    def active_day(self) -> date:
        return self._day
    @property
    def session_start(self) -> datetime:
        return self._session_start
    def rolled_over(self) -> bool:
        today = _today_local()
        if today != self._day:
            self._day = today
            self._session_start = _now_local()
            logging.info(f"DAY-BOUNDARY rollover new_day={self._day}")
            return True
        return False
    def alert_is_today(self, ts_str: str) -> bool:
        d = _parse_alert_date(ts_str)
        if d is None:
            return True
        return d == self._day
    def seconds_until_midnight(self) -> float:
        now = _now_local()
        tomorrow = datetime.combine(
            self._day + timedelta(days=1), datetime.min.time(), tzinfo=DAY_TZ
        )
        return max(0.0, (tomorrow - now).total_seconds())
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
    }
_failed_logins: dict[str, deque]  = {}
_dedup:         dict[str, float]  = {}
counters: dict = _fresh_counters()
def _record_failed_login(srcip: str) -> None:
    now = time.monotonic()
    if srcip not in _failed_logins:
        _failed_logins[srcip] = deque()
    _failed_logins[srcip].append(now)
    _evict_login(srcip, now)
def _evict_login(srcip: str, now: float) -> None:
    cutoff = now - BRUTE_FORCE_WINDOW
    q = _failed_logins.get(srcip)
    if q:
        while q and q[0] < cutoff:
            q.popleft()
def _failed_login_count(srcip: str) -> int:
    now    = time.monotonic()
    cutoff = now - BRUTE_FORCE_WINDOW
    q      = _failed_logins.get(srcip)
    if not q:
        return 0
    return sum(1 for t in q if t >= cutoff)
def escalate_brute_force(alert: dict) -> dict:
    rule_id = alert.get("rule_id", "")
    srcip   = alert.get("srcip", "")

    if rule_id not in FAILED_LOGIN_RULES or not srcip:
        return alert
    _record_failed_login(srcip)
    count = _failed_login_count(srcip)
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
def build_alert(raw: dict, source: str) -> Optional[dict]:
    try:
        rule   = raw.get("rule") or {}
        agent  = raw.get("agent") or {}
        data   = raw.get("data") or {}
        if source == "archives" and not rule:
            rule_id = "ARCHIVE"
            level   = 0
            desc    = sanitize(
                str(raw.get("full_log", raw.get("location", "Archive event"))), 500
            )
        else:
            rule_id = sanitize(str(rule.get("id") or "").strip(), 20)
            level   = safe_level(rule.get("level"))
            desc    = sanitize(str(rule.get("description") or ""), 500)

        if source == "alerts" and not rule_id:
            return None
        srcip = sanitize(
            str(data.get("srcip") or data.get("src_ip") or
                 raw.get("srcip") or raw.get("src_ip") or
                 raw.get("zeek", {}).get("id.orig_h") or ""), 45
        )
        dstip = sanitize(
            str(data.get("dstip") or data.get("dst_ip") or
                 raw.get("dstip") or raw.get("dst_ip") or
                 raw.get("zeek", {}).get("id.resp_h") or ""), 45
        )
        location = sanitize(str(raw.get("location") or ""), 300)
        full_log = sanitize(str(raw.get("full_log")  or ""), 600)
        ts       = str(raw.get("timestamp") or "")
        agent_name = sanitize(str(agent.get("name") or "wazuh-manager"), 100)
        agent_id   = sanitize(str(agent.get("id")   or "000").strip(), 10)
        agent_ip   = sanitize(str(agent.get("ip")   or ""), 45)
        syscheck = raw.get("syscheck", {})
        file_path = sanitize(str(syscheck.get("path", "")), 300)
        file_event = sanitize(str(syscheck.get("event", "")), 50)
        suricata = data.get("alert", {})
        suri_sig      = sanitize(str(suricata.get("signature", "")), 500)
        suri_cat      = sanitize(str(suricata.get("category", "")), 200)
        suri_sev      = sanitize(str(suricata.get("severity", "")), 10)
        zeek = raw.get("zeek", {})
        zeek_service  = sanitize(str(zeek.get("service", "")), 100)
        zeek_proto    = sanitize(str(zeek.get("proto", "")), 20)
        zeek_uid      = sanitize(str(zeek.get("uid", "")), 50)
        mitre = []   # prevent UnboundLocalError
        if rule_id == "ARCHIVE":
            sev = "LOW"
            decoder_name = (
                raw.get("decoder", {})
                   .get("name", "")
            )
            reason = f"Archive event ({decoder_name})"
        else:
            sev, reason = classify_rule(rule_id, level, desc)
            mitre = get_mitre(rule_id)
            # Merge native MITRE tags from the rule itself
            native_mitre = rule.get("mitre", {}).get("id", [])
            if native_mitre:
                mitre.extend(native_mitre)
                mitre = sorted(set(mitre))

        return {
            "id":               sanitize(str(raw.get("id") or ""), 64),
            "timestamp":        ts,
            "level":            level,
            "severity":         sev,
            "rule_id":          rule_id,
            "description":      desc,
            "reason":           reason,
            "mitre":            mitre,
            "agent_id":         agent_id,
            "agent_name":       agent_name,
            "agent_ip":         agent_ip,
            "srcip":            srcip,
            "dstip":            dstip,
            "location":         location,
            "full_log":         full_log,
            "file_path":        file_path,
            "file_event":       file_event,
            "suricata_signature": suri_sig,
            "suricata_category":  suri_cat,
            "suricata_severity":  suri_sev,
            "zeek_service":     zeek_service,
            "zeek_proto":       zeek_proto,
            "zeek_uid":         zeek_uid,
            "source":           source,
        }

    except Exception as exc:
        logging.debug(f"build_alert failed: {exc}  raw={str(raw)[:200]}")
        return None
class FileTailer:
    def __init__(self, path: str, tail_mode: bool = False) -> None:
        self.path       = Path(path)
        self._offset:   int          = 0
        self._ino:      Optional[int] = None
        self._tail_mode: bool        = tail_mode
        self._initialised: bool      = False
        self._buf:      str          = ""

    def read_lines(self) -> list[str]:
        if not self.path.exists() or not self.path.is_file():
            return []
        try:
            st = self.path.stat()
        except OSError:
            return []

        if self._ino is not None and self._ino != st.st_ino:
            logging.info(f"FileTailer: rotation detected for {self.path}")
            self._offset = 0
            self._buf    = ""

        self._ino = st.st_ino

        try:
            with open(self.path, "r", errors="replace") as f:
                if not self._initialised:
                    self._initialised = True
                    if self._tail_mode:
                        f.seek(0, 2)
                        self._offset = f.tell()
                        return []
                    else:
                        self._offset = 0

                f.seek(0, 2)
                eof = f.tell()
                if eof < self._offset:
                    logging.info(f"FileTailer: truncation detected for {self.path}")
                    self._offset = 0
                    self._buf    = ""

                if eof == self._offset:
                    return []

                f.seek(self._offset)
                chunk = f.read(1_048_576)
                self._offset = f.tell()

        except (OSError, PermissionError) as exc:
            logging.warning(f"FileTailer read error {self.path}: {exc}")
            return []
        if not chunk:
            return []
        self._buf += chunk
        lines = self._buf.split("\n")
        self._buf = lines[-1]
        return [ln.strip() for ln in lines[:-1] if ln.strip()]
class MultiTailer:
    def __init__(self, tail_mode: bool = False) -> None:
        self._tailers: dict[str, FileTailer] = {
            "alerts":   FileTailer(ALERT_FILE,    tail_mode),
            "archives": FileTailer(ARCHIVES_FILE, tail_mode),
        }

    def read_new_lines(self) -> Iterator[tuple[str, str]]:
        for source, tailer in self._tailers.items():
            for line in tailer.read_lines():
                yield source, line
# ── Memory cleanup
def cleanup_memory() -> None:
    now = time.monotonic()
    for key in list(_dedup.keys()):
        if _dedup[key] < now - DEDUP_WINDOW:
            del _dedup[key]

    for ip in list(_failed_logins.keys()):
        _evict_login(ip, now)
        if not _failed_logins[ip]:
            del _failed_logins[ip]
# ── Graceful shutdown 
_shutdown_requested: bool = False
def _handle_signal(signum, frame) -> None:
    global _shutdown_requested
    _shutdown_requested = True
# ── Main loop 
def main() -> None:
    args = _parse_args()
    _setup_logging(args.debug)
    verbose = args.verbose
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)
    tail_mode = not args.replay

    min_sev_value = SEVERITY_ORDER.get(MIN_SEVERITY, 2)

    print(
        f"\n{C.GREEN}{C.BOLD}"
        f"╔{'═'*60}╗\n"
        f"║{'  SOC REAL-TIME ALERT INTERCEPTOR':^60}║\n"
        f"║{'  Wazuh Threat-Hunting Mode':^60}║\n"
        f"╚{'═'*60}╝{C.RESET}"
    )
    for path, label in [(ALERT_FILE, "alerts"), (ARCHIVES_FILE, "archives")]:
        if not Path(path).exists():
            print(
                f"  {C.ORANGE}[WARN]{C.RESET} {label} file not found: "
                f"{C.CYAN}{path}{C.RESET} — waiting for wazuh-manager…"
            )
    tailer     = MultiTailer(tail_mode=tail_mode)
    correlator = Correlator()
    day        = DayBoundary()
    cycle      = 0

    logging.info(
        f"Interceptor started  min_sev={MIN_SEVERITY} tail={tail_mode} "
        f"poll={POLL_INTERVAL}s"
    )
    try:
        while not _shutdown_requested:
            if day.rolled_over():
                yesterday = day.active_day - timedelta(days=1)
                show_daily_summary(yesterday, day.session_start, counters, DAY_TIMEZONE)
                logging.info(
                    f"DAILY-SUMMARY date={yesterday} total={counters['total']} "
                    f"CRIT={counters['CRITICAL']} HIGH={counters['HIGH']} "
                    f"MED={counters['MEDIUM']} LOW={counters['LOW']} "
                    f"skip={counters['skipped']}"
                )
                counters.update(_fresh_counters())
                _dedup.clear()
                _failed_logins.clear()
                correlator.reset()
                cycle = 0
                print(
                    f"\n{C.CYAN}{C.BOLD}"
                    f"── New day: {day.active_day}  [{DAY_TIMEZONE}] ──"
                    f"{C.RESET}\n"
                )
            got_events = False
            for source, line in tailer.read_new_lines():
                if len(line) > 512_000:
                    logging.warning(f"Oversized line ({len(line)} bytes) from {source} – skipped")
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
                rule_id = alert["rule_id"]
                level   = alert["level"]

                if not day.alert_is_today(alert["timestamp"]):
                    counters["skipped"] += 1
                    logging.debug(f"SKIP date-filter rule={rule_id} ts={alert['timestamp']}")
                    continue
                alert = escalate_brute_force(alert)
                sev_val = SEVERITY_ORDER.get(alert["severity"], 0)
                if sev_val < min_sev_value:
                    counters["skipped"] += 1
                    logging.debug(
                        f"SKIP sev-filter rule={rule_id} "
                        f"sev={alert['severity']} min={MIN_SEVERITY}"
                    )
                    continue
                # Dedup key now includes file_path to prevent FIM suppression
                agent_id = alert.get("agent_id", "000")
                srcip    = alert.get("srcip", "")
                file_p   = alert.get("file_path", "")
                dup_key  = f"{rule_id}|{agent_id}|{srcip}|{file_p}"
                now_mono = time.monotonic()

                if dup_key in _dedup and (now_mono - _dedup[dup_key]) < DEDUP_WINDOW:
                    counters["skipped"] += 1
                    logging.debug(
                        f"SKIP dedup rule={rule_id} agent={agent_id} src={srcip} file={file_p}"
                    )
                    continue
                _dedup[dup_key] = now_mono

                sev = alert["severity"]
                counters["total"] += 1
                counters[sev]      = counters.get(sev, 0) + 1
                if source == "alerts":
                    counters["src_alerts"]   += 1
                else:
                    counters["src_archives"] += 1

                if verbose:
                    show(alert)
                else:
                    show_compact(alert)
                # Agent-aware correlation
                if rule_id != "ARCHIVE":
                    correlator.add(rule_id, agent_id)
                    result = correlator.check()
                    if result:
                        show_correlation(result)
                        logging.info(
                            f"CORRELATION {result['name']} sev={result['severity']} "
                            f"agent={agent_id}"
                        )
                logging.info(
                    f"ALERT src={source} rule={rule_id} sev={sev} "
                    f"lvl={level} agent={agent_id} ip={srcip} "
                    f"desc={alert['description'][:80]}"
                )
            cycle += 1
            if cycle % 100 == 0:
                cleanup_memory()
            if cycle % 300 == 0:
                show_stats(day.active_day, counters, day.seconds_until_midnight())
            if not got_events:
                time.sleep(POLL_INTERVAL)
    finally:
        show_shutdown(day.active_day, day.session_start, counters, DAY_TIMEZONE)
        logging.info(
            f"Interceptor stopped  total={counters['total']} "
            f"CRIT={counters['CRITICAL']} HIGH={counters['HIGH']}"
        )
        sys.exit(0)
if __name__ == "__main__":
    main()
