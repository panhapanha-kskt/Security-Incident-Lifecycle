from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import re
import sys
_USE_COLOR = sys.stdout.isatty()

def _c(code: str) -> str:
    return code if _USE_COLOR else ""
class C:
    RESET   = _c("\033[0m")
    BOLD    = _c("\033[1m")
    DIM     = _c("\033[2m")
    ITALIC  = _c("\033[3m")

    BLUE    = _c("\033[38;5;27m")
    CYAN    = _c("\033[38;5;51m")
    STEEL   = _c("\033[38;5;153m")
    SKY     = _c("\033[38;5;117m")
    TEAL    = _c("\033[38;5;80m")

    WHITE   = _c("\033[38;5;255m")
    LGRAY   = _c("\033[38;5;252m")
    GRAY    = _c("\033[38;5;244m")
    DGRAY   = _c("\033[38;5;238m")

    RED     = _c("\033[38;5;196m")
    ORANGE  = _c("\033[38;5;208m")
    YELLOW  = _c("\033[38;5;226m")
    GREEN   = _c("\033[38;5;47m")
    PURPLE  = _c("\033[38;5;135m")
    PINK    = _c("\033[38;5;213m")

    @staticmethod
    def sev(level: str) -> str:
        return {
            "CRITICAL": C.RED    + C.BOLD,
            "HIGH":     C.ORANGE + C.BOLD,
            "MEDIUM":   C.YELLOW,
            "LOW":      C.SKY,
            "INFO":     C.GRAY,
        }.get(level, C.WHITE)

    @staticmethod
    def sev_bg(level: str) -> str:
        return {
            "CRITICAL": _c("\033[41;97;1m"),
            "HIGH":     _c("\033[48;5;166m\033[38;5;0m\033[1m"),
            "MEDIUM":   _c("\033[48;5;226m\033[38;5;0m"),
            "LOW":      _c("\033[48;5;24m\033[38;5;255m"),
            "INFO":     _c("\033[48;5;237m\033[38;5;244m"),
        }.get(level, _c("\033[7m"))

# ── Security helpers ─────────────────────────────────────────
_ANSI_RE   = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
_CTRL_RE   = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_INJECT_RE = re.compile(r'[\r\n]')

def sanitize(text: str, max_len: int = 1000) -> str:
    s = _ANSI_RE.sub('', str(text))
    s = _CTRL_RE.sub('', s)
    s = _INJECT_RE.sub(' ', s)
    return s[:max_len]


def format_timestamp(iso_str: str) -> str:
    if not iso_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")
    ts = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', str(iso_str))
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return sanitize(iso_str, 40)

_COMPACT_SEV_LABEL = {
    "CRITICAL": "CRIT",
    "HIGH":     "HIGH",
    "MEDIUM":   "MED ",
    "LOW":      "LOW ",
    "INFO":     "INFO",
}
def show_compact(alert: dict) -> None:
    sev        = alert.get("severity", "INFO")
    rule_id    = sanitize(alert.get("rule_id", "—"), 20)
    desc       = sanitize(alert.get("reason") or alert.get("description", ""), 90)
    agent_name = sanitize(alert.get("agent_name", ""), 30)
    agent_id   = sanitize(alert.get("agent_id", ""), 10)
    srcip      = sanitize(alert.get("srcip", ""), 45)
    ts_display = format_timestamp(alert.get("timestamp", ""))

    sev_color = C.sev(sev)
    label     = _COMPACT_SEV_LABEL.get(sev, (sev + "    ")[:4])
    ip_part   = f"  {C.ORANGE}{srcip}{C.RESET}" if srcip else ""

    print(
        f"{C.DIM}{ts_display}{C.RESET}  "
        f"{sev_color}{label}{C.RESET}  "
        f"{C.CYAN}{rule_id:<8}{C.RESET} "
        f"{C.WHITE}{agent_name}{C.RESET}{C.GRAY}({agent_id}){C.RESET}"
        f"{ip_part}  "
        f"{desc}"
    )

def _source_tag(source: str) -> str:
    if source == "archives":
        return f"{C.TEAL}[ARCHIVES]{C.RESET}"
    return f"{C.GREEN}[ALERTS  ]{C.RESET}"
_BADGES = {
    "CRITICAL": "CRITICAL",
    "HIGH":     " HIGH   ",
    "MEDIUM":   " MEDIUM ",
    "LOW":      "  LOW   ",
    "INFO":     "  INFO  ",
}
def _badge(sev: str) -> str:
    label = _BADGES.get(sev, " UNKNOWN")
    return f"{C.sev_bg(sev)} {label} {C.RESET}"


_DIV_HEAVY  = f"{C.DGRAY}{'═' * 76}{C.RESET}"
_DIV_LIGHT  = f"{C.DGRAY}{'─' * 76}{C.RESET}"
_DIV_CRIT   = f"{C.RED}{'▓' * 76}{C.RESET}"
_DIV_HIGH   = f"{C.ORANGE}{'▒' * 76}{C.RESET}"


def _top_divider(sev: str) -> str:
    if sev == "CRITICAL":
        return _DIV_CRIT
    if sev == "HIGH":
        return _DIV_HIGH
    return _DIV_HEAVY
def _field(label: str, value: str, color: str = "") -> None:
    col = color or C.WHITE
    pad = f"{C.STEEL}{label:<14}{C.RESET}"
    print(f"  {pad}  {col}{value}{C.RESET}")
def show(alert: dict) -> None:
    sev           = alert.get("severity", "INFO")
    rule_id       = sanitize(alert.get("rule_id", "—"), 20)
    level         = alert.get("level", 0)
    desc          = sanitize(alert.get("description", ""), 500)
    reason        = sanitize(alert.get("reason", ""), 200)
    srcip         = sanitize(alert.get("srcip", ""), 45)
    dstip         = sanitize(alert.get("dstip", ""), 45)
    agent_id      = sanitize(alert.get("agent_id", ""), 10)
    agent_name    = sanitize(alert.get("agent_name", ""), 100)
    agent_ip      = sanitize(alert.get("agent_ip", ""), 45)
    location      = sanitize(alert.get("location", ""), 200)
    full_log      = sanitize(alert.get("full_log", ""), 400)
    mitre         = alert.get("mitre", [])
    source        = alert.get("source", "alerts")
    ts_display    = format_timestamp(alert.get("timestamp", ""))

    file_path     = sanitize(alert.get("file_path", ""), 300)
    file_event    = sanitize(alert.get("file_event", ""), 50)
    suri_sig      = sanitize(alert.get("suricata_signature", ""), 500)
    suri_cat      = sanitize(alert.get("suricata_category", ""), 200)
    suri_sev      = sanitize(alert.get("suricata_severity", ""), 10)
    zeek_svc      = sanitize(alert.get("zeek_service", ""), 100)
    zeek_proto    = sanitize(alert.get("zeek_proto", ""), 20)

    event_type = "GENERIC"
    if file_path:
        event_type = "FILE INTEGRITY"
    elif suri_sig:
        event_type = "IDS"
    elif zeek_svc or zeek_proto:
        event_type = "NETWORK"
    elif rule_id == "ARCHIVE":
        event_type = "ARCHIVE"

    sev_color   = C.sev(sev)
    badge       = _badge(sev)
    source_tag  = _source_tag(source)

    print(_top_divider(sev))

    print(
        f"  {C.STEEL}{'TIMESTAMP':<14}{C.RESET}  "
        f"{C.CYAN}{C.BOLD}{ts_display}{C.RESET}"
        f"   {badge}  {source_tag}"
    )

    print(
        f"  {C.STEEL}{'RULE':<14}{C.RESET}  "
        f"{C.GRAY}ID: {C.CYAN}{rule_id:<12}{C.RESET}"
        f"  {C.GRAY}Level: {sev_color}{C.BOLD}{level}{C.RESET}"
    )

    _field("DESCRIPTION", desc, sev_color)

    if reason and reason != desc:
        _field("REASON", reason, C.WHITE)

    _field("TYPE", f"{C.BOLD}{event_type}{C.RESET}", C.STEEL)

    print(f"  {C.DGRAY}{'·' * 72}{C.RESET}")

    agent_str = f"{C.WHITE}{agent_name}{C.RESET}  {C.GRAY}(ID: {C.STEEL}{agent_id}{C.RESET}{C.GRAY}){C.RESET}"
    _field("AGENT", agent_str)
    if agent_ip:
        _field("AGENT_IP", agent_ip, C.CYAN)

    if file_path:
        _field("FILE", file_path, C.ORANGE)
        if file_event:
            _field("ACTION", file_event, C.YELLOW)

    if srcip or dstip:
        parts = []
        if srcip:
            parts.append(f"{C.ORANGE}SRC  {srcip}{C.RESET}")
        if dstip:
            parts.append(f"{C.SKY}DST  {dstip}{C.RESET}")
        _field("NETWORK", "   ".join(parts))

    if suri_sig:
        _field("SIGNATURE", suri_sig, C.RED + C.BOLD)
        if suri_cat:
            _field("CATEGORY", suri_cat, C.PURPLE)
        if suri_sev:
            _field("IDS SEV", suri_sev, C.YELLOW)

    if zeek_svc:
        _field("ZEEK SVC", zeek_svc, C.TEAL)
    if zeek_proto:
        _field("ZEEK PROTO", zeek_proto, C.TEAL)

    if location:
        _field("LOCATION", location, C.LGRAY)

    if mitre:
        tags = "  ".join(f"{C.PURPLE}{m}{C.RESET}" for m in mitre)
        _field("MITRE", tags)

    if full_log:
        _field("LOG", full_log, C.DIM)

    print(_DIV_LIGHT)
def show_correlation(result: dict) -> None:
    sev  = result.get("severity", "HIGH")
    name = result.get("name", "UNKNOWN")
    desc = result.get("description", "")

    print(f"\n{C.RED}{C.BOLD}{'▀' * 76}{C.RESET}")
    print(
        f"  {C.RED}{C.BOLD}[CORRELATION ALERT]{C.RESET}  "
        f"{_badge(sev)}  "
        f"{C.WHITE}{C.BOLD}{name}{C.RESET}"
    )
    if desc:
        print(f"  {C.STEEL}{'DETAIL':<14}{C.RESET}  {C.YELLOW}{desc}{C.RESET}")
    print(f"{C.RED}{C.BOLD}{'▄' * 76}{C.RESET}\n")
def show_stats(day, ctrs: dict, secs_left: float) -> None:
    hrs  = int(secs_left // 3600)
    mins = int((secs_left % 3600) // 60)
    print(
        f"\n{C.BLUE}{C.BOLD}[LIVE STATS]{C.RESET}"
        f"  {C.STEEL}Day {C.CYAN}{day}{C.RESET}"
        f"  │  resets in {C.YELLOW}{hrs:02d}h{mins:02d}m{C.RESET}"
        f"  │  total {C.WHITE}{ctrs['total']}{C.RESET}"
        f"  {C.RED}CRIT:{ctrs['CRITICAL']}{C.RESET}"
        f"  {C.ORANGE}HIGH:{ctrs['HIGH']}{C.RESET}"
        f"  {C.YELLOW}MED:{ctrs['MEDIUM']}{C.RESET}"
        f"  {C.SKY}LOW:{ctrs['LOW']}{C.RESET}"
        f"  {C.GREEN}INFO:{ctrs['INFO']}{C.RESET}"
        f"  {C.GRAY}skip:{ctrs['skipped']}{C.RESET}"
    )
def show_daily_summary(day, session_start, ctrs: dict, tz_name: str) -> None:
    # datetime and ZoneInfo are imported at the top of this module
    tz       = ZoneInfo(tz_name)
    duration = str(datetime.now(tz) - session_start).split(".")[0]

    print(f"\n{C.BLUE}{C.BOLD}╔{'═' * 58}╗")
    header = f"  DAILY SUMMARY  {day}  [{tz_name}]"
    print(f"║{header:<58}║")
    print(f"╠{'═' * 58}╣{C.RESET}")

    rows = [
        ("Active window",       duration,              C.CYAN),
        ("Total alerts",        ctrs["total"],          C.WHITE),
        ("─" * 20,              "",                     C.DGRAY),
        ("CRITICAL",            ctrs["CRITICAL"],       C.RED    + C.BOLD if ctrs["CRITICAL"] else C.GRAY),
        ("HIGH",                ctrs["HIGH"],           C.ORANGE + C.BOLD if ctrs["HIGH"]     else C.GRAY),
        ("MEDIUM",              ctrs["MEDIUM"],         C.YELLOW if ctrs["MEDIUM"]             else C.GRAY),
        ("LOW",                 ctrs["LOW"],            C.SKY    if ctrs["LOW"]                else C.GRAY),
        ("INFO",                ctrs["INFO"],           C.GRAY),
        ("─" * 20,              "",                     C.DGRAY),
        ("Skipped/dedup",       ctrs["skipped"],        C.GRAY),
        ("From alerts.json",    ctrs.get("src_alerts",   0), C.GREEN),
        ("From archives.json",  ctrs.get("src_archives", 0), C.TEAL),
    ]

    for label, val, color in rows:
        if label.startswith("─"):
            print(f"{C.BLUE}╠{'─' * 58}╣{C.RESET}")
            continue
        print(
            f"{C.BLUE}║{C.RESET}"
            f"  {C.STEEL}{label:<26}{C.RESET}"
            f"  {color}{val}{C.RESET}"
        )

    print(f"{C.BLUE}╚{'═' * 58}╝{C.RESET}\n")
def show_shutdown(day, session_start, ctrs: dict, tz_name: str) -> None:
    # datetime and ZoneInfo are imported at the top of this module
    tz       = ZoneInfo(tz_name)
    duration = str(datetime.now(tz) - session_start).split(".")[0]

    print(f"\n{C.ORANGE}{C.BOLD}╔{'═' * 42}╗")
    print(f"║{'  INTERCEPTOR SHUTDOWN SUMMARY':<42}║")
    print(f"╠{'═' * 42}╣{C.RESET}")
    for label, val in [
        ("Day",           str(day)),
        ("Active window", duration),
        ("Total alerts",  ctrs["total"]),
        ("CRITICAL",      ctrs["CRITICAL"]),
        ("HIGH",          ctrs["HIGH"]),
        ("MEDIUM",        ctrs["MEDIUM"]),
        ("LOW",           ctrs["LOW"]),
        ("INFO",          ctrs["INFO"]),
        ("Skipped/dedup", ctrs["skipped"]),
    ]:
        print(f"{C.ORANGE}║{C.RESET}  {C.STEEL}{label:<20}{C.RESET}  {C.CYAN}{val}{C.RESET}")
    print(f"{C.ORANGE}╚{'═' * 42}╝{C.RESET}")
