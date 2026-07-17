#!/usr/bin/env python3
from __future__ import annotations  

import json
import os
import signal
import smtplib
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from classifier import SEVERITY_ORDER
from config import ALERT_FILE, ARCHIVES_FILE, POLL_INTERVAL
from display import C, show
from intercept import MultiTailer, build_alert

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT   = 587
SMTP_USER     = ""
SMTP_PASSWORD = ""
ALERT_EMAIL   = ""

EMAIL_DEDUP_SEC = 300   

class SMTPDeliveryError(Exception):
    """Raised by GmailAlerter.send() when SMTP fails (not on dedup/sev skip)."""


def _load_gmail_config() -> bool:
    global SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL
    SMTP_USER     = os.environ.get("GMAIL_USER", "").strip()
    SMTP_PASSWORD = os.environ.get("GMAIL_PASS", "").strip()
    ALERT_EMAIL   = os.environ.get("ALERT_TO",   "").strip()
    return bool(SMTP_USER and SMTP_PASSWORD and ALERT_EMAIL)

SEV_COLOR_CSS = {
    "CRITICAL": {"accent": "#E24B4A", "bg": "#791F1F", "dim": "rgba(226,75,74,.12)"},
    "HIGH":     {"accent": "#EF9F27", "bg": "#633806", "dim": "rgba(239,159,39,.12)"},
    "MEDIUM":   {"accent": "#378ADD", "bg": "#0C447C", "dim": "rgba(55,138,221,.12)"},
    "LOW":      {"accent": "#639922", "bg": "#27500A", "dim": "rgba(99,153,34,.12)"},
    "INFO":     {"accent": "#888780", "bg": "#444441", "dim": "rgba(136,135,128,.12)"},
}

def build_html_email(alert: dict) -> str:
    sev     = alert.get("severity", "INFO")
    colors  = SEV_COLOR_CSS.get(sev, SEV_COLOR_CSS["INFO"])
    accent  = colors["accent"]
    level   = alert.get("level", 0)
    rule_id = alert.get("rule_id", "—")
    desc    = alert.get("description", "No description")
    agent   = f"{alert.get('agent_name','—')} (ID: {alert.get('agent_id','—')})"
    agent_ip = alert.get("agent_ip", "—")
    srcip    = alert.get("srcip",    "—") or "—"
    dstip    = alert.get("dstip",    "—") or "—"
    location = alert.get("location", "—") or "—"
    source   = alert.get("source",   "—")
    reason   = alert.get("reason",   "—") or "—"
    mitre    = alert.get("mitre", [])
    full_log = (alert.get("full_log") or "")[:700]

    ts_raw = alert.get("timestamp", "")
    try:
        ts = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S"),
        )
    except Exception:
        ts = ts_raw

    now_str = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

    def kv(label: str, value: str, color: Optional[str] = None) -> str:
        vc = f"color:{color};" if color else "color:#cccccc;"
        return (
            f"<tr>"
            f'<td style="padding:7px 12px;border-bottom:1px solid #2a2a2a;font-size:10px;'
            f"color:#666;text-transform:uppercase;letter-spacing:.1em;"
            f'font-family:Courier New,monospace;width:130px;vertical-align:top;">{label}</td>'
            f'<td style="padding:7px 12px;border-bottom:1px solid #2a2a2a;font-size:12px;'
            f'{vc}font-family:Courier New,monospace;word-break:break-all;">{value}</td>'
            f"</tr>"
        )

    kv_rows = "".join([
        kv("Timestamp",  ts),
        kv("Rule ID",    rule_id, accent),
        kv("Reason",     reason),
        kv("Agent",      agent),
        kv("Agent IP",   agent_ip),
        kv("Source IP",  srcip, accent if srcip != "—" else None),
        kv("Dest IP",    dstip),
        kv("Location",   location),
        kv("Log Source", source),
    ])

    mitre_html = " ".join(
        f'<a href="https://attack.mitre.org/techniques/{m.replace(".","/")}" '
        f'style="display:inline-block;background:rgba(55,138,221,.15);border:1px solid rgba(55,138,221,.3);'
        f'border-radius:3px;padding:2px 7px;font-size:9px;color:#378ADD;margin:2px;text-decoration:none;">'
        f"{m}</a>"
        for m in mitre
    ) or '<span style="color:#555;">No MITRE mapping</span>'

    vt_link = ""
    if srcip != "—":
        vt_link = (
            f'<a href="https://www.virustotal.com/gui/ip-address/{srcip}" '
            f'style="display:inline-block;background:#1a1a1a;border:1px solid #333;'
            f"border-radius:4px;padding:5px 10px;font-size:11px;color:#888;"
            f'text-decoration:none;margin-right:7px;font-family:Courier New,monospace;">'
            f"&#128269; Check {srcip} on VirusTotal</a>"
        )

    raw_log_section = ""
    if full_log:
        raw_log_section = (
            f'<div style="margin-bottom:18px;">'
            f'<div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;'
            f'color:#555;margin-bottom:7px;">Raw Log (truncated)</div>'
            f'<pre style="background:#0d0d0d;border:1px solid #222;border-radius:4px;'
            f"padding:10px;font-family:Courier New,monospace;font-size:10px;color:#888;"
            f'white-space:pre-wrap;word-break:break-all;margin:0;">{full_log}</pre></div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>[SOC {sev}] Rule {rule_id}</title></head>
<body style="margin:0;padding:0;background:#f0f0f0;font-family:Courier New,monospace;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:28px 12px;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0"
  style="background:#111;border-radius:8px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.4);">

  <!-- identity strip -->
  <tr><td style="background:rgba(0,0,0,.4);padding:5px 22px;">
    <span style="font-size:9px;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.5);">
      CBSA GROUP 7 &middot; BLUE TEAM OPERATIONS CENTER &middot; WAZUH SOC DEFENSE PLATFORM
    </span>
  </td></tr>

  <!-- header -->
  <tr><td style="background:{accent};padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:18px 22px 18px;">
          <div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;
            color:rgba(255,255,255,.75);margin-bottom:5px;">Security Alert</div>
          <div style="font-size:30px;font-weight:700;color:#fff;letter-spacing:.05em;line-height:1;">
            {sev}
          </div>
        </td>
        <td align="right" style="padding:18px 22px;vertical-align:top;">
          <div style="background:rgba(0,0,0,.3);border-radius:6px;padding:8px 14px;text-align:center;">
            <div style="font-size:9px;color:rgba(255,255,255,.6);letter-spacing:.1em;margin-bottom:3px;">LEVEL</div>
            <div style="font-size:34px;font-weight:700;color:#fff;line-height:1;">{level}</div>
          </div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- description -->
  <tr><td style="background:#1a1a1a;padding:16px 22px;border-bottom:1px solid #222;">
    <div style="font-size:14px;color:#fff;font-weight:600;
      border-left:3px solid {accent};padding-left:11px;line-height:1.5;">
      {desc}
    </div>
  </td></tr>

  <!-- body -->
  <tr><td style="background:#111;padding:22px;">
    <table width="100%" cellpadding="0" cellspacing="0"
      style="border-collapse:collapse;margin-bottom:18px;">
      {kv_rows}
    </table>

    <div style="margin-bottom:18px;">
      <div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#555;margin-bottom:7px;">MITRE ATT&amp;CK</div>
      {mitre_html}
    </div>

    {raw_log_section}

    <div style="background:#0d0d0d;border:1px solid #222;border-radius:4px;padding:12px 14px;margin-bottom:18px;">
      <div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#555;margin-bottom:8px;">
        Analyst Checklist
      </div>
      <div style="font-size:11px;color:#888;line-height:1.9;">
        &#9656; Verify source IP in Criminal IP / VirusTotal<br>
        &#9656; Check agent logs for correlated activity within &plusmn;5 min window<br>
        &#9656; Escalate to Tier-2 if source IP is internal (RFC1918)<br>
        &#9656; Review MITRE ATT&amp;CK techniques linked above
      </div>
    </div>

    <div style="margin-bottom:20px;">
      {vt_link}
      <a href="https://attack.mitre.org/"
        style="display:inline-block;background:#1a1a1a;border:1px solid #333;border-radius:4px;
        padding:5px 10px;font-size:11px;color:#888;text-decoration:none;
        font-family:Courier New,monospace;">&#128737; MITRE Navigator</a>
    </div>

    <div style="border-top:1px solid #222;padding-top:14px;font-size:10px;color:#444;text-align:center;line-height:1.8;">
      Auto-generated by <strong style="color:#666;">Wazuh SOC Defense Platform v3</strong>
      &nbsp;&middot;&nbsp; {now_str}<br>
      Trigger: Rule level {level} classified as <strong style="color:{accent};">{sev}</strong><br>
      <span style="color:#333;">Team: Tith Sopanha
      &nbsp;&middot;&nbsp; FOR OFFICIAL SOC USE ONLY</span>
    </div>
  </td></tr>
  <tr><td style="background:{accent};height:3px;"></td></tr>
</table>
</td></tr></table>
</body></html>"""


class GmailAlerter:
    EMAIL_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}

    def __init__(self, dedup_sec: int = EMAIL_DEDUP_SEC, verbose: bool = False) -> None:
        self._dedup_sec  = dedup_sec
        self. _verbose     = verbose
        self._last_sent: dict[str, float] = {}
        self._enabled = _load_gmail_config()
        if not self._enabled:
            print(
                f"  {C.ORANGE}[EMAIL]{C.RESET} GMAIL_USER / GMAIL_PASS / ALERT_TO not set "
                f"— email alerting disabled."
            )

    def send(self, alert: dict) -> bool:
        if not self._enabled:
            return False

        sev = alert.get("severity", "INFO")
        if sev not in self.EMAIL_SEVERITIES:
            return False

        rule_id = alert.get("rule_id", "?")
        srcip   = alert.get("srcip", "") or "N/A"
        key     = f"{rule_id}|{srcip}"

        now  = time.time()
        last = self._last_sent.get(key)
        if last is not None and (now - last) < self._dedup_sec:
            return False   

        desc    = alert.get("description", "")
        icon    = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵"}.get(sev, "⚪")
        subject = (
            f"[SOC {sev}] {icon} Rule {rule_id} — "
            f"{desc[:55]}{'...' if len(desc) > 55 else ''}"
        )

        html_body  = build_html_email(alert)
        plain_body = (
            f"WAZUH SOC DEFENSE PLATFORM — SECURITY ALERT\n"
            f"{'=' * 60}\n"
            f"Severity   : {sev}\n"
            f"Level      : {alert.get('level')}\n"
            f"Rule ID    : {rule_id}\n"
            f"Description: {desc}\n"
            f"Source IP  : {srcip}\n"
            f"Agent      : {alert.get('agent_name', 'N/A')}\n"
            f"Timestamp  : {alert.get('timestamp', '')}\n"
            f"MITRE      : {', '.join(alert.get('mitre', [])) or 'N/A'}\n"
            f"{'=' * 60}\n"
            f"Team: Kosal Karuna · Cho Davon · Tith Sopanha\n"
            f"FOR OFFICIAL SOC USE ONLY"
        )

        try:
            msg = MIMEMultipart("alternative")
            msg["From"]    = SMTP_USER
            msg["To"]      = ALERT_EMAIL
            msg["Subject"] = subject
            msg.attach(MIMEText(plain_body, "plain"))
            msg.attach(MIMEText(html_body,  "html"))

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)

            self._last_sent[key] = now
            if self._verbose:
                print(f"  {C.GREEN}[EMAIL SENT]{C.RESET} {subject[:80]}")
            return True

        except Exception as exc:
            raise SMTPDeliveryError(str(exc)) from exc

    def cleanup(self, now: Optional[float] = None) -> None:
        t      = now if now is not None else time.time()
        cutoff = t - self._dedup_sec
        self._last_sent = {k: v for k, v in self._last_sent.items() if v > cutoff}

    def reset(self) -> None:
        self._last_sent.clear()

def main() -> None:
    if not _load_gmail_config():
        print(
            f"\n  {C.RED}[FATAL]{C.RESET} Set GMAIL_USER, GMAIL_PASS, and ALERT_TO "
            f"environment variables before running standalone.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"\n{C.CYAN}{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  GMAIL ALERT STANDALONE TEST MODE{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  Sending to: {ALERT_EMAIL}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'=' * 60}{C.RESET}\n")

    tailer  = MultiTailer(tail_mode=True)
    alerter = GmailAlerter()

    shutdown = False

    def handle_sig(sig: int, frame: object) -> None:
        nonlocal shutdown
        shutdown = True

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT,  handle_sig)

    while not shutdown:
        got_events = False
        for source, line in tailer.read_new_lines():
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue

            alert = build_alert(raw, source)
            if alert is None:
                continue

            show(alert)
            try:
                alerter.send(alert)
            except SMTPDeliveryError as exc:
                print(f"  {C.RED}[EMAIL FAILED]{C.RESET} {exc}")
            got_events = True

        if not got_events:
            time.sleep(POLL_INTERVAL)

    print(f"\n{C.ORANGE}Shutting down Gmail Alert standalone monitor.{C.RESET}")
    sys.exit(0)

if __name__ == "__main__":
    main()
