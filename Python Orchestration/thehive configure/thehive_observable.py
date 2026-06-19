#!/usr/bin/env python3
from __future__ import annotations

import html
import ipaddress
import logging
import re
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ioc_detector import IOCClassifier
from config import MALWARE_HASH_RULES

logger = logging.getLogger(__name__)

_ioc_classifier = IOCClassifier()

# ── ALLOWED OBSERVABLE TYPES ─────────────────────────────────────────────────
# All extracted observables are filtered to only these two before posting.
_ALLOWED_TYPES: frozenset[str] = frozenset({"ip", "user-agent"})

# ── Regex patterns ────────────────────────────────────────────────────────────
# IP addresses in free text (IPv4 only — covers the vast majority of cases)
_RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_RE_USERAGENT = re.compile(
    r"(?:"
    # HTTP header form:  User-Agent: <value>
    r'[Uu]ser[-_][Aa]gent\s*[:\s]+([^\r\n"\']{10,300})'
    r"|"
    # Bare scanner fingerprints in log lines (nikto, sqlmap, etc.)
    r"((?:Mozilla|curl|python-requests|python-urllib|Go-http-client|"
    r"nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|dirb|"
    r"hydra|medusa|wfuzz|ffuf|nuclei|whatweb|w3af|acunetix|"
    r"nessus|openvas|metasploit|msfconsole|havoc|sliver|cobaltstrike)"
    r"[^\r\n\"']{9,250})"    # require ≥9 chars after the tool name so short
                              # description phrases ("nikto user-agent") are skipped
    r")",
    re.IGNORECASE,
)

# ── Rule classification sets ──────────────────────────────────────────────────
# These MUST stay in sync with thehive-intercept.py and wazuh_fim.py.

_FIM_RULES: frozenset[str] = frozenset({
    "100117", "100123",        # critical file modified / repeated mods
    "550",    "553",    "554", # native Wazuh syscheck rules
})

_BRUTE_FORCE_RULES: frozenset[str] = frozenset({
    "5503", "5710", "5712", "5715", "5716", "5758",
    "100105", "100116", "100901", "100106",
})

# ── IP helpers ────────────────────────────────────────────────────────────────

def _is_valid_ip(value: str) -> bool:
    """True if value is a usable IPv4/IPv6 address (not loopback/link-local)."""
    try:
        addr = ipaddress.ip_address(value.strip())
        return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)
    except ValueError:
        return False


def _is_private_ip(value: str) -> bool:
    """True if value is RFC-1918 / private address space."""
    try:
        return ipaddress.ip_address(value.strip()).is_private
    except ValueError:
        return False


# ── User-agent extraction helper ──────────────────────────────────────────────

def _extract_user_agents(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()

    for m in _RE_USERAGENT.finditer(text):
        # Group 1: after "User-Agent:" header
        # Group 2: bare scanner fingerprint
        ua = (m.group(1) or m.group(2) or "").strip().strip('"\'')
        if ua and ua.lower() not in seen:
            seen.add(ua.lower())
            results.append(ua)

    return results


# ── IP extraction from raw text ───────────────────────────────────────────────

def _extract_ips_from_text(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()

    for m in _RE_IP.finditer(text):
        ip = m.group(0)
        if ip not in seen and _is_valid_ip(ip):
            seen.add(ip)
            results.append(ip)

    return results


# ── Syscheck context builder ──────────────────────────────────────────────────

def _syscheck_context(alert: dict) -> str:
    sc = alert.get("syscheck") or {}
    lines: list[str] = []

    path = str(sc.get("path") or "").strip()
    if path:
        lines.append(f"File : {path}")

    event = str(sc.get("event") or "").strip()
    if event:
        lines.append(f"Event: {event}")

    for label, key in [
        ("MD5  (now)", "md5_after"),
        ("SHA1 (now)", "sha1_after"),
        ("SHA256(now)", "sha256_after"),
        ("MD5  (was)", "md5_before"),
        ("SHA1 (was)", "sha1_before"),
        ("SHA256(was)", "sha256_before"),
    ]:
        v = str(sc.get(key) or "").strip()
        if v:
            lines.append(f"{label}: {v}")

    for label, key in [
        ("Owner (now)", "uname_after"),
        ("Group (now)", "gname_after"),
        ("Perms (now)", "perm_after"),
    ]:
        v = str(sc.get(key) or "").strip()
        if v:
            lines.append(f"{label}: {v}")

    return "\n".join(lines)
class ObservableExtractor:
    @staticmethod
    def _sanitize(value: str, max_len: int = 512) -> str:
        cleaned = re.sub(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", value)
        return cleaned[:max_len].strip()

    def extract(self, alert: dict) -> list[dict]:
        observables: list[dict] = []
        seen_pairs: set[tuple[str, str]] = set()

        def add(data_type: str, value: str, source: str, message: str = "") -> None:
            v = self._sanitize(value)
            if not v:
                return
            pair = (data_type, v.lower())
            if pair in seen_pairs:
                return
            seen_pairs.add(pair)
            observables.append({
                "data_type": data_type,
                "value":     v,
                "source":    source,
                "message":   message or f"Extracted from field: {source}",
            })

        rule_id    = alert.get("rule_id", "")
        agent_name = alert.get("agent_name", "?")
        agent_id   = alert.get("agent_id",   "?")
        severity   = alert.get("severity",   "INFO")
        timestamp  = alert.get("timestamp",  "")
        description = str(alert.get("description") or "")
        full_log    = str(alert.get("full_log")    or "")
        reason      = str(alert.get("reason")      or "")
        location    = str(alert.get("location")    or "")

        # Build syscheck context once — reused in IP messages for FIM rules
        fim_ctx = _syscheck_context(alert) if rule_id in _FIM_RULES else ""

        # ── 1. Structured IP fields ───────────────────────────────────────
        for field, label in [
            ("srcip",    "Source IP"),
            ("dstip",    "Destination IP"),
            ("agent_ip", "Agent IP"),
        ]:
            ip = str(alert.get(field) or "").strip()
            if not ip or not _is_valid_ip(ip):
                continue

            note_parts = [
                f"{label} seen in alert",
                f"Rule: {rule_id}",
                f"Severity: {severity}",
                f"Agent: {agent_name} (ID: {agent_id})",
                f"Timestamp: {timestamp}",
            ]
            if description:
                note_parts.append(f"Description: {description[:200]}")
            if reason:
                note_parts.append(f"Reason: {reason[:200]}")
            if full_log:
                note_parts.append(f"Raw log: {full_log[:300]}")
            if _is_private_ip(ip):
                note_parts.append("[INTERNAL network address]")
            if fim_ctx:
                note_parts.append(f"FIM context:\n{fim_ctx}")

            add("ip", ip, field, "\n".join(note_parts))

        # ── 2. Suricata structured IP fields ─────────────────────────────
        data_obj = alert.get("data") or {}
        for sub_key, label in [
            ("src_ip",  "Suricata source IP"),
            ("dest_ip", "Suricata destination IP"),
        ]:
            ip = str(data_obj.get(sub_key) or "").strip()
            if not ip or not _is_valid_ip(ip):
                continue
            suri_sig = str(alert.get("suricata_signature") or "").strip()
            note_parts = [
                f"{label}",
                f"Rule: {rule_id}  Severity: {severity}",
                f"Agent: {agent_name} (ID: {agent_id})",
                f"Timestamp: {timestamp}",
            ]
            if suri_sig:
                note_parts.append(f"Suricata signature: {suri_sig}")
            if full_log:
                note_parts.append(f"Raw log: {full_log[:300]}")
            add("ip", ip, f"data.{sub_key}", "\n".join(note_parts))

        # ── 3. Zeek structured IP fields ──────────────────────────────────
        zeek = alert.get("zeek") or {}
        for sub_key, label in [
            ("id.orig_h", "Zeek originator IP"),
            ("id.resp_h", "Zeek responder IP"),
        ]:
            ip = str(zeek.get(sub_key) or "").strip()
            if not ip or not _is_valid_ip(ip):
                continue
            note_parts = [
                f"{label}",
                f"Rule: {rule_id}  Severity: {severity}",
                f"Agent: {agent_name} (ID: {agent_id})",
                f"Timestamp: {timestamp}",
            ]
            zeek_svc = str(alert.get("zeek_service") or "").strip()
            if zeek_svc:
                note_parts.append(f"Zeek service: {zeek_svc}")
            if full_log:
                note_parts.append(f"Raw log: {full_log[:300]}")
            add("ip", ip, f"zeek.{sub_key}", "\n".join(note_parts))

        # ── 4. Raw-log / description IP mining ───────────────────────────
        blobs_for_ip = [
            ("full_log",    full_log),
            ("description", description),
            ("location",    location),
        ]
        for blob_name, blob_text in blobs_for_ip:
            if not blob_text:
                continue
            for ip in _extract_ips_from_text(blob_text):
                note_parts = [
                    f"IP found in {blob_name} via regex scan",
                    f"Rule: {rule_id}  Severity: {severity}",
                    f"Agent: {agent_name} (ID: {agent_id})",
                    f"Timestamp: {timestamp}",
                    f"Context: {blob_text[:300]}",
                ]
                if fim_ctx:
                    note_parts.append(f"FIM context:\n{fim_ctx}")
                add("ip", ip, f"{blob_name}[regex]", "\n".join(note_parts))

        # ── 5. Suricata HTTP user-agent structured field ──────────────────
        http_obj = data_obj.get("http") or {}
        ua_structured = str(http_obj.get("http_user_agent") or "").strip()
        if ua_structured:
            note_parts = [
                "User-Agent from Suricata HTTP event",
                f"Rule: {rule_id}  Severity: {severity}",
                f"Agent: {agent_name} (ID: {agent_id})",
                f"Timestamp: {timestamp}",
            ]
            if full_log:
                note_parts.append(f"Raw log: {full_log[:300]}")
            add("user-agent", ua_structured,
                "data.http.http_user_agent", "\n".join(note_parts))

        # ── 6. Raw-log / description user-agent mining ────────────────────
        blobs_for_ua = [
            ("full_log",    full_log),
            ("description", description),
        ]
        for blob_name, blob_text in blobs_for_ua:
            if not blob_text:
                continue
            if blob_name == "description":
                _UA_HEADER_ONLY = re.compile(
                    r'[Uu]ser[-_][Aa]gent\s*[:\s]+([^\r\n"\']{10,300})',
                    re.IGNORECASE,
                )
                for m in _UA_HEADER_ONLY.finditer(blob_text):
                    ua = m.group(1).strip().strip('"\'')
                    if ua:
                        note_parts = [
                            f"User-Agent found in {blob_name} (header form)",
                            f"Rule: {rule_id}  Severity: {severity}",
                            f"Agent: {agent_name} (ID: {agent_id})",
                            f"Timestamp: {timestamp}",
                            f"Context: {blob_text[:300]}",
                        ]
                        add("user-agent", ua,
                            f"{blob_name}[regex]", "\n".join(note_parts))
            else:
                for ua in _extract_user_agents(blob_text):
                    note_parts = [
                        f"User-Agent found in {blob_name}",
                        f"Rule: {rule_id}  Severity: {severity}",
                        f"Agent: {agent_name} (ID: {agent_id})",
                        f"Timestamp: {timestamp}",
                        f"Context: {blob_text[:300]}",
                    ]
                    add("user-agent", ua,
                        f"{blob_name}[regex]", "\n".join(note_parts))

        return observables
class TheHiveObservableManager:
    def __init__(
        self,
        client,
        default_tlp:  int   = 2,   # AMBER
        default_pap:  int   = 2,   # AMBER
        retry_delay:  float = 1.0,
        max_retries:  int   = 2,
    ) -> None:
        self._client      = client
        self._default_tlp = default_tlp
        self._default_pap = default_pap
        self._retry_delay = retry_delay
        self._max_retries = max_retries
        self._extractor   = ObservableExtractor()
    def add_observables(self, case_id: str, alert: dict) -> dict:
        rule_id    = alert.get("rule_id", "")
        is_ioc     = _ioc_classifier.is_ioc(rule_id)
        category   = _ioc_classifier.classify(rule_id)
        is_fim     = rule_id in _FIM_RULES
        is_brute   = rule_id in _BRUTE_FORCE_RULES

        all_observables = self._extractor.extract(alert)

        # ── TYPE FILTER (CHANGE-1) ────────────────────────────────────────
        observables = [o for o in all_observables if o["data_type"] in _ALLOWED_TYPES]
        type_skipped = len(all_observables) - len(observables)

        summary: dict = {
            "case_id":    case_id,
            "added":      0,
            "skipped":    type_skipped,   # counts both type-filtered and duplicate
            "failed":     0,
            "ioc_count":  0,
            "hash_count": 0,              # always 0 now — hashes are filtered out
            "errors":     [],
        }

        if not observables:
            logger.info(
                f"No ip/user-agent observables to post  "
                f"case={case_id}  rule={rule_id}  "
                f"(extracted={len(all_observables)} total, all filtered)"
            )
            return summary

        logger.info(
            f"Posting {len(observables)} observable(s) [ip/user-agent only]  "
            f"case={case_id}  rule={rule_id}  category={category}  "
            f"ioc_rule={is_ioc}  fim={is_fim}  "
            f"(filtered out {type_skipped} non-ip/ua types)"
        )

        for obs in observables:
            ioc_flag = self._decide_ioc(obs, is_ioc, is_fim)
            sighted  = self._decide_sighted(obs, is_brute, is_fim)
            tlp, pap = self._decide_tlp_pap(obs, ioc_flag)

            payload = self._build_payload(
                obs, alert, category,
                ioc_flag=ioc_flag,
                sighted=sighted,
                tlp=tlp,
                pap=pap,
            )
            result = self._post_observable(case_id, payload)

            if result == "created":
                summary["added"] += 1
                if ioc_flag:
                    summary["ioc_count"] += 1
            elif result == "duplicate":
                summary["skipped"] += 1
            else:
                summary["failed"] += 1
                summary["errors"].append(
                    f"{obs['data_type']}:{obs['value'][:40]} → {result}"
                )

        logger.info(
            f"Observable summary  case={case_id}  "
            f"added={summary['added']}  ioc={summary['ioc_count']}  "
            f"skipped={summary['skipped']}  failed={summary['failed']}"
        )
        return summary

    # ── IOC decision ──────────────────────────────────────────────────────────

    def _decide_ioc(
        self,
        obs:    dict,
        is_ioc: bool,
        is_fim: bool,
    ) -> bool:
        if not is_ioc:
            return False
        if obs["data_type"] != "ip":
            # user-agent strings are contextual evidence, not standalone IOCs
            return False
        if is_fim:
            return False
        if _is_private_ip(obs["value"]):
            return False
        return True

    # ── Sighted decision ──────────────────────────────────────────────────────

    def _decide_sighted(
        self,
        obs:      dict,
        is_brute: bool,
        is_fim:   bool,
    ) -> bool:
        if obs["data_type"] != "ip":
            return False
        if is_fim or is_brute:
            return True
        if _is_private_ip(obs["value"]):
            return True
        return False

    # ── TLP / PAP decision ────────────────────────────────────────────────────

    def _decide_tlp_pap(
        self,
        obs:      dict,
        ioc_flag: bool,
    ) -> tuple[int, int]:
        dtype   = obs["data_type"]
        is_priv = dtype == "ip" and _is_private_ip(obs["value"])

        if ioc_flag and dtype == "ip" and not is_priv:
            return 3, 2   # RED, AMBER
        if ioc_flag:
            return 2, 2   # AMBER, AMBER
        if is_priv:
            return 1, 1   # GREEN, GREEN
        return self._default_tlp, self._default_pap
    def _build_payload(
        self,
        obs:      dict,
        alert:    dict,
        category: str,
        ioc_flag: bool,
        sighted:  bool,
        tlp:      int,
        pap:      int,
    ) -> dict:
        rule_id    = html.escape(str(alert.get("rule_id",    "?")))
        agent_name = html.escape(str(alert.get("agent_name", "?")))
        agent_id   = html.escape(str(alert.get("agent_id",   "?")))
        severity   = html.escape(str(alert.get("severity",   "INFO")))
        timestamp  = html.escape(str(alert.get("timestamp",  "")))
        ctx_msg    = html.escape(str(obs["message"]))

        header_lines = [
            "── Wazuh SOC Observable ──────────────────────────────",
            f"Type      : {obs['data_type']}",
            f"Rule      : {rule_id}",
            f"Category  : {category}",
            f"Severity  : {severity}",
            f"Agent     : {agent_name} (ID: {agent_id})",
            f"Timestamp : {timestamp}",
            f"Source    : {obs['source']}",
            "",
            ctx_msg,
        ]
        if ioc_flag:
            header_lines.append(
                "\n⚠  IOC — matches Wazuh IOC-grade rule classification"
            )
        if sighted:
            header_lines.append(
                "👁  Sighted — indicator observed inside the monitored network"
            )

        tags = [
            "wazuh",
            f"rule:{alert.get('rule_id', '?')}",
            f"type:{obs['data_type']}",
            f"category:{category.lower().replace(' ', '_')}",
            f"severity:{severity.lower()}",
            f"agent:{agent_name}",
            f"source:{obs['source']}",
        ]
        if ioc_flag:
            tags.append("ioc")
        if sighted:
            tags.append("sighted")
        if alert.get("rule_id", "") in MALWARE_HASH_RULES:
            tags.append("malware")

        return {
            "dataType":         obs["data_type"],
            "data":             obs["value"],
            "message":         "\n".join(header_lines),
            "tlp":              tlp,
            "pap":              pap,
            "ioc":              ioc_flag,
            "sighted":          sighted,
            "tags":             tags,
            "ignoreSimilarity": False,
        }
    def _post_observable(self, case_id: str, payload: dict) -> str:
        url = f"{self._client.url}/api/v1/case/{case_id}/observable"
        for attempt in range(1, self._max_retries + 2):
            try:
                resp = self._client.session.post(
                    url, json=payload, timeout=self._client.timeout
                )
                if resp.status_code in (200, 201):
                    return "created"
                if resp.status_code == 400:
                    body = resp.text.lower()
                    if any(x in body for x in ("already", "duplicate", "exist")):
                        return "duplicate"
                    return f"HTTP 400: {resp.text[:120]}"
                if resp.status_code >= 500 and attempt <= self._max_retries:
                    time.sleep(self._retry_delay * attempt)
                    continue
                return f"HTTP {resp.status_code}: {resp.text[:120]}"
            except Exception as exc:
                if attempt <= self._max_retries:
                    time.sleep(self._retry_delay * attempt)
                    continue
                return f"Exception: {exc}"
        return "max retries exceeded"
def attach_observables(
    client,
    case_id:     str,
    alert:       dict,
    default_tlp: int = 2,
    default_pap: int = 2,
) -> dict:
    mgr = TheHiveObservableManager(
        client,
        default_tlp=default_tlp,
        default_pap=default_pap,
    )
    return mgr.add_observables(case_id, alert)
