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
from thehive_responder import run_responder, RESPONDER_NETWORK, RESPONDER_FIM
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ioc_detector import IOCClassifier
from config import MALWARE_HASH_RULES
logger = logging.getLogger(__name__)
_ioc_classifier = IOCClassifier()
_ALLOWED_TYPES: frozenset[str] = frozenset({"ip", "user-agent", "hash"})
_ANALYZER_NAMES: dict[str, list[str]] = {
    "ip": [
        "VirusTotal_GetReport_3_1",
        "Shodan_ReverseDNS_1_0",
        "MISP_2_1",
    ],
    "user-agent": [
        "MISP_2_1",
    ],
    "hash": [
        "VirusTotal_GetReport_3_1",
        "MISP_2_1",
    ],
}
_PRIVATE_IP_ANALYZERS: list[str] = [
    "MISP_2_1",
]
TLP_WHITE = 0
TLP_GREEN = 1
TLP_AMBER = 2
TLP_RED   = 3
PAP_WHITE = 0
PAP_GREEN = 1
PAP_AMBER = 2
PAP_RED   = 3
_RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_USERAGENT = re.compile(
    r"(?:"
    r'[Uu]ser[-_][Aa]gent\s*[:\s]+([^\r\n"\']{10,300})'
    r"|"
    r"((?:Mozilla|curl|python-requests|python-urllib|Go-http-client|"
    r"nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|dirb|"
    r"hydra|medusa|wfuzz|ffuf|nuclei|whatweb|w3af|acunetix|"
    r"nessus|openvas|metasploit|msfconsole|havoc|sliver|cobaltstrike)"
    r"[^\r\n\"']{9,250})"
    r")",
    re.IGNORECASE,
)
_UA_HEADER_ONLY = re.compile(
    r'[Uu]ser[-_][Aa]gent\s*[:\s]+([^\r\n"\']{10,300})',
    re.IGNORECASE,
)
_FIM_RULES: frozenset[str] = frozenset({
    "100117", "100123",
    "550", "553", "554",
})
_BRUTE_FORCE_RULES: frozenset[str] = frozenset({
    "5503", "5710", "5712", "5715", "5716", "5758",
    "100105", "100116", "100901", "100106",
})
_RESPONDER_RULES: frozenset[str] = _FIM_RULES | _BRUTE_FORCE_RULES
def _is_valid_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip())
        return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)
    except ValueError:
        return False
def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_private
    except ValueError:
        return False
def _extract_ips_from_text(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for m in _RE_IP.finditer(text):
        ip = m.group(0)
        if ip not in seen and _is_valid_ip(ip):
            seen.add(ip)
            results.append(ip)
    return results
def _extract_user_agents(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for m in _RE_USERAGENT.finditer(text):
        ua = (m.group(1) or m.group(2) or "").strip().strip('"\'')
        if ua and ua.lower() not in seen:
            seen.add(ua.lower())
            results.append(ua)
    return results
def _syscheck_context(alert: dict) -> str:
    sc = alert.get("syscheck") or {}
    lines: list[str] = []
    for label, key in [
        ("File",        "path"),
        ("Event",       "event"),
        ("MD5 (now)",   "md5_after"),
        ("SHA1 (now)",  "sha1_after"),
        ("SHA256(now)", "sha256_after"),
        ("MD5 (was)",   "md5_before"),
        ("SHA1 (was)",  "sha1_before"),
        ("SHA256(was)", "sha256_before"),
        ("Owner(now)",  "uname_after"),
        ("Group(now)",  "gname_after"),
        ("Perms(now)",  "perm_after"),
    ]:
        v = str(sc.get(key) or "").strip()
        if v:
            lines.append(f"{label}: {v}")
    if not lines:
        fp = str(alert.get("file_path") or "").strip()
        fe = str(alert.get("file_event") or "").strip()
        if fp:
            lines.append(f"File: {fp}")
        if fe:
            lines.append(f"Event: {fe}")
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

        rule_id     = alert.get("rule_id", "")
        agent_name  = alert.get("agent_name", "?")
        agent_id    = alert.get("agent_id",   "?")
        severity    = alert.get("severity",   "INFO")
        timestamp   = alert.get("timestamp",  "")
        description = str(alert.get("description") or "")
        full_log    = str(alert.get("full_log")    or "")
        reason      = str(alert.get("reason")      or "")
        location    = str(alert.get("location")    or "")
        data_obj    = alert.get("data") or {}
        fim_ctx     = _syscheck_context(alert) if rule_id in _FIM_RULES else ""

        def _ip_note(label: str, ip: str, extra: str = "") -> str:
            parts = [
                f"{label}",
                f"Rule: {rule_id}  Severity: {severity}",
                f"Agent: {agent_name} (ID: {agent_id})",
                f"Timestamp: {timestamp}",
            ]
            if description:
                parts.append(f"Description: {description[:200]}")
            if reason:
                parts.append(f"Reason: {reason[:200]}")
            if full_log:
                parts.append(f"Raw log: {full_log[:300]}")
            if _is_private_ip(ip):
                parts.append("[INTERNAL network address]")
            if fim_ctx:
                parts.append(f"FIM context:\n{fim_ctx}")
            if extra:
                parts.append(extra)
            return "\n".join(parts)

        for field, label in [
            ("srcip",    "Source IP seen in alert"),
            ("dstip",    "Destination IP seen in alert"),
            ("agent_ip", "Agent IP seen in alert"),
        ]:
            ip = str(alert.get(field) or "").strip()
            if ip and _is_valid_ip(ip):
                add("ip", ip, field, _ip_note(label, ip))

        for sub_key, label in [("src_ip", "Suricata source IP"), ("dest_ip", "Suricata destination IP")]:
            ip = str(data_obj.get(sub_key) or "").strip()
            if ip and _is_valid_ip(ip):
                suri_sig = str(alert.get("suricata_signature") or "").strip()
                extra = f"Suricata signature: {suri_sig}" if suri_sig else ""
                add("ip", ip, f"data.{sub_key}", _ip_note(label, ip, extra))

        zeek = alert.get("zeek") or {}
        for sub_key, label in [("id.orig_h", "Zeek originator IP"), ("id.resp_h", "Zeek responder IP")]:
            ip = str(zeek.get(sub_key) or "").strip()
            if ip and _is_valid_ip(ip):
                svc = str(alert.get("zeek_service") or "").strip()
                extra = f"Zeek service: {svc}" if svc else ""
                add("ip", ip, f"zeek.{sub_key}", _ip_note(label, ip, extra))

        for blob_name, blob_text in [("full_log", full_log), ("description", description), ("location", location)]:
            if not blob_text:
                continue
            for ip in _extract_ips_from_text(blob_text):
                note = _ip_note(f"IP found in {blob_name} via regex", ip,
                                f"Context: {blob_text[:300]}")
                add("ip", ip, f"{blob_name}[regex]", note)

        http_obj = data_obj.get("http") or {}
        ua = str(http_obj.get("http_user_agent") or "").strip()
        if ua:
            parts = [
                "User-Agent from Suricata HTTP event",
                f"Rule: {rule_id}  Severity: {severity}",
                f"Agent: {agent_name} (ID: {agent_id})",
                f"Timestamp: {timestamp}",
            ]
            if full_log:
                parts.append(f"Raw log: {full_log[:300]}")
            add("user-agent", ua, "data.http.http_user_agent", "\n".join(parts))

        for blob_name, blob_text in [("full_log", full_log), ("description", description)]:
            if not blob_text:
                continue
            if blob_name == "description":
                for m in _UA_HEADER_ONLY.finditer(blob_text):
                    ua = m.group(1).strip().strip('"\'')
                    if ua:
                        parts = [
                            f"User-Agent found in {blob_name} (header form)",
                            f"Rule: {rule_id}  Severity: {severity}",
                            f"Agent: {agent_name} (ID: {agent_id})",
                            f"Timestamp: {timestamp}",
                            f"Context: {blob_text[:300]}",
                        ]
                        add("user-agent", ua, f"{blob_name}[regex]", "\n".join(parts))
            else:
                for ua in _extract_user_agents(blob_text):
                    parts = [
                        f"User-Agent found in {blob_name}",
                        f"Rule: {rule_id}  Severity: {severity}",
                        f"Agent: {agent_name} (ID: {agent_id})",
                        f"Timestamp: {timestamp}",
                        f"Context: {blob_text[:300]}",
                    ]
                    add("user-agent", ua, f"{blob_name}[regex]", "\n".join(parts))

        if rule_id in _FIM_RULES or rule_id in MALWARE_HASH_RULES:
            sc = alert.get("syscheck") or {}
            file_path = str(sc.get("path") or alert.get("file_path") or "").strip()
            for hash_label, hash_key in [
                ("md5",    "md5_after"),
                ("sha1",   "sha1_after"),
                ("sha256", "sha256_after"),
            ]:
                h = str(sc.get(hash_key) or "").strip()
                if not h:
                    continue
                note_parts = [
                    f"File hash ({hash_label.upper()}) from syscheck",
                    f"Rule: {rule_id}  Severity: {severity}",
                    f"Agent: {agent_name} (ID: {agent_id})",
                    f"Timestamp: {timestamp}",
                ]
                if file_path:
                    note_parts.append(f"File: {file_path}")
                if full_log:
                    note_parts.append(f"Raw log: {full_log[:300]}")
                add("hash", h, f"syscheck.{hash_key}", "\n".join(note_parts))

        return observables
class TheHiveObservableManager:
    def __init__(
        self,
        client,
        default_tlp: int   = TLP_AMBER,
        default_pap: int   = PAP_AMBER,
        retry_delay: float = 1.0,
        max_retries: int   = 2,
    ) -> None:
        self._client      = client
        self._default_tlp = default_tlp
        self._default_pap = default_pap
        self._retry_delay = retry_delay
        self._max_retries = max_retries
        self._extractor   = ObservableExtractor()
        self._cortex_id:             Optional[str]  = None
        self._analyzer_cache:        dict[str, str] = {}
        self._analyzer_cache_loaded: bool           = False

    def add_observables(self, case_id: str, alert: dict) -> dict:
        rule_id  = alert.get("rule_id", "")
        is_ioc   = _ioc_classifier.is_ioc(rule_id)
        category = _ioc_classifier.classify(rule_id)
        is_fim   = rule_id in _FIM_RULES
        is_brute = rule_id in _BRUTE_FORCE_RULES

        all_observables = self._extractor.extract(alert)
        observables = [o for o in all_observables if o["data_type"] in _ALLOWED_TYPES]
        type_skipped = len(all_observables) - len(observables)

        summary: dict = {
            "case_id":          case_id,
            "added":            0,
            "skipped":          type_skipped,
            "failed":           0,
            "ioc_count":        0,
            "hash_count":       0,
            "analyzer_jobs":    0,
            "responder_status": None,
            "responder_action": None,
            "errors":           [],
        }
        if not observables:
            logger.info(
                f"No observables of allowed types {set(_ALLOWED_TYPES)}  "
                f"case={case_id}  rule={rule_id}  "
                f"(extracted={len(all_observables)}, all filtered)"
            )
            if rule_id in _RESPONDER_RULES:
                resp_result = self._trigger_responders(case_id, alert)
                summary["responder_status"] = resp_result.get("status")
                summary["responder_action"] = resp_result.get("action_id")
            return summary
        self._ensure_analyzer_cache()
        if not self._cortex_id:
            logger.warning(
                "No Cortex server found via /api/connector/cortex/analyzer — "
                "observables will be posted but analyzers will NOT be triggered"
            )
        logger.info(
            f"Posting {len(observables)} observable(s)  case={case_id}  "
            f"rule={rule_id}  category={category}  ioc={is_ioc}  fim={is_fim}"
        )
        for obs in observables:
            ioc_flag = self._decide_ioc(obs, is_ioc, is_fim)
            sighted  = self._decide_sighted(obs, is_brute, is_fim)
            tlp, pap = self._decide_tlp_pap(obs, ioc_flag)
            desc_txt = self._build_description(obs, alert, category, ioc_flag, sighted)
            payload = self._build_payload(obs, alert, category, ioc_flag, sighted, tlp, pap, desc_txt)
            result, obs_id = self._post_observable(case_id, payload)
            if result == "created":
                summary["added"] += 1
                if ioc_flag:
                    summary["ioc_count"] += 1
                if obs["data_type"] == "hash":
                    summary["hash_count"] += 1
                if obs_id and self._cortex_id:
                    jobs = self._trigger_analyzers(obs_id, obs)
                    summary["analyzer_jobs"] += jobs
            elif result == "updated":
                summary["added"] += 1
                if obs["data_type"] == "hash":
                    summary["hash_count"] += 1
                if obs_id and self._cortex_id:
                    jobs = self._trigger_analyzers(obs_id, obs)
                    summary["analyzer_jobs"] += jobs

            elif result == "duplicate":
                summary["skipped"] += 1
            else:
                summary["failed"] += 1
                summary["errors"].append(f"{obs['data_type']}:{obs['value'][:40]} → {result}")
        if rule_id in _RESPONDER_RULES:
            resp_result = self._trigger_responders(case_id, alert)
            summary["responder_status"] = resp_result.get("status")
            summary["responder_action"] = resp_result.get("action_id")
        else:
            logger.debug(
                f"No responder mapping for rule={rule_id} — skipped"
            )

        logger.info(
            f"Observable summary  case={case_id}  added={summary['added']}  "
            f"ioc={summary['ioc_count']}  hash={summary['hash_count']}  "
            f"skipped={summary['skipped']}  failed={summary['failed']}  "
            f"analyzer_jobs={summary['analyzer_jobs']}  "
            f"responder={summary['responder_status']}"
        )
        return summary
    def _ensure_analyzer_cache(self) -> None:
        if self._analyzer_cache_loaded:
            return
        url = f"{self._client.url}/api/connector/cortex/analyzer"
        try:
            resp = self._client.session.get(url, timeout=self._client.timeout)
            if resp.status_code != 200:
                logger.warning(
                    f"Analyzer list HTTP {resp.status_code} — cache not loaded, will retry"
                )
                return
            entries = resp.json()
            if not isinstance(entries, list):
                logger.warning("Analyzer list response is not a list — cache not loaded, will retry")
                return
            loaded_count = 0
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = (entry.get("name") or entry.get("analyzerId") or "").strip()
                worker_id = (
                    entry.get("id") or
                    entry.get("analyzerId") or
                    entry.get("workerDefinitionId") or ""
                ).strip()
                if name and worker_id:
                    self._analyzer_cache[name] = worker_id
                    loaded_count += 1
                if self._cortex_id is None:
                    cortex_ids = entry.get("cortexIds") or []
                    if isinstance(cortex_ids, list) and cortex_ids:
                        first_id = str(cortex_ids[0]).strip()
                        if first_id:
                            self._cortex_id = first_id
                            logger.info(f"Auto-resolved cortex_id={self._cortex_id!r}")
            if loaded_count == 0:
                logger.warning(
                    "Analyzer list returned 0 usable entries — cache not loaded, will retry"
                )
                return
            self._analyzer_cache_loaded = True
            logger.info(
                f"Analyzer cache loaded: {loaded_count} entries  "
                f"cortex_id={self._cortex_id!r}  "
                f"cached_names={list(self._analyzer_cache.keys())}"
            )
        except Exception as exc:
            logger.warning(f"Analyzer cache load failed: {exc} — will retry on next observable")

    def _trigger_analyzers(self, obs_id: str, obs: dict) -> int:
        data_type = obs["data_type"]
        if data_type == "ip":
            if _is_private_ip(obs["value"]):
                analyzer_names = list(_PRIVATE_IP_ANALYZERS)
                logger.debug(
                    f"Private IP {obs['value']} — using private-IP analyzer list: "
                    f"{analyzer_names}"
                )
            else:
                analyzer_names = list(_ANALYZER_NAMES.get("ip", []))
                logger.debug(
                    f"Public IP {obs['value']} — using public-IP analyzer list: "
                    f"{analyzer_names}"
                )
        else:
            analyzer_names = list(_ANALYZER_NAMES.get(data_type, []))

        if not analyzer_names:
            logger.debug(
                f"No analyzers configured for type={data_type} value={obs['value']}"
            )
            return 0

        url        = f"{self._client.url}/api/v1/connector/cortex/job"
        jobs_fired = 0

        for analyzer_name in analyzer_names:
            analyzer_id = self._analyzer_cache.get(analyzer_name)
            if not analyzer_id:
                logger.warning(
                    f"SKIPPED ANALYZER '{analyzer_name}' — UUID NOT FOUND IN CACHE. "
                    f"Available: {list(self._analyzer_cache.keys())}"
                )
                continue

            payload = {
                "cortexId":   self._cortex_id,
                "analyzerId": analyzer_id,
                "artifactId": obs_id,
            }
            for attempt in range(self._max_retries + 1):
                try:
                    resp = self._client.session.post(
                        url, json=payload, timeout=self._client.timeout
                    )
                    if resp.status_code in (200, 201):
                        job_id = resp.json().get("cortexJobId", "?")
                        logger.info(
                            f"Analyzer triggered  name={analyzer_name}  "
                            f"id={analyzer_id}  obs={obs_id}  "
                            f"value={obs['value']}  cortex_job={job_id}"
                        )
                        jobs_fired += 1
                        break
                    else:
                        logger.warning(
                            f"Analyzer trigger failed  name={analyzer_name}  "
                            f"HTTP {resp.status_code}: {resp.text[:200]}"
                        )
                        if attempt < self._max_retries:
                            time.sleep(self._retry_delay * (attempt + 1))
                except Exception as exc:
                    logger.warning(
                        f"Analyzer trigger exception  name={analyzer_name}  "
                        f"obs={obs_id}  error={exc}"
                    )
                    if attempt < self._max_retries:
                        time.sleep(self._retry_delay * (attempt + 1))
        return jobs_fired
    def _trigger_responders(self, case_id: str, alert: dict) -> dict:
        rule_id = str(alert.get("rule_id", ""))

        if rule_id in _FIM_RULES:
            responder_name = RESPONDER_FIM
        elif rule_id in _BRUTE_FORCE_RULES:
            responder_name = RESPONDER_NETWORK
        else:
            logger.debug(
                f"_trigger_responders: rule={rule_id} has no responder mapping — skipped"
            )
            return {"status": "skipped", "responder": None, "error": "no mapping for rule"}
        logger.info(
            f"_trigger_responders: case={case_id}  rule={rule_id}  "
            f"responder={responder_name}"
        )
        result = run_responder(
            client         = self._client,
            case_id        = case_id,
            responder_name = responder_name,
        )
        logger.info(
            f"_trigger_responders result: case={case_id}  "
            f"responder={responder_name}  status={result['status']}  "
            f"action_id={result.get('action_id')}  error={result.get('error')}"
        )
        return result
    def _decide_ioc(self, obs: dict, is_ioc: bool, is_fim: bool) -> bool:
        dtype = obs["data_type"]
        if dtype == "hash":
            return True
        if not is_ioc or dtype != "ip":
            return False
        if is_fim or _is_private_ip(obs["value"]):
            return False
        return True
    def _decide_sighted(self, obs: dict, is_brute: bool, is_fim: bool) -> bool:
        if obs["data_type"] != "ip":
            return False
        if is_fim or is_brute or _is_private_ip(obs["value"]):
            return True
        return False
    def _decide_tlp_pap(self, obs: dict, ioc_flag: bool) -> tuple[int, int]:
        dtype   = obs["data_type"]
        is_priv = dtype == "ip" and _is_private_ip(obs["value"])
        if dtype == "hash":
            return TLP_AMBER, PAP_AMBER
        if ioc_flag and dtype == "ip" and not is_priv:
            return TLP_AMBER, PAP_AMBER
        if is_priv:
            return TLP_GREEN, PAP_GREEN
        return TLP_AMBER, PAP_AMBER
    def _build_description(
        self, obs: dict, alert: dict, category: str, ioc_flag: bool, sighted: bool
    ) -> str:
        rule_id    = alert.get("rule_id",    "?")
        agent_name = alert.get("agent_name", "?")
        agent_id   = alert.get("agent_id",   "?")
        severity   = alert.get("severity",   "INFO")
        timestamp  = alert.get("timestamp",  "")
        desc       = str(alert.get("description") or "")[:200]
        reason     = str(alert.get("reason")      or "")[:200]
        srcip      = alert.get("srcip", "") or ""
        dstip      = alert.get("dstip", "") or ""
        full_log   = str(alert.get("full_log") or "")[:300]
        mitre      = ", ".join(alert.get("mitre", [])) or "N/A"
        fim_ctx    = _syscheck_context(alert) if alert.get("rule_id", "") in _FIM_RULES else ""
        lines = [
            "=== Wazuh SOC Auto-Observable ===",
            f"Type      : {obs['data_type']}",
            f"Value     : {obs['value']}",
            f"Source    : {obs['source']}",
            "",
            "=== Incident Detail ===",
            f"Timestamp : {timestamp}",
            f"Rule ID   : {rule_id}",
            f"Severity  : {severity}",
            f"Category  : {category}",
            f"Agent     : {agent_name} (ID: {agent_id})",
        ]
        if desc:
            lines.append(f"Description: {desc}")
        if reason and reason != desc:
            lines.append(f"Reason    : {reason}")
        if srcip:
            lines.append(f"Source IP : {srcip}")
        if dstip:
            lines.append(f"Dest IP   : {dstip}")
        if mitre != "N/A":
            lines.append(f"MITRE     : {mitre}")
        if full_log:
            lines += ["", "=== Raw Log (truncated) ===", full_log]
        if fim_ctx:
            lines += ["", "=== FIM Context ===", fim_ctx]
        if ioc_flag:
            lines += ["", "IOC — matches Wazuh IOC-grade rule classification"]
        if sighted:
            lines.append("Sighted — indicator observed inside monitored network")
        if obs["data_type"] == "ip" and _is_private_ip(obs["value"]):
            lines += ["", "INTERNAL IP — running MISP only (VirusTotal/Shodan skipped)"]
        return "\n".join(lines)
    def _build_payload(
        self, obs: dict, alert: dict, category: str,
        ioc_flag: bool, sighted: bool, tlp: int, pap: int, description_text: str
    ) -> dict:
        rule_id    = str(alert.get("rule_id",    "?"))
        agent_name = str(alert.get("agent_name", "?"))
        severity   = str(alert.get("severity",   "INFO"))
        tags = [
            "wazuh",
            f"rule:{rule_id}",
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
        if obs["data_type"] == "ip" and _is_private_ip(obs["value"]):
            tags.append("internal-ip")
        return {
            "dataType":         obs["data_type"],
            "data":             obs["value"],
            "message":          description_text,
            "description":      description_text,
            "tlp":              tlp,
            "pap":              pap,
            "ioc":              ioc_flag,
            "sighted":          sighted,
            "tags":             tags,
            "ignoreSimilarity": False,
        }
    def _post_observable(self, case_id: str, payload: dict) -> tuple[str, Optional[str]]:
        url = f"{self._client.url}/api/v1/case/{case_id}/observable"
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._client.session.post(url, json=payload, timeout=self._client.timeout)

                if resp.status_code in (200, 201):
                    body   = resp.json()
                    obs_id = (body[0].get("_id") if isinstance(body, list) and body
                              else body.get("_id") if isinstance(body, dict)
                              else None)
                    logger.debug(
                        f"Observable created  case={case_id}  id={obs_id}  "
                        f"type={payload['dataType']}  value={payload['data'][:40]}"
                    )
                    return "created", obs_id
                if resp.status_code == 207:
                    obs_id = self._extract_id_from_207(resp)
                    if obs_id:
                        self._patch_observable(obs_id, payload)
                        return "updated", obs_id
                    return "duplicate", None
                if resp.status_code == 400:
                    body_text = resp.text.lower()
                    if any(x in body_text for x in ("already", "duplicate", "exist")):
                        return "duplicate", None
                    return f"HTTP 400: {resp.text[:120]}", None
                if resp.status_code >= 500 and attempt < self._max_retries:
                    logger.warning(
                        f"HTTP {resp.status_code} posting observable "
                        f"(attempt {attempt+1}) — retrying"
                    )
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue

                return f"HTTP {resp.status_code}: {resp.text[:120]}", None
            except Exception as exc:
                if attempt < self._max_retries:
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                return f"Exception: {exc}", None
        return "max retries exceeded", None
    @staticmethod
    def _extract_id_from_207(resp) -> Optional[str]:
        try:
            body = resp.json()
            if isinstance(body, list) and body:
                return body[0].get("_id")
            if isinstance(body, dict):
                return body.get("_id")
        except Exception:
            pass
        return None
    def _patch_observable(self, obs_id: str, payload: dict) -> None:
        url = f"{self._client.url}/api/v1/observable/{obs_id}"
        patch_body = {
            "tlp":         payload["tlp"],
            "pap":         payload["pap"],
            "message":     payload["message"],
            "description": payload["description"],
            "ioc":         payload["ioc"],
            "sighted":     payload["sighted"],
            "tags":        payload["tags"],
        }
        try:
            resp = self._client.session.patch(url, json=patch_body, timeout=self._client.timeout)
            if resp.status_code in (200, 204):
                logger.debug(f"Observable PATCHed  id={obs_id}")
            else:
                logger.warning(
                    f"Observable PATCH failed  id={obs_id}  "
                    f"HTTP {resp.status_code}: {resp.text[:120]}"
                )
        except Exception as exc:
            logger.warning(f"Observable PATCH exception  id={obs_id}  error={exc}")
# ── Module-level singleton
_manager_singleton: Optional[TheHiveObservableManager] = None
def attach_observables(
    client,
    case_id:     str,
    alert:       dict,
    default_tlp: int = TLP_AMBER,
    default_pap: int = PAP_AMBER,
) -> dict:
    global _manager_singleton
    if (
        _manager_singleton is None
        or _manager_singleton._client is not client
    ):
        _manager_singleton = TheHiveObservableManager(
            client,
            default_tlp=default_tlp,
            default_pap=default_pap,
        )
    return _manager_singleton.add_observables(case_id, alert)
