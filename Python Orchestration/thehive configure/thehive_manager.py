#!/usr/bin/env python3
"""
thehive_manager.py – TheHive case creation with dedup and distinct return values.

Return contract for process_alert() and process_correlation():
    str   – TheHive case ID: case was created successfully
    False – dedup-skipped: same (rule_id, srcip) seen within CASE_DEDUP_SEC
    None  – failure (API error, dry-run, or below min severity)
"""

import logging
import time
from typing import Optional, Union

logger = logging.getLogger(__name__)

SEVERITY_MAP: dict[str, int] = {
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4,
}

DEDUP_SKIPPED = False


class TheHiveCaseManager:
    """
    Wraps TheHiveClient to:
      • enforce a minimum severity threshold before creating cases
      • deduplicate cases: same (rule_id, srcip) within CASE_DEDUP_SEC
        returns False instead of hitting the API again
      • return distinct values so the caller can update counters correctly
    """

    def __init__(
        self,
        client,
        dry_run: bool = False,
        case_min_severity: str = "MEDIUM",
        case_dedup_sec: int = 600,
    ) -> None:
        self.client            = client
        self.dry_run           = dry_run
        self.case_min_severity = case_min_severity
        self.case_dedup_sec    = case_dedup_sec
        self._last_sent: dict[str, float] = {}
        self._min_sev_int: int = SEVERITY_MAP.get(case_min_severity, 2)

        logger.info(
            f"TheHiveCaseManager ready  "
            f"min_sev={case_min_severity}  dedup={case_dedup_sec}s  "
            f"dry_run={dry_run}"
        )

    # ── public API ────────────────────────────────────────────────────────

    def process_alert(self, alert: dict) -> Union[str, bool, None]:
        severity = alert.get("severity", "LOW")

        if SEVERITY_MAP.get(severity, 0) < self._min_sev_int:
            logger.debug(
                f"Case skipped (below min sev): "
                f"rule={alert.get('rule_id','?')} sev={severity}"
            )
            return None

        rule_id = alert.get("rule_id", "?")
        srcip   = alert.get("srcip", "") or ""
        key     = f"{rule_id}|{srcip}"
        now     = time.monotonic()

        last = self._last_sent.get(key)
        if last is not None and (now - last) < self.case_dedup_sec:
            logger.debug(
                f"Case dedup-skipped: rule={rule_id} src={srcip} "
                f"(cooldown {self.case_dedup_sec - (now - last):.0f}s left)"
            )
            return DEDUP_SKIPPED

        case_data = self._build_alert_case(alert, severity)

        if self.dry_run:
            print(f"[DRY-RUN] Would create case: {case_data['title']}")
            return None

        try:
            result = self.client.create_case(case_data)
            case_id: str = result.get("_id") or result.get("id") or ""
            self._last_sent[key] = now
            print(f"[+] TheHive case created: {case_data['title']}  (id={case_id})")
            logger.info(
                f"TheHive case created  id={case_id}  rule={rule_id}  "
                f"sev={severity}  src={srcip}"
            )
            return case_id
        except Exception as exc:
            print(f"[!] Failed creating case: {exc}")
            logger.error(f"TheHive create_case error: {exc}")
            return None

    def process_correlation(
        self, corr: dict, agent_id: str
    ) -> Union[str, bool, None]:
        name = corr.get("name", "UNKNOWN_CORRELATION")
        sev  = corr.get("severity", "HIGH")
        key  = f"CORR|{name}|{agent_id}"
        now  = time.monotonic()

        last = self._last_sent.get(key)
        if last is not None and (now - last) < self.case_dedup_sec:
            logger.debug(
                f"Correlation case dedup-skipped: name={name} agent={agent_id}"
            )
            return DEDUP_SKIPPED

        case_data = self._build_correlation_case(corr, agent_id, sev)

        if self.dry_run:
            print(f"[DRY-RUN] Would create correlation case: {case_data['title']}")
            return None

        try:
            result  = self.client.create_case(case_data)
            case_id = result.get("_id") or result.get("id") or ""
            self._last_sent[key] = now
            print(f"[+] TheHive correlation case created: {case_data['title']}  (id={case_id})")
            logger.info(
                f"TheHive correlation case created  id={case_id}  "
                f"name={name}  agent={agent_id}"
            )
            return case_id
        except Exception as exc:
            print(f"[!] Correlation case failed: {exc}")
            logger.error(f"TheHive correlation create_case error: {exc}")
            return None

    def cleanup(self) -> None:
        now    = time.monotonic()
        cutoff = now - self.case_dedup_sec
        before = len(self._last_sent)
        self._last_sent = {k: v for k, v in self._last_sent.items() if v > cutoff}
        evicted = before - len(self._last_sent)
        if evicted:
            logger.debug(f"TheHiveCaseManager.cleanup: evicted {evicted} dedup entries")

    def reset(self) -> None:
        self._last_sent.clear()
        logger.debug("TheHiveCaseManager.reset: dedup store cleared")

    # ── private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _build_alert_case(alert: dict, severity: str) -> dict:
        rule_id   = alert.get("rule_id", "?")
        desc      = alert.get("description", "Wazuh Alert")
        srcip     = alert.get("srcip", "") or "N/A"
        dstip     = alert.get("dstip", "") or "N/A"
        agent     = alert.get("agent_name", "N/A")
        agent_id  = alert.get("agent_id", "N/A")
        agent_ip  = alert.get("agent_ip", "") or "N/A"
        timestamp = alert.get("timestamp", "")
        location  = alert.get("location", "") or "N/A"
        mitre     = ", ".join(alert.get("mitre", [])) or "N/A"
        reason    = alert.get("reason", "") or desc
        full_log  = (alert.get("full_log") or "")[:700]

        log_section = f"\n**Raw Log (truncated)**\n```\n{full_log}\n```" if full_log else ""

        return {
            "title": f"[{severity}] Rule {rule_id} — {desc[:80]}",
            "description": (
                f"## Wazuh SOC Alert\n\n"
                f"| Field       | Value |\n"
                f"|-------------|-------|\n"
                f"| Timestamp   | {timestamp} |\n"
                f"| Rule ID     | {rule_id} |\n"
                f"| Severity    | {severity} |\n"
                f"| Reason      | {reason} |\n"
                f"| Source IP   | {srcip} |\n"
                f"| Dest IP     | {dstip} |\n"
                f"| Agent       | {agent} (ID: {agent_id}) |\n"
                f"| Agent IP    | {agent_ip} |\n"
                f"| Location    | {location} |\n"
                f"| MITRE       | {mitre} |\n"
                f"{log_section}"
            ),
            "severity": SEVERITY_MAP.get(severity, 1),
            "tlp":  2,
            "pap":  2,
            "tags": ["wazuh", "soc", severity.lower(), f"rule:{rule_id}"],
            "flag": severity == "CRITICAL",
            "customFields": {
                "wazuh_agent_id": {
                    "string": alert.get("agent_id", "")
                },
                "wazuh_alert_id": {
                    "string": alert.get("alert_id", "") or alert.get("timestamp", "")
                },
                "wazuh_rule_id": {
                    "string": alert.get("rule_id", "")
                }
            }
        }

    @staticmethod
    def _build_correlation_case(corr: dict, agent_id: str, sev: str) -> dict:
        name = corr.get("name", "UNKNOWN_CORRELATION")
        desc = corr.get("description", "")

        return {
            "title": f"[CORRELATION] {name}",
            "description": (
                f"## Wazuh Correlation Event\n\n"
                f"| Field      | Value |\n"
                f"|------------|-------|\n"
                f"| Name       | {name} |\n"
                f"| Severity   | {sev} |\n"
                f"| Agent ID   | {agent_id} |\n"
                f"| Detail     | {desc} |\n"
            ),
            "severity": SEVERITY_MAP.get(sev, 3),
            "tlp":  2,
            "pap":  2,
            "tags": ["wazuh", "correlation", sev.lower()],
            "flag": sev == "CRITICAL",
        }