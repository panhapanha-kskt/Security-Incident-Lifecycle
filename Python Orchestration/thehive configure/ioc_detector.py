#!/usr/bin/env python3
# ioc_detector.py – IOC classification engine
# (Production version – includes malware-hash IOC fix)

from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from config import (
    ALERT_FILE,
    CRITICAL_RULES,
    FAILED_LOGIN_RULES,
    HIGH_RULES,
    LOG_FILE,
    MALWARE_HASH_RULES,
    MEDIUM_RULES,
)

# IOC_RULE_SETS now includes MALWARE_HASH_RULES so that rules like
# 110002/110003/110004 are correctly flagged as IOCs.
IOC_RULE_SETS: tuple = (
    CRITICAL_RULES,
    HIGH_RULES,
    FAILED_LOGIN_RULES,
    MALWARE_HASH_RULES,
)

_NEWLINE_RE = re.compile(r"[\r\n\x00]")


def _safe(value: object, max_len: int = 300) -> str:
    """Strip control characters and truncate for safe log writing."""
    return _NEWLINE_RE.sub(" ", str(value or ""))[:max_len]


class IOCClassifier:
    """
    Loads Wazuh alerts.json, classifies each alert by rule ID, determines
    IOC status, and produces a structured result set.
    """

    def load_alerts(self) -> list[dict]:
        """Read every JSON line from ALERT_FILE; skip malformed lines."""
        alerts: list[dict] = []
        path = Path(ALERT_FILE)

        if not path.exists():
            print(f"[-] Error: Alert file not found: {ALERT_FILE}")
            return alerts

        try:
            with open(path, "r", errors="replace") as fh:
                for lineno, raw in enumerate(fh, 1):
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            alerts.append(obj)
                        else:
                            print(
                                f"[-] Warning: Line {lineno} is not a JSON "
                                f"object — skipped"
                            )
                    except json.JSONDecodeError:
                        print(
                            f"[-] Warning: Malformed JSON at line {lineno} — "
                            f"skipped: {line[:80]}"
                        )
        except PermissionError:
            print(f"[-] Error: Permission denied reading {ALERT_FILE}")

        return alerts

    def get_rule_id(self, alert: dict) -> str | None:
        """Extract rule.id as a string; return None if absent."""
        try:
            rid = alert["rule"]["id"]
            return str(rid).strip() if rid else None
        except (KeyError, TypeError):
            return None

    def classify(self, rule_id: str | None) -> str:
        """
        Map a rule ID to a severity category string.
        Explicit "Malware Hash" branch added (FIX 2).
        """
        if not rule_id:
            return "Unknown"
        if rule_id in CRITICAL_RULES:
            return "Critical"
        if rule_id in HIGH_RULES:
            return "High"
        if rule_id in MEDIUM_RULES:
            return "Medium"
        if rule_id in FAILED_LOGIN_RULES:
            return "Failed Login"
        if rule_id in MALWARE_HASH_RULES:
            return "Malware Hash"
        return "Unknown"

    def is_ioc(self, rule_id: str | None) -> bool:
        """
        Return True if the rule ID belongs to an IOC‑grade rule set.
        MALWARE_HASH_RULES included (FIX 1).
        """
        if not rule_id:
            return False
        return any(rule_id in rs for rs in IOC_RULE_SETS)

    def classify_alert(self, alert: dict) -> dict:
        """Return an enriched dict for one raw Wazuh alert dict."""
        rule        = alert.get("rule") or {}
        agent       = alert.get("agent") or {}
        data_obj    = alert.get("data") or {}
        rule_id     = self.get_rule_id(alert)
        srcip       = str(
            data_obj.get("srcip") or data_obj.get("src_ip") or
            alert.get("srcip")   or alert.get("src_ip")    or ""
        )
        dstip       = str(
            data_obj.get("dstip") or data_obj.get("dst_ip") or
            alert.get("dstip")   or alert.get("dst_ip")    or ""
        )
        mitre_raw   = rule.get("mitre", {})
        mitre_ids: list[str] = (
            mitre_raw.get("id", []) if isinstance(mitre_raw, dict) else []
        )

        return {
            "timestamp":   alert.get("timestamp", ""),
            "rule_id":     rule_id,
            "category":    self.classify(rule_id),
            "is_ioc":      self.is_ioc(rule_id),
            "description": str(rule.get("description") or ""),
            "agent_id":    str(agent.get("id") or ""),
            "agent_name":  str(agent.get("name") or ""),
            "srcip":       srcip,
            "dstip":       dstip,
            "full_log":    str(alert.get("full_log") or "")[:700],
            "mitre":       mitre_ids,
            "data":        data_obj,
            # syscheck sub-dict passed through so ObservableExtractor can
            # pull typed hash fields (md5_after, sha256_after, etc.) directly
            "syscheck":    alert.get("syscheck") or {},
        }

    def process(self) -> dict[str, list[dict]]:
        """Load all alerts and bucket them by category."""
        results: dict[str, list[dict]] = {
            "Critical": [], "Malware Hash": [], "High": [],
            "Medium": [], "Failed Login": [], "Unknown": [],
        }
        raw_alerts   = self.load_alerts()
        unknown_count = 0
        for alert in raw_alerts:
            enriched = self.classify_alert(alert)
            category = enriched["category"]
            if category == "Unknown":
                unknown_count += 1
            results.setdefault(category, []).append(enriched)
        if unknown_count:
            print(
                f"[~] Note: {unknown_count} alert(s) had no matching rule ID "
                f"and were placed in 'Unknown'."
            )
        return results

    def report(self, results: dict[str, list[dict]]) -> None:
        """Print a terminal summary."""
        total = sum(len(v) for v in results.values())
        print(f"\n{'═' * 60}")
        print(
            f"  IOC CLASSIFIER REPORT  —  "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        print(f"  Total alerts processed: {total}")
        print(f"{'═' * 60}")

        order = ["Critical", "Malware Hash", "High", "Medium", "Failed Login", "Unknown"]
        ioc_categories = {"Critical", "Malware Hash", "High", "Failed Login"}
        for category in order:
            items = results.get(category, [])
            ioc_marker = " [IOC]" if category in ioc_categories else ""
            print(f"\n=== {category}{ioc_marker} Alerts ({len(items)}) ===")
            for item in items:
                ioc_tag = " ★IOC" if item["is_ioc"] else ""
                print(
                    f"  - [{_safe(item['timestamp'], 30)}] "
                    f"Rule {_safe(item['rule_id'], 10)}{ioc_tag}"
                    f" | Agent: {_safe(item['agent_name'], 40)}"
                    f" | {_safe(item['description'], 80)}"
                )
                if item["srcip"]:
                    print(f"      SRC: {_safe(item['srcip'], 45)}")
                sc = item.get("syscheck") or {}
                if sc.get("path"):
                    print(f"      FILE: {_safe(sc['path'], 200)}")
        print(f"\n{'═' * 60}\n")

    def write_log(self, results: dict[str, list[dict]]) -> None:
        """Append a structured report to LOG_FILE."""
        log_path = Path(LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(
                    f"\n=== IOC Report Generated at "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} ===\n"
                )
                order = ["Critical", "Malware Hash", "High", "Medium", "Failed Login", "Unknown"]
                for category in order:
                    items = results.get(category, [])
                    fh.write(f"\n--- {category} Alerts ({len(items)}) ---\n")
                    for item in items:
                        ioc_flag = "IOC=YES" if item["is_ioc"] else "IOC=NO"
                        sc       = item.get("syscheck") or {}
                        file_hint = _safe(sc.get("path", ""), 200) if sc else ""
                        line = (
                            f"{_safe(item['timestamp'], 30)} | "
                            f"{ioc_flag} | "
                            f"Rule: {_safe(item['rule_id'], 10)} | "
                            f"Agent: {_safe(item['agent_name'], 40)} | "
                            f"SRC: {_safe(item['srcip'], 45)} | "
                            f"File: {file_hint} | "
                            f"Desc: {_safe(item['description'], 120)}\n"
                        )
                        fh.write(line)
        except (PermissionError, OSError) as exc:
            print(f"[-] Error writing to log file: {exc}")


if __name__ == "__main__":
    engine  = IOCClassifier()
    results = engine.process()
    engine.report(results)
    engine.write_log(results)
