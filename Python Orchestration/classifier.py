# classifier.py – severity classification and MITRE mapping
from config import CRITICAL_RULES, HIGH_RULES, MEDIUM_RULES, MITRE_MAPPING

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}

def safe_level(raw_level) -> int:
    if raw_level is None or raw_level == "":
        return 0
    try:
        return int(raw_level)
    except (TypeError, ValueError):
        return 0

def level_to_severity(level: int) -> str:
    if level >= 13:
        return "CRITICAL"
    if level >= 10:
        return "HIGH"
    if level >= 7:
        return "MEDIUM"
    if level >= 4:
        return "LOW"
    return "INFO"

def classify_rule(rule_id: str, level: int, desc: str = "") -> tuple[str, str]:
    if rule_id in CRITICAL_RULES:
        return "CRITICAL", CRITICAL_RULES[rule_id]
    if rule_id in HIGH_RULES:
        return "HIGH", HIGH_RULES[rule_id]
    if rule_id in MEDIUM_RULES:
        return "MEDIUM", MEDIUM_RULES[rule_id]
    sev = level_to_severity(level)
    label = desc[:80] if desc else f"level {level}"
    return sev, f"{sev} – {label}"

def get_mitre(rule_id: str) -> list[str]:
    return list(MITRE_MAPPING.get(rule_id, []))