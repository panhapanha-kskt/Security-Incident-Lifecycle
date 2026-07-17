import time
from typing import Optional
from config import CORRELATION_WINDOW

class Correlator:
    SIGNATURES: list[dict] = [
        {
            "name":        "TOR_C2_CHANNEL_SUSPECTED",
            "conditions":  frozenset({"100625", "100101"}),
            "severity":    "CRITICAL",
            "description": "TOR node + reverse-shell tool detected within 5 min",
        },
        {
            "name":        "ACTIVE_COMPROMISE",
            "conditions":  frozenset({"100628", "100117"}),
            "severity":    "CRITICAL",
            "description": "Criminal IP inbound + critical file modified within 5 min",
        },
        {
            "name":        "BRUTE_THEN_ROOT",
            "conditions":  frozenset({"100901", "100106"}),
            "severity":    "CRITICAL",
            "description": "SSH brute-force confirmed + privilege escalation attempt",
        },
        {
            "name":        "SCAN_THEN_EXPLOIT",
            "conditions":  frozenset({"100904", "100805"}),
            "severity":    "HIGH",
            "description": "Zeek port-scan + SQL injection attempt within 5 min",
        },
        {
            "name":        "MINER_DROPPED",
            "conditions":  frozenset({"100101", "100119"}),
            "severity":    "HIGH",
            "description": "Reverse-shell + crypto-mining tool detected together",
        },
    ]

    def __init__(self) -> None:
        self._history: list[tuple[float, str, str]] = []
        self._active: set[tuple[str, str]] = set()
        self._fired: dict[tuple[str, str], float] = {}

    def add(self, rule_id: str, agent_id: str) -> None:
        now = time.monotonic()
        self._history.append((now, agent_id, rule_id))
        self._evict(now)                  
        self._active.add((agent_id, rule_id))

    def check(self) -> Optional[dict]:
        now = time.monotonic()
        self._evict(now)
        cutoff = now - CORRELATION_WINDOW
        self._fired = {k: v for k, v in self._fired.items() if v > cutoff}
        agent_rules: dict[str, set[str]] = {}
        for ag_id, r_id in self._active:
            agent_rules.setdefault(ag_id, set()).add(r_id)

        for sig in self.SIGNATURES:
            name = sig["name"]
            for ag_id, rules in agent_rules.items():
                if (name, ag_id) in self._fired:
                    continue                  
                if sig["conditions"].issubset(rules):
                    self._fired[(name, ag_id)] = now
                    return {
                        "name":        name,
                        "severity":    sig["severity"],
                        "description": sig["description"],
                    }
        return None

    def reset(self) -> None:
        self._history.clear()
        self._active.clear()
        self._fired.clear()

    def _evict(self, now: float) -> None:
        cutoff        = now - CORRELATION_WINDOW
        self._history = [(t, a, r) for t, a, r in self._history if t > cutoff]
        self._active  = {(a, r) for (_, a, r) in self._history}
