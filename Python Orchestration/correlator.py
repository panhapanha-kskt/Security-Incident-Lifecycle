# correlator.py – in-memory correlation engine (agent-aware)
#
# _active lifecycle note:
#   _active is a *derived view* of _history, not an independent set.
#   Every call to _evict() rebuilds _active from whatever entries remain
#   in _history after the CORRELATION_WINDOW cutoff.  This means:
#     • Rules older than CORRELATION_WINDOW are automatically expired —
#       intentional; we only correlate events that happened close together.
#     • There is no way to "pin" a rule in _active independently of _history.
#     • Callers should NOT cache references to _active between calls.
#
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
        # _history: ordered list of (monotonic_timestamp, agent_id, rule_id)
        # Acts as the single source of truth; _active is always derived from it.
        self._history: list[tuple[float, str, str]] = []

        # _active: set of (agent_id, rule_id) pairs still within CORRELATION_WINDOW.
        # Rebuilt on every _evict() call — do NOT treat as a persistent store.
        self._active: set[tuple[str, str]] = set()

        # _fired: tracks which (signature_name, agent_id) combos have already
        # fired within the current window to prevent duplicate correlation alerts.
        # Entries are evicted when their timestamp falls outside CORRELATION_WINDOW.
        self._fired: dict[tuple[str, str], float] = {}

    def add(self, rule_id: str, agent_id: str) -> None:
        """
        Record that *rule_id* fired on *agent_id* at this moment.
        Immediately evicts history entries older than CORRELATION_WINDOW so
        _active stays current without a separate periodic cleanup call.
        """
        now = time.monotonic()
        self._history.append((now, agent_id, rule_id))
        self._evict(now)                  # rebuilds _active as a side-effect
        self._active.add((agent_id, rule_id))

    def check(self) -> Optional[dict]:
        """
        Inspect the current window for matching signatures.

        Returns the first unfired signature whose conditions are fully met
        by a single agent within CORRELATION_WINDOW, or None.

        Note: because _active is rebuilt from _history on every _evict() call,
        any rules that have aged out of the window will NOT appear here —
        which is exactly the desired behaviour for time-bounded correlation.
        """
        now = time.monotonic()
        self._evict(now)

        # Evict expired fired entries so the same signature can re-fire after
        # the window has fully rolled past the original events.
        cutoff = now - CORRELATION_WINDOW
        self._fired = {k: v for k, v in self._fired.items() if v > cutoff}

        # Group currently-active rules by agent
        agent_rules: dict[str, set[str]] = {}
        for ag_id, r_id in self._active:
            agent_rules.setdefault(ag_id, set()).add(r_id)

        for sig in self.SIGNATURES:
            name = sig["name"]
            for ag_id, rules in agent_rules.items():
                if (name, ag_id) in self._fired:
                    continue                  # already fired for this agent
                if sig["conditions"].issubset(rules):
                    self._fired[(name, ag_id)] = now
                    return {
                        "name":        name,
                        "severity":    sig["severity"],
                        "description": sig["description"],
                    }
        return None

    def reset(self) -> None:
        """Clear all state — call on day-boundary rollover."""
        self._history.clear()
        self._active.clear()
        self._fired.clear()

    # ── private ───────────────────────────────────────────────────────────

    def _evict(self, now: float) -> None:
        """
        Remove history entries older than CORRELATION_WINDOW and rebuild
        _active from whatever remains.

        This is the *only* place _active is written after __init__.
        Any (agent_id, rule_id) pair whose last event has aged past the
        window will disappear from _active automatically.
        """
        cutoff        = now - CORRELATION_WINDOW
        self._history = [(t, a, r) for t, a, r in self._history if t > cutoff]
        # Rebuild from history — intentionally discards expired rules
        self._active  = {(a, r) for (_, a, r) in self._history}