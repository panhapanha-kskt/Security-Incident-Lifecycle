#!/usr/bin/env python3
from __future__ import annotations
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional
logger = logging.getLogger(__name__)
HITL_ENABLED        = os.environ.get("HITL_ENABLED", "true").strip().lower() == "true"
HITL_LISTEN_HOST    = os.environ.get("HITL_LISTEN_HOST", "0.0.0.0")
HITL_LISTEN_PORT    = int(os.environ.get("HITL_LISTEN_PORT", "8899"))
HITL_PUBLIC_BASE    = os.environ.get("HITL_PUBLIC_BASE", "http://172.24.80.95:8899")
HITL_TIMEOUT_SEC    = int(os.environ.get("HITL_TIMEOUT_SEC", "120"))   # 2 minutes
HITL_TIMEOUT_ACTION = os.environ.get("HITL_TIMEOUT_ACTION", "reject").strip().lower()
HITL_TIMEOUT_ACTION_LABEL = "APPROVE (fail-open)" if HITL_TIMEOUT_ACTION == "approve" else "REJECT (fail-closed)"
_POLL_INTERVAL = 0.5
@dataclass
class _PendingApproval:
    token:      str
    case_id:    str
    rule_id:    str
    created_at: float = field(default_factory=time.monotonic)
    status:     str   = "pending"   # pending | approved | rejected
    decided_at: Optional[float] = None
    decided_by: Optional[str]   = None
class ApprovalGate:
    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._pending: dict[str, _PendingApproval] = {}
        self._server_started = False
    # ── public API 
    def create_request(self, case_id: str, rule_id: str) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._pending[token] = _PendingApproval(token=token, case_id=case_id, rule_id=rule_id)
        return token
    def approve_url(self, token: str) -> str:
        return f"{HITL_PUBLIC_BASE}/hitl/approve/{token}"
    def reject_url(self, token: str) -> str:
        return f"{HITL_PUBLIC_BASE}/hitl/reject/{token}"
    def wait_for_decision(self, token: str, timeout: float = HITL_TIMEOUT_SEC) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                rec = self._pending.get(token)
                if rec and rec.status != "pending":
                    approved = rec.status == "approved"
                    logger.info(
                        f"HITL decision received  token={token[:8]}…  "
                        f"case={rec.case_id}  status={rec.status}  by={rec.decided_by}"
                    )
                    return approved
            time.sleep(_POLL_INTERVAL)
        with self._lock:
            rec = self._pending.get(token)
            case_id = rec.case_id if rec else "?"
            if rec:
                rec.status     = f"timeout_{HITL_TIMEOUT_ACTION}"
                rec.decided_at = time.monotonic()
        logger.warning(
            f"HITL timeout ({timeout:.0f}s) — no response  token={token[:8]}…  "
            f"case={case_id}  default_action={HITL_TIMEOUT_ACTION}"
        )
        return HITL_TIMEOUT_ACTION == "approve"
    def resolve(self, token: str, decision: str, decided_by: str = "email-link") -> bool:
        with self._lock:
            rec = self._pending.get(token)
            if rec is None:
                return False
            if rec.status != "pending":
                return True  # already decided — idempotent double-click
            rec.status     = decision
            rec.decided_at = time.monotonic()
            rec.decided_by = decided_by
        return True
    def cleanup(self, max_age_sec: int = 3600) -> None:
        now = time.monotonic()
        with self._lock:
            for tok in [t for t, r in self._pending.items() if now - r.created_at > max_age_sec]:
                del self._pending[tok]
    # ── HTTP listener 
    def start_server(self) -> None:
        if self._server_started or not HITL_ENABLED:
            return
        self._server_started = True
        threading.Thread(target=self._run_flask, daemon=True).start()
        logger.info(f"HITL approval listener starting  {HITL_LISTEN_HOST}:{HITL_LISTEN_PORT}")
    def _run_flask(self) -> None:
        from flask import Flask, Response
        app = Flask(__name__)
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.WARNING)
        @app.route("/hitl/approve/<token>")
        def _approve(token):
            ok = self.resolve(token, "approved")
            msg = "Approved — automated response will proceed." if ok else "Unknown or expired token."
            return Response(_page(ok, msg), mimetype="text/html")
        @app.route("/hitl/reject/<token>")
        def _reject(token):
            ok = self.resolve(token, "rejected")
            msg = "Rejected — no automated action will be taken for this alert." if ok else "Unknown or expired token."
            return Response(_page(ok, msg), mimetype="text/html")

        app.run(host=HITL_LISTEN_HOST, port=HITL_LISTEN_PORT, debug=False, use_reloader=False)
def _page(ok: bool, msg: str) -> str:
    color = "#639922" if ok else "#E24B4A"
    return (
        f"<html><body style='background:#111;color:#eee;font-family:monospace;"
        f"display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'>"
        f"<div style='text-align:center;'><h2 style='color:{color};'>{msg}</h2>"
        f"<p style='color:#888;'>ASIL SOC &middot; CBSA Group 7</p></div></body></html>"
    )

gate = ApprovalGate()   # module-level singleton, same pattern as thehive_observable.py
