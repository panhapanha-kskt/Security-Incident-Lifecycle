#!/usr/bin/env python3
"""
thehive_responder.py
────────────────────
Standalone responder trigger — no observable logic required.
Mirrors the TheHive UI action:
    Open Case → Click "Responders" → Select → Click "Run"
"""
from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class TheHiveResponderRunner:
    """
    Trigger a named Cortex responder on a TheHive case,
    identical to clicking the responder button in the UI.
    """

    def __init__(
        self,
        client,
        responder_name: str,
        retry_delay: float = 1.0,
        max_retries: int = 2,
        poll_result: bool = False,
        poll_interval: float = 3.0,
        poll_timeout: float = 60.0,
    ) -> None:
        self._client         = client
        self._responder_name = responder_name
        self._retry_delay    = retry_delay
        self._max_retries    = max_retries
        self._poll_result    = poll_result
        self._poll_interval  = poll_interval
        self._poll_timeout   = poll_timeout

    # ── Public entry point ─────────────────────────────────────────────────

    def run(self, case_id: str) -> dict:
        summary = {
            "case_id":    case_id,
            "responder":  self._responder_name,
            "action_id":  None,
            "status":     "failed",
            "job_result": None,
            "error":      None,
        }

        responder_id = self._resolve_responder_id(case_id)
        if not responder_id:
            summary["status"] = "not_found"
            summary["error"]  = (
                f"Responder '{self._responder_name}' not found for case {case_id}"
            )
            logger.error(summary["error"])
            return summary

        action_id = self._trigger(case_id, responder_id)
        if not action_id:
            summary["error"] = "Responder trigger returned no action ID"
            return summary

        summary["action_id"] = action_id
        summary["status"]    = "triggered"
        logger.info(
            f"Responder '{self._responder_name}' triggered on case {case_id} "
            f"→ action_id={action_id}"
        )

        if self._poll_result:
            job_result = self._poll_job(action_id)
            summary["job_result"] = job_result
            logger.info(
                f"Cortex job result for case {case_id} "
                f"action={action_id}: {job_result}"
            )

        return summary

    # ── Step 1: resolve responder ID ───────────────────────────────────────

    def _resolve_responder_id(self, case_id: str) -> Optional[str]:
        url = (
            f"{self._client.url}/api/connector/cortex/responder"
            f"/case/{case_id}"
        )
        try:
            resp = self._client.session.get(url, timeout=self._client.timeout)

            if resp.status_code != 200:
                logger.error(
                    f"Failed to list responders for case {case_id}: "
                    f"HTTP {resp.status_code} — {resp.text[:120]}"
                )
                return None

            responders: list[dict] = resp.json()
            for r in responders:
                if r.get("name") == self._responder_name:
                    logger.debug(
                        f"Resolved responder '{self._responder_name}' "
                        f"→ id={r['id']}"
                    )
                    return r["id"]

            logger.warning(
                f"Responder '{self._responder_name}' not found among "
                f"{len(responders)} available responder(s) for case {case_id}"
            )
            return None

        except Exception as exc:
            logger.error(f"Exception resolving responder for case {case_id}: {exc}")
            return None

    # ── Step 2: trigger the responder ──────────────────────────────────────

    def _trigger(self, case_id: str, responder_id: str) -> Optional[str]:
        url     = f"{self._client.url}/api/connector/cortex/action"
        payload = {
            "responderId": responder_id,
            "objectType":  "case",
            "objectId":    case_id,
        }

        for attempt in range(1, self._max_retries + 2):
            try:
                resp = self._client.session.post(
                    url,
                    json=payload,
                    timeout=self._client.timeout,
                )

                if resp.status_code in (200, 201):
                    return resp.json().get("id", "unknown")

                if resp.status_code >= 500 and attempt <= self._max_retries:
                    logger.warning(
                        f"Responder trigger HTTP {resp.status_code} — "
                        f"retrying ({attempt}/{self._max_retries})"
                    )
                    time.sleep(self._retry_delay * attempt)
                    continue

                logger.error(
                    f"Responder trigger failed case={case_id} "
                    f"HTTP {resp.status_code}: {resp.text[:120]}"
                )
                return None

            except Exception as exc:
                if attempt <= self._max_retries:
                    logger.warning(
                        f"Responder trigger exception (attempt {attempt}): "
                        f"{exc} — retrying"
                    )
                    time.sleep(self._retry_delay * attempt)
                    continue

                logger.error(
                    f"Responder trigger exception case={case_id}: {exc}"
                )
                return None

        logger.error(
            f"Responder trigger exceeded max retries for case {case_id}"
        )
        return None

    # ── Step 3 (optional): poll Cortex job until done ──────────────────────

    def _poll_job(self, action_id: str) -> str:
        url      = f"{self._client.url}/api/connector/cortex/job/{action_id}"
        waited   = 0.0
        terminal = {"Success", "Failure"}

        while waited < self._poll_timeout:
            try:
                resp = self._client.session.get(url, timeout=self._client.timeout)
                if resp.status_code == 200:
                    data   = resp.json()
                    status = data.get("status", "")
                    if status in terminal:
                        return status
                    logger.debug(
                        f"Cortex job {action_id} status={status} — "
                        f"polling again in {self._poll_interval}s"
                    )
                else:
                    logger.warning(
                        f"Poll job HTTP {resp.status_code} for action {action_id}"
                    )
            except Exception as exc:
                logger.warning(f"Poll job exception: {exc}")

            time.sleep(self._poll_interval)
            waited += self._poll_interval

        logger.warning(
            f"Poll timeout reached for action {action_id} after {self._poll_timeout}s"
        )
        return "timeout"


# ── Convenience function ───────────────────────────────────────────────────

def run_responder(
    client,
    case_id:        str,
    responder_name: str,
    poll_result:    bool  = False,
    poll_timeout:   float = 60.0,
) -> dict:
    runner = TheHiveResponderRunner(
        client         = client,
        responder_name = responder_name,
        poll_result    = poll_result,
        poll_timeout   = poll_timeout,
    )
    return runner.run(case_id)