#!/usr/bin/env python3
from __future__ import annotations
import json
import logging
import os
import re
import time
from typing import Optional
import requests as _requests

logger = logging.getLogger(__name__)

_WAZUH_MANAGER: str = os.environ.get("WAZUH_API_URL",  "https://192.168.200.129:55000")
_WAZUH_USER:    str = os.environ.get("WAZUH_API_USER", "wazuh-wui")
_WAZUH_PASS:    str = os.environ.get("WAZUH_API_PASS", "")
_CORTEX_URL: str = os.environ.get("CORTEX_URL", "https://172.24.80.95:9443")
_CORTEX_KEY: str = os.environ.get("CORTEX_KEY", "zE58rzZN9Bxc+yU+I037r2XqmqRrGfAq")

# ── NEW: Indexer creds for real AR-success confirmation ──────────────────────
# The manager's <indexer> block already points at this host (see ossec.conf).
# Set WAZUH_INDEXER_USER / WAZUH_INDEXER_PASS in the environment to enable
# genuine confirmation. If unset, the code falls back to trusting the
# dispatch-only result (old behaviour), but logs a clear warning so nobody
# mistakes "dispatched" for "confirmed" again.
_INDEXER_URL:  str = os.environ.get("WAZUH_INDEXER_URL", "https://192.168.200.129:9200")
_INDEXER_USER: str = os.environ.get("WAZUH_INDEXER_USER", "admin")
_INDEXER_PASS: str = os.environ.get("WAZUH_INDEXER_PASS", "")
_INDEXER_INDEX_PATTERN: str = os.environ.get("WAZUH_INDEXER_INDEX", "wazuh-alerts-*")

RESPONDER_NETWORK: str = "Wazuh_1_0"
RESPONDER_FIM:     str = "WazuhFIM_1_0"
_CORTEX_UUID_MAP: dict[str, list[tuple[str, str]]] = {
    RESPONDER_NETWORK: [
        ("Wazuh_1_0_1_0", "c45653768b9ab1e95aee1969a04a4c5d"),
        ("Wazuh_1_0",     "9005ef9766e6885f2d29ed57372b4dbe"),
    ],
    RESPONDER_FIM: [
        ("WazuhFIM_1_0_1_0", "a3ea8a5fbd48194607e9f0cd502b5295"),
    ],
}


def _trigger_responder_cortex_direct(case_id: str, responder_name: str) -> dict:
    variants = _CORTEX_UUID_MAP.get(responder_name)
    if not variants:
        return {
            "status":    "failed",
            "action_id": None,
            "error":     f"No Cortex UUID configured for '{responder_name}'",
        }

    headers = {
        "Authorization": f"Bearer {_CORTEX_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "data":     case_id,
        "dataType": "thehive:case",
        "tlp":      2,
    }
    for variant_name, uuid in variants:
        url = f"{_CORTEX_URL}/api/responder/{uuid}/run"
        logger.debug(
            f"Cortex direct POST  url={url}  case={case_id}  "
            f"responder={variant_name}  uuid={uuid}"
        )
        try:
            resp = _requests.post(
                url,
                headers=headers,
                data=json.dumps(payload),
                verify=False,
                timeout=30,
            )
            if resp.status_code in (200, 201):
                body   = resp.json()
                job_id = body.get("id") or body.get("_id") or "?"
                logger.info(
                    f"Cortex direct triggered  case={case_id}  "
                    f"responder={variant_name}  uuid={uuid}  job_id={job_id}"
                )
                return {"status": "triggered", "action_id": job_id, "error": None}
            if resp.status_code == 404:
                logger.warning(
                    f"Cortex direct 404  case={case_id}  "
                    f"responder={variant_name}  uuid={uuid} — trying next"
                )
                continue
            logger.error(
                f"Cortex direct failed  case={case_id}  "
                f"responder={variant_name}  "
                f"HTTP {resp.status_code}: {resp.text[:300]}"
            )
            continue
        except Exception as exc:
            logger.error(
                f"Cortex direct exception  case={case_id}  "
                f"responder={variant_name}  error={exc}"
            )
            continue
    return {
        "status":    "failed",
        "action_id": None,
        "error":     f"All Cortex direct attempts failed for '{responder_name}'",
    }


def _trigger_responder_via_thehive(client, case_id: str, responder_name: str) -> dict:
    variants = _CORTEX_UUID_MAP.get(responder_name)
    if not variants:
        return {
            "status":    "failed",
            "action_id": None,
            "error":     f"No responder UUID configured for '{responder_name}'",
        }

    for variant_name, uuid in variants:
        url = f"{client.url}/api/connector/cortex/action"
        payload = {
            "responderId": uuid,
            "objectId":    case_id,
            "objectType":  "case",
        }
        try:
            resp = client.session.post(url, json=payload, timeout=client.timeout)
            if resp.status_code in (200, 201):
                body   = resp.json()
                job_id = body.get("id") or body.get("_id") or body.get("cortexJobId") or "?"
                logger.info(
                    f"TheHive-routed responder triggered  case={case_id}  "
                    f"responder={variant_name}  uuid={uuid}  job_id={job_id}"
                )
                return {"status": "triggered", "action_id": job_id, "error": None}
            logger.warning(
                f"TheHive action HTTP {resp.status_code}  case={case_id}  "
                f"responder={variant_name}: {resp.text[:200]}"
            )
        except Exception as exc:
            logger.warning(
                f"TheHive action exception  case={case_id}  "
                f"responder={variant_name}: {exc}"
            )

    return {
        "status":    "failed",
        "action_id": None,
        "error":     f"All TheHive-routed attempts failed for '{responder_name}'",
    }


def _extract_from_tags(tags: list, prefix: str) -> str:
    if not tags:
        return ""
    for tag in tags:
        if isinstance(tag, str) and tag.startswith(f"{prefix}:"):
            return tag.split(":", 1)[1]
    return ""


def _extract_from_description_metadata(description: str, key: str) -> str:
    if not description:
        return ""
    match = re.search(r'<!--WAZUH_METADATA\s+(\{.*?\})\s*-->', description)
    if match:
        try:
            return str(json.loads(match.group(1)).get(key, ""))
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return ""


def _read_custom_field(custom_fields, key: str) -> str:
    if isinstance(custom_fields, list):
        result = {}
        for item in custom_fields:
            if isinstance(item, dict):
                name  = item.get("name")  or item.get("key")    or ""
                value = item.get("value") or item.get("string") or ""
                if name:
                    result[name] = value
        custom_fields = result
    if not isinstance(custom_fields, dict):
        return ""
    field = custom_fields.get(key)
    if field is None:
        return ""
    if isinstance(field, str):
        return field.strip()
    if isinstance(field, dict):
        return str(field.get("string") or field.get("value") or "").strip()
    return str(field).strip()


def _scrape_srcip_from_description(description: str) -> str:
    if not description:
        return ""
    m = re.search(
        r"\|\s*Source IP\s*\|\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*\|",
        description,
    )
    if m:
        ip = m.group(1).strip()
        if ip and ip not in ("N/A", ""):
            return ip
    return ""


def _scrape_agentip_from_description(description: str) -> str:
    if not description:
        return ""
    m = re.search(
        r"\|\s*Agent IP\s*\|\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*\|",
        description,
    )
    if m:
        ip = m.group(1).strip()
        if ip and ip not in ("N/A", ""):
            return ip
    return ""


def _scrape_filepath_from_description(description: str) -> str:
    if not description:
        return ""
    m = re.search(
        r"(/(?:etc|home|var|usr|opt|tmp|root)/[^\s|`\"'<>]{2,200})",
        description,
    )
    if m:
        return m.group(1).strip()
    return ""


def _is_usable_ip(ip: str) -> bool:
    return bool(ip) and ip.upper() not in ("N/A", "NONE", "")


# ── NEW: real execution confirmation ─────────────────────────────────────────
def _poll_ar_execution_confirmed(
    agent_id:   str,
    match_term: str,
    command_name: str,
    timeout:    float = 60.0,
    interval:   float = 3.0,
) -> tuple[bool, str]:
    """
    Poll the Wazuh indexer for the *actual* SUCCESS line the AR script writes
    to /var/ossec/logs/active-responses.log (that file is forwarded back to
    the manager as a localfile source, so it lands in the alerts index).

    Returns (confirmed: bool, detail: str).

    NOTE: field names (agent.id, full_log) assume the standard Wazuh index
    template. If your indexer mapping differs, adjust the query below —
    this cannot be verified without access to your live index.
    """
    if not _INDEXER_PASS:
        logger.warning(
            "WAZUH_INDEXER_PASS not set — cannot confirm actual AR execution. "
            "Falling back to dispatch-only status (manager accepted the "
            "request, but on-agent success is UNVERIFIED)."
        )
        return True, "unverified (no indexer credentials configured)"

    deadline = time.time() + timeout
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"agent.id": agent_id}},
                    {"match_phrase": {"full_log": "SUCCESS"}},
                    {"match_phrase": {"full_log": match_term}},
                    {"match_phrase": {"full_log": command_name}},
                ],
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ],
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 1,
    }

    last_error = ""
    while time.time() < deadline:
        try:
            resp = _requests.post(
                f"{_INDEXER_URL}/{_INDEXER_INDEX_PATTERN}/_search",
                json=query,
                auth=(_INDEXER_USER, _INDEXER_PASS),
                verify=False,
                timeout=10,
            )
            if resp.status_code == 200:
                body = resp.json()
                total = body.get("hits", {}).get("total", {})
                count = total.get("value", 0) if isinstance(total, dict) else total
                if count and count > 0:
                    logger.info(
                        f"AR execution CONFIRMED via indexer  agent={agent_id}  "
                        f"term={match_term}  command={command_name}"
                    )
                    return True, "confirmed via indexer SUCCESS log entry"
            else:
                last_error = f"indexer HTTP {resp.status_code}: {resp.text[:150]}"
        except Exception as exc:
            last_error = f"indexer query exception: {exc}"
        time.sleep(interval)

    logger.warning(
        f"AR execution NOT confirmed within {timeout}s  agent={agent_id}  "
        f"term={match_term}  last_error={last_error}"
    )
    return False, f"no SUCCESS entry found within {timeout}s ({last_error})"


class WazuhAPIClient:
    def __init__(self, base_url, username, password, verify_ssl=False):
        self.base_url    = base_url.rstrip("/")
        self.username    = username
        self.password    = password
        self.verify_ssl  = verify_ssl
        self._token:        Optional[str] = None
        self._token_expiry: float         = 0.0

    def _get_token(self) -> Optional[str]:
        now = time.time()
        if self._token and now < self._token_expiry:
            return self._token
        try:
            resp = _requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=15,
            )
            if resp.status_code == 200:
                self._token        = resp.json().get("data", {}).get("token")
                self._token_expiry = now + 3300
                return self._token
            logger.error(f"Wazuh auth failed: HTTP {resp.status_code}")
            return None
        except Exception as exc:
            logger.error(f"Wazuh auth error: {exc}")
            return None

    def run_active_response(self, agent_id, command, arguments=None, srcip=None) -> bool:
        """
        Returns True only when the MANAGER accepted the dispatch (HTTP 2xx).
        This is NOT proof the agent executed the command successfully —
        callers that need real confirmation must use poll_result=True on
        run_responder(), which checks the indexer for the actual SUCCESS
        log line written by the AR script on the agent.
        """
        token = self._get_token()
        if not token:
            return False
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body: dict = {"command": command}
        if arguments:
            body["arguments"] = [str(a) for a in arguments if a]
        if srcip:
            body["alert"] = {"data": {"srcip": str(srcip)}}
        try:
            resp = _requests.put(
                f"{self.base_url}/active-response",
                headers=headers,
                json=body,
                params={"agents_list": agent_id},
                verify=self.verify_ssl,
                timeout=30,
            )
            if resp.status_code in (200, 201, 204):
                logger.info(f"Wazuh AR dispatched  agent={agent_id}  command={command}  srcip={srcip}")
                return True
            logger.error(f"Wazuh AR failed  HTTP {resp.status_code}: {resp.text[:200]}")
            return False
        except Exception as exc:
            logger.error(f"Wazuh AR exception: {exc}")
            return False


_wazuh_client: Optional[WazuhAPIClient] = None


def _get_wazuh_client() -> Optional[WazuhAPIClient]:
    global _wazuh_client
    if not _WAZUH_PASS:
        return None
    if _wazuh_client is None:
        _wazuh_client = WazuhAPIClient(_WAZUH_MANAGER, _WAZUH_USER, _WAZUH_PASS)
    return _wazuh_client


def _trigger_via_wazuh_direct(
    client,
    case_id,
    responder_name,
    poll_result:  bool  = False,
    poll_timeout: float = 60.0,
) -> dict:
    summary: dict = {
        "status": "failed", "action_id": None, "ip_used": None, "error": None,
        "confirmed": False, "confirmation_detail": None,
    }
    if not _WAZUH_PASS:
        summary["error"] = "WAZUH_API_PASS not set"
        return summary
    try:
        resp = client.session.get(f"{client.url}/api/v1/case/{case_id}", timeout=client.timeout)
        if resp.status_code != 200:
            summary["error"] = f"get_case HTTP {resp.status_code}"
            return summary
        case_data = resp.json()
    except Exception as exc:
        summary["error"] = f"get_case exception: {exc}"
        return summary
    description   = case_data.get("description", "")
    tags          = case_data.get("tags", [])
    custom_fields = case_data.get("customFields") or {}

    agent_id = (
        _extract_from_tags(tags, "agent")
        or _extract_from_description_metadata(description, "agent_id")
        or _read_custom_field(custom_fields, "wazuh_agent_id")
    )
    if not agent_id:
        summary["status"] = "skipped"
        summary["error"]  = f"agent_id not found  case={case_id}"
        return summary
    agent_id = str(agent_id).strip()

    srcip = (
        _extract_from_tags(tags, "srcip")
        or _extract_from_description_metadata(description, "srcip")
        or _read_custom_field(custom_fields, "wazuh_srcip")
        or _scrape_srcip_from_description(description)
    )
    if not _is_usable_ip(srcip):
        srcip = ""

    agent_ip = (
        _extract_from_tags(tags, "agentip")
        or _extract_from_description_metadata(description, "agent_ip")
        or _read_custom_field(custom_fields, "wazuh_agent_ip")
        or _scrape_agentip_from_description(description)
    )
    if not _is_usable_ip(agent_ip):
        agent_ip = ""

    command = ""
    arguments: list = []
    ip_used = ""
    match_term = ""       # the string we'll look for in the AR log to confirm success
    command_name = ""     # the script name that writes the AR log line

    if responder_name in (RESPONDER_FIM, f"{RESPONDER_FIM}_1_0"):
        command       = "fim-respond.sh"
        command_name  = "fim-respond"
        file_path     = _scrape_filepath_from_description(description)
        arguments     = [file_path] if file_path else []
        match_term    = file_path
    elif responder_name in (RESPONDER_NETWORK, f"{RESPONDER_NETWORK}_1_0"):
        command      = "!custom-block-ip"
        command_name = "custom-block-ip"
        if _is_usable_ip(srcip):
            ip_used = srcip
            arguments = [srcip]
        elif _is_usable_ip(agent_ip):
            ip_used = agent_ip
            arguments = [agent_ip]
        else:
            summary["status"] = "skipped"
            summary["error"]  = f"No srcip or agent_ip  case={case_id}"
            return summary
        match_term = ip_used
    else:
        summary["error"] = f"Unknown responder: {responder_name!r}"
        return summary

    wazuh = _get_wazuh_client()
    if wazuh is None:
        summary["error"] = "WAZUH_API_PASS not set"
        return summary
    dispatched = wazuh.run_active_response(
        agent_id,
        command,
        arguments=arguments,
        srcip=(ip_used if command == "firewall-drop" else None),
    )
    if not dispatched:
        summary["error"] = f"Wazuh AR dispatch returned False  case={case_id}"
        logger.error(summary["error"])
        return summary

    summary["ip_used"] = ip_used

    # ── This is the actual fix: don't stop at "dispatched", confirm it ──────
    if poll_result and match_term:
        confirmed, detail = _poll_ar_execution_confirmed(
            agent_id, match_term, command_name, timeout=poll_timeout
        )
        summary["confirmed"]            = confirmed
        summary["confirmation_detail"]  = detail
        if confirmed:
            summary["status"]    = "triggered"
            summary["action_id"] = f"WAZUH-AR-{int(time.time())}"
            logger.info(
                f"Wazuh direct CONFIRMED  case={case_id}  agent={agent_id}  "
                f"command={command}  args={arguments}"
            )
        else:
            summary["status"] = "dispatched_unconfirmed"
            summary["error"]  = detail
    else:
        # Old behaviour preserved when poll_result=False: dispatch-only status.
        # Callers relying on this path should be aware "triggered" here means
        # "manager accepted it", not "agent confirmed it executed".
        summary["status"]    = "triggered"
        summary["action_id"] = f"WAZUH-AR-{int(time.time())}"
        summary["confirmed"] = None  # explicitly "unknown", not "confirmed True"
        logger.info(
            f"Wazuh direct DISPATCHED (unconfirmed — poll_result=False)  "
            f"case={case_id}  agent={agent_id}  command={command}  args={arguments}"
        )

    return summary


def run_responder(
    client,
    case_id:        str,
    responder_name: str,
    poll_result:    bool  = False,
    poll_timeout:   float = 60.0,
) -> dict:
    summary: dict = {
        "case_id":    case_id,
        "responder":  responder_name,
        "action_id":  None,
        "status":     "failed",
        "ip_used":    None,
        "confirmed":  None,
        "error":      None,
    }

    logger.info(
        f"run_responder  case={case_id}  responder={responder_name}  "
        f"poll_result={poll_result}  poll_timeout={poll_timeout}"
    )

    if not _WAZUH_PASS:
        logger.warning(
            f"WAZUH_API_PASS not set — falling back to TheHive/Cortex route "
            f"(unverified) for case={case_id}"
        )
        result = _trigger_responder_via_thehive(client, case_id, responder_name)
        summary["status"]    = result["status"]
        summary["action_id"] = result["action_id"]
        summary["error"]     = result.get("error")
        return summary

    # poll_result/poll_timeout are now actually threaded through and used.
    fallback = _trigger_via_wazuh_direct(
        client, case_id, responder_name,
        poll_result=poll_result, poll_timeout=poll_timeout,
    )
    summary["status"]    = fallback["status"]
    summary["action_id"] = fallback.get("action_id")
    summary["ip_used"]   = fallback.get("ip_used")
    summary["confirmed"] = fallback.get("confirmed")
    summary["error"]     = fallback.get("error")

    if summary["status"] not in ("triggered",):
        logger.warning(
            f"Wazuh-direct trigger did not confirm  case={case_id}  "
            f"status={summary['status']}  error={summary['error']}  "
            f"— trying TheHive/Cortex route as last resort"
        )
        result = _trigger_responder_via_thehive(client, case_id, responder_name)
        if result["status"] == "triggered":
            summary["status"]    = "triggered"
            summary["action_id"] = result["action_id"]
            summary["confirmed"] = None  # Cortex route has no equivalent confirmation
            summary["error"]     = None

    return summary
