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
    def run_active_response(self, agent_id, command, arguments=None) -> bool:
        token = self._get_token()
        if not token:
            return False
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body: dict = {"command": command}
        if arguments:
            body["arguments"] = [str(a) for a in arguments if a]
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
                logger.info(f"Wazuh AR dispatched  agent={agent_id}  command={command}")
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
def _trigger_via_wazuh_direct(client, case_id, responder_name) -> dict:
    summary: dict = {"status": "failed", "action_id": None, "ip_used": None, "error": None}
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
    if responder_name in (RESPONDER_FIM, f"{RESPONDER_FIM}_1_0"):
        command   = "fim-respond.sh"
        file_path = _scrape_filepath_from_description(description)
        arguments = [file_path] if file_path else []
    elif responder_name in (RESPONDER_NETWORK, f"{RESPONDER_NETWORK}_1_0"):
        command = "firewall-drop"
        if _is_usable_ip(srcip):
            ip_used = srcip
            arguments = [srcip]
        elif _is_usable_ip(agent_ip):
            ip_used = agent_ip
            arguments = [agent_ip]
            logger.warning(f"Wazuh direct: agent_ip fallback  case={case_id}  agent_ip={agent_ip}")
        else:
            summary["status"] = "skipped"
            summary["error"]  = f"No srcip or agent_ip  case={case_id}"
            return summary
    else:
        summary["error"] = f"Unknown responder: {responder_name!r}"
        return summary
    wazuh = _get_wazuh_client()
    if wazuh is None:
        summary["error"] = "WAZUH_API_PASS not set"
        return summary
    success = wazuh.run_active_response(agent_id, command, arguments)
    if success:
        summary["status"]    = "triggered"
        summary["action_id"] = f"WAZUH-AR-{int(time.time())}"
        summary["ip_used"]   = ip_used
        logger.info(f"Wazuh direct triggered  case={case_id}  agent={agent_id}  command={command}  args={arguments}")
    else:
        summary["error"] = f"Wazuh AR returned False  case={case_id}"
        logger.error(summary["error"])
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
        "error":      None,
    }
    logger.info(f"run_responder  case={case_id}  responder={responder_name}")
    result = _trigger_responder_cortex_direct(case_id, responder_name)
    if result["status"] == "triggered":
        summary["status"]    = "triggered"
        summary["action_id"] = result["action_id"]
        return summary
    logger.warning(
        f"Cortex direct failed  case={case_id}  "
        f"error={result.get('error', '')}  — falling back to Wazuh API"
    )
    if not _WAZUH_PASS:
        summary["error"] = f"Cortex direct failed and WAZUH_API_PASS not set. Error: {result.get('error', '')}"
        logger.error(summary["error"])
        return summary
    fallback = _trigger_via_wazuh_direct(client, case_id, responder_name)
    summary["status"]    = fallback["status"]
    summary["action_id"] = fallback.get("action_id")
    summary["ip_used"]   = fallback.get("ip_used")
    summary["error"]     = fallback.get("error")
    return summary
