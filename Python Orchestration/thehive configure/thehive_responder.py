#!/usr/bin/env python3
from __future__ import annotations
import json
import logging
import os
import re
import time
from typing import Optional
logger = logging.getLogger(__name__)
_WAZUH_MANAGER: str = os.environ.get("WAZUH_API_URL",  "https://192.168.200.129:55000")
_WAZUH_USER:    str = os.environ.get("WAZUH_API_USER", "wazuh-wui")
_WAZUH_PASS:    str = os.environ.get("WAZUH_API_PASS", "")


class WazuhAPIClient:
    def __init__(
        self,
        base_url:   str,
        username:   str,
        password:   str,
        verify_ssl: bool = False,
    ) -> None:
        self.base_url   = base_url.rstrip("/")
        self.username   = username
        self.password   = password
        self.verify_ssl = verify_ssl
        self._token:        Optional[str] = None
        self._token_expiry: float         = 0.0

    def _get_token(self) -> Optional[str]:
        now = time.time()
        if self._token and now < self._token_expiry:
            return self._token

        import requests
        url = f"{self.base_url}/security/user/authenticate"
        try:
            resp = requests.post(
                url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._token        = data.get("data", {}).get("token")
                self._token_expiry = now + 3300   # 55-min cache (TTL=1h)
                logger.info("Wazuh API: authenticated successfully")
                return self._token
            logger.error(
                f"Wazuh API auth failed: HTTP {resp.status_code} — {resp.text[:200]}"
            )
            return None
        except Exception as exc:
            logger.error(f"Wazuh API connection error during auth: {exc}")
            return None

    def _request(
        self,
        method:    str,
        endpoint:  str,
        json_data: Optional[dict] = None,
        params:    Optional[dict] = None,
    ) -> Optional[dict]:
        token = self._get_token()
        if not token:
            return None

        import requests
        url     = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }
        logger.debug(
            f"Wazuh API {method} {endpoint}  "
            f"params={params}  body={json.dumps(json_data or {})}"
        )
        try:
            resp = requests.request(
                method, url,
                json=json_data,
                params=params,
                headers=headers,
                verify=self.verify_ssl,
                timeout=30,
            )
            if resp.status_code in (200, 201, 204):
                return resp.json() if resp.text else {"success": True}
            logger.error(
                f"Wazuh API error {resp.status_code} [{method} {endpoint}]: "
                f"{resp.text[:300]}"
            )
            return None
        except Exception as exc:
            logger.error(f"Wazuh API request error [{method} {endpoint}]: {exc}")
            return None

    def run_active_response(
        self,
        agent_id:  str,
        command:   str,
        arguments: Optional[list] = None,
    ) -> bool:
        params: dict = {"agents_list": agent_id}
        body:   dict = {"command": command}
        if arguments:
            body["arguments"] = [str(a) for a in arguments if a]

        logger.debug(
            f"Wazuh AR  agent={agent_id}  command={command}  "
            f"arguments={arguments}  query={params}  body={body}"
        )

        data = self._request("PUT", "/active-response", json_data=body, params=params)
        if data is not None:
            affected = (
                data.get("data", {}).get("affected_items", [agent_id])
                if isinstance(data, dict) else [agent_id]
            )
            logger.info(
                f"Wazuh AR dispatched  agent={agent_id}  "
                f"command={command}  affected={affected}"
            )
            return True
        return False
_wazuh_client: Optional[WazuhAPIClient] = None
def _get_wazuh_client() -> Optional[WazuhAPIClient]:
    global _wazuh_client
    if not _WAZUH_PASS:
        return None
    if _wazuh_client is None:
        _wazuh_client = WazuhAPIClient(
            base_url   = _WAZUH_MANAGER,
            username   = _WAZUH_USER,
            password   = _WAZUH_PASS,
            verify_ssl = False,
        )
    return _wazuh_client
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
            metadata = json.loads(match.group(1))
            return str(metadata.get(key, ""))
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
            logger.info(f"Responder: srcip scraped from description fallback: {ip}")
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
            logger.info(f"Responder: agent_ip scraped from description fallback: {ip}")
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
        path = m.group(1).strip()
        logger.info(f"Responder: file path scraped from description fallback: {path}")
        return path
    return ""
def _is_usable_ip(ip: str) -> bool:
    return bool(ip) and ip.upper() not in ("N/A", "NONE", "")
def run_responder(
    client,
    case_id:        str,
    responder_name: str,
    poll_result:    bool  = False,
    poll_timeout:   float = 60.0,
) -> dict:
    """
    Public entry point called by thehive-intercept.py.

    Metadata extraction priority for ALL IP fields:
      1. Tags              (agent:006, rule:5710, srcip:10.0.0.1, agentip:192.168.200.128)
      2. Description WAJSON (<!--WAZUH_METADATA {...} -->)
      3. customFields      (TheHive 4 backward compat)
      4. Markdown table scrape (last resort)

    Wazuh_1_0 IP resolution (FIX-7):
      Priority 1 — srcip  (attacker's IP, the normal case)
      Priority 2 — agent_ip (agent's own IP, used for local-execution
                   threats like msfconsole running on the agent itself,
                   i.e. rule 100101 with no inbound srcip)
      Priority 3 — skip (no usable IP found at all)

    Returns:
      {
        status:    "triggered" | "skipped" | "failed",
        action_id: str | None,
        ip_used:   str | None,   # which IP was sent to Wazuh (FIX-7)
        error:     str | None,
      }
    """
    summary: dict = {
        "case_id":    case_id,
        "responder":  responder_name,
        "action_id":  None,
        "status":     "failed",
        "ip_used":    None,        
        "job_result": None,
        "error":      None,
    }
    if not _WAZUH_PASS:
        summary["error"] = (
            "WAZUH_API_PASS environment variable is not set. "
            "Export it before starting thehive-intercept.py."
        )
        logger.error(summary["error"])
        return summary
    url = f"{client.url}/api/v1/case/{case_id}"
    try:
        resp = client.session.get(url, timeout=client.timeout)
        if resp.status_code != 200:
            summary["error"] = (
                f"TheHive get_case failed: HTTP {resp.status_code} — "
                f"{resp.text[:120]}"
            )
            logger.error(summary["error"])
            return summary
        case_data = resp.json()
    except Exception as exc:
        summary["error"] = f"Error fetching case from TheHive: {exc}"
        logger.error(summary["error"])
        return summary
    description   = case_data.get("description", "")
    tags          = case_data.get("tags", [])
    custom_fields = case_data.get("customFields") or {}
    agent_id = (
        _extract_from_tags(tags, "agent")
        or _extract_from_description_metadata(description, "agent_id")
        or _read_custom_field(custom_fields, "wazuh_agent_id")
    )
    rule_id = (
        _extract_from_tags(tags, "rule")
        or _extract_from_description_metadata(description, "rule_id")
        or _read_custom_field(custom_fields, "wazuh_rule_id")
    )
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

    agent_id = str(agent_id).strip() if agent_id else ""
    rule_id  = str(rule_id).strip()  if rule_id  else ""

    logger.info(
        f"Responder metadata  case={case_id}  "
        f"agent={agent_id!r}  rule={rule_id!r}  "
        f"srcip={srcip!r}  agent_ip={agent_ip!r}  "
        f"tags={tags}"
    )
    if not agent_id:
        summary["error"] = (
            f"agent_id could not be extracted from case {case_id}. "
            f"Checked tags, WAJSON, customFields, and Markdown. "
            f"Tags present: {tags}"
        )
        logger.error(summary["error"])
        return summary
    command:   Optional[str] = None
    arguments: list          = []
    ip_used:   str           = ""

    if responder_name == "WazuhFIM_1_0":
        file_path = _scrape_filepath_from_description(description)
        command   = "fim-respond.sh"
        arguments = [file_path] if file_path else []
        logger.info(
            f"WazuhFIM_1_0  command={command}  file_path={file_path!r}"
        )

    elif responder_name == "Wazuh_1_0":
        command = "firewall-drop"
        if _is_usable_ip(srcip):
            ip_used   = srcip
            arguments = [srcip]
            logger.info(
                f"Wazuh_1_0  command={command}  "
                f"ip_source=srcip  ip={srcip}"
            )
        elif _is_usable_ip(agent_ip):
            ip_used   = agent_ip
            arguments = [agent_ip]
            logger.warning(
                f"Wazuh_1_0 using agent_ip as srcip fallback  "
                f"case={case_id}  agent={agent_id}  "
                f"agent_ip={agent_ip}  rule={rule_id!r}  "
                f"(no srcip — local execution threat assumed)"
            )
        else:
            summary["status"] = "skipped"
            summary["error"]  = (
                f"Wazuh_1_0 skipped for case {case_id}: "
                f"no srcip and no agent_ip available  rule={rule_id!r}"
            )
            logger.warning(summary["error"])
            return summary

    else:
        summary["error"] = (
            f"Unknown responder_name: {responder_name!r}. "
            f"Expected 'Wazuh_1_0' or 'WazuhFIM_1_0'."
        )
        logger.error(summary["error"])
        return summary
    wazuh = _get_wazuh_client()
    if wazuh is None:
        summary["error"] = "WAZUH_API_PASS not set — cannot create WazuhAPIClient"
        logger.error(summary["error"])
        return summary
    success = wazuh.run_active_response(agent_id, command, arguments)
    if success:
        summary["status"]    = "triggered"
        summary["action_id"] = f"WAZUH-AR-{int(time.time())}"
        summary["ip_used"]   = ip_used   # FIX-7
        logger.info(
            f"{responder_name} triggered  case={case_id}  "
            f"agent={agent_id}  command={command}  args={arguments}  "
            f"ip_used={ip_used!r}"
        )
    else:
        summary["error"] = (
            f"Wazuh API run_active_response returned False  "
            f"case={case_id}  agent={agent_id}  command={command}  "
            f"args={arguments}"
        )
        logger.error(summary["error"])

    return summary
