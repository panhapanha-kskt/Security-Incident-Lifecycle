#!/usr/bin/env python3
import requests
import json
import re
import urllib3
from cortexutils.responder import Responder

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhFIM(Responder):

    def __init__(self):
        super().__init__()
        self.wazuh_manager  = self.get_param("config.wazuh_manager", "https://192.168.200.129:55000")
        self.wazuh_user     = self.get_param("config.wazuh_user", "wazuh-wui")
        self.wazuh_password = self.get_param("config.wazuh_password", None)
        self.thehive_url    = self.get_param("config.thehive_url", "https://172.24.80.95:8443")
        self.thehive_key    = self.get_param("config.thehive_key", None)

    def _extract_from_tags(self, tags, prefix):
        for tag in (tags or []):
            if isinstance(tag, str) and tag.startswith(f"{prefix}:"):
                return tag.split(":", 1)[1]
        return ""

    def _extract_from_wajson(self, description, key):
        if not description:
            return ""
        m = re.search(r'<!--WAZUH_METADATA\s+(\{.*?\})\s*-->', description)
        if m:
            try:
                return str(json.loads(m.group(1)).get(key, ""))
            except Exception:
                pass
        return ""

    def _fetch_case_from_thehive(self, case_id):
        headers = {}
        if self.thehive_key:
            headers["Authorization"] = f"Bearer {self.thehive_key}"
        for cid in [case_id, f"~{case_id.lstrip('~')}"]:
            try:
                r = requests.get(
                    f"{self.thehive_url}/api/v1/case/{cid}",
                    headers=headers, verify=False, timeout=15,
                )
                if r.status_code == 200:
                    return r.json()
            except Exception:
                pass
        return {}

    def _normalize_custom_fields(self, raw):
        """
        TheHive 5 returns customFields in two possible shapes:
          - dict:  {"wazuh_rule_id": {"string": "550"}, ...}   ← TheHive 4 / empty case
          - list:  [{"name": "wazuh_rule_id", "value": "550", "type": "string"}, ...]

        Normalise both into a plain {key: value} dict so the rest of
        the code can call .get() safely.
        """
        if isinstance(raw, list):
            result = {}
            for item in raw:
                if not isinstance(item, dict) or "name" not in item:
                    continue
                # prefer "value", fall back to type-keyed sub-dict
                val = item.get("value")
                if val is None:
                    for type_key in ("string", "integer", "boolean", "float", "date"):
                        if type_key in item:
                            val = item[type_key]
                            break
                result[item["name"]] = val
            return result

        if isinstance(raw, dict):
            # Values may be bare scalars OR {"string": "550"} sub-dicts
            result = {}
            for k, v in raw.items():
                if isinstance(v, dict):
                    for type_key in ("string", "integer", "boolean", "float", "date", "value"):
                        if type_key in v:
                            result[k] = v[type_key]
                            break
                    else:
                        result[k] = None
                else:
                    result[k] = v
            return result

        return {}  # unexpected type → safe empty dict

    def _get_token(self):
        url = f"{self.wazuh_manager}/security/user/authenticate"
        r = requests.get(url, auth=(self.wazuh_user, self.wazuh_password),
                         verify=False, timeout=15)
        r.raise_for_status()
        return r.json()["data"]["token"]

    def _run_ar(self, token, agent_id, rule_id, file_path):
        url = f"{self.wazuh_manager}/active-response"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "command": "fim-respond.sh",
            "arguments": [],
            "alert": {
                "rule": {"id": rule_id, "description": "FIM: critical file modified"},
                "syscheck": {"path": file_path}
            }
        }
        r = requests.put(url, headers=headers, params={"agents_list": agent_id},
                         json=payload, verify=False, timeout=15)
        r.raise_for_status()
        return r.json()

    def run(self):
        raw = self.get_data()

        if isinstance(raw, str):
            case_id = raw
            case    = self._fetch_case_from_thehive(case_id)
        elif isinstance(raw, dict):
            case    = raw
            case_id = raw.get("_id", "unknown")
        else:
            self.error(f"Unexpected input type: {type(raw)} — {raw!r}")
            return

        description = case.get("description", "")
        tags        = case.get("tags", [])

        # ── FIX: normalise customFields regardless of shape returned by TheHive ──
        custom = self._normalize_custom_fields(
            case.get("customFields") or case.get("customFieldValues") or {}
        )
        # ─────────────────────────────────────────────────────────────────────────

        # custom is now always a plain {key: bare_value} dict — safe to .get()
        rule_id = str(custom.get("wazuh_rule_id") or "").strip()
        if not rule_id:
            rule_id = self._extract_from_tags(tags, "rule")
        if not rule_id:
            rule_id = self._extract_from_wajson(description, "rule_id")

        agent_id = str(custom.get("wazuh_agent_id") or "").strip()
        if not agent_id:
            agent_id = self._extract_from_tags(tags, "agent")
        if not agent_id:
            agent_id = self._extract_from_wajson(description, "agent_id")

        file_path = ""
        for line in description.splitlines():
            if "File '" in line and "modified" in line:
                try:
                    file_path = line.split("'")[1]
                except IndexError:
                    pass
                break

        if not rule_id:
            self.error(f"Could not extract rule_id  case={case_id}  tags={tags}")
            return
        if not agent_id:
            self.error(f"Could not extract agent_id  case={case_id}  tags={tags}")
            return
        if not self.wazuh_password:
            self.error("wazuh_password not configured")
            return

        try:
            token  = self._get_token()
            result = self._run_ar(token, agent_id, rule_id, file_path)
            self.report({
                "message":   "fim-respond AR executed successfully",
                "case_id":   case_id,
                "rule_id":   rule_id,
                "agent_id":  agent_id,
                "file_path": file_path,
                "wazuh_api_response": result,
            })
        except requests.exceptions.HTTPError as e:
            self.error(f"Wazuh API HTTP error: {e.response.status_code} — {e.response.text}")
        except requests.exceptions.ConnectionError as e:
            self.error(f"Cannot reach Wazuh API at {self.wazuh_manager}: {str(e)}")
        except Exception as e:
            self.error(f"Unexpected error: {str(e)}")

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='WazuhFIM: FIM Response Executed')]


if __name__ == "__main__":
    WazuhFIM().run()
