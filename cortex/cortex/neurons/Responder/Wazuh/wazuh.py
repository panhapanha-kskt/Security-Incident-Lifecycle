#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import ipaddress
import re
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Wazuh(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.wazuh_manager  = self.get_param('config.wazuh_manager',  None, 'Wazuh manager URL missing!')
        self.wazuh_user     = self.get_param('config.wazuh_user',     None, 'Username missing!')
        self.wazuh_password = self.get_param('config.wazuh_password', None, 'Password missing!')
        self.thehive_url    = self.get_param('config.thehive_url', None) or 'https://172.24.80.95:8443'
        self.thehive_key    = self.get_param('config.thehive_key', None) or 'SSZNE7qtAl6iBJNhls4Pvvt/iDuu7e+Y'

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

    def _tag(self, tags, prefix):
        for tag in (tags or []):
            if isinstance(tag, str) and tag.startswith(f"{prefix}:"):
                return tag.split(":", 1)[1]
        return ""

    def _wajson(self, description, key):
        if not description:
            return ""
        m = re.search(r'<!--WAZUH_METADATA\s+(\{.*?\})\s*-->', description)
        if m:
            try:
                return str(json.loads(m.group(1)).get(key, ""))
            except Exception:
                pass
        return ""

    def _get_jwt_token(self):
        resp = requests.get(
            f"{self.wazuh_manager}/security/user/authenticate",
            auth=(self.wazuh_user, self.wazuh_password),
            verify=False, timeout=10,
        )
        if resp.status_code != 200:
            self.error({'message': f'Wazuh auth failed: HTTP {resp.status_code}'})
        token = resp.json().get('data', {}).get('token')
        if not token:
            self.error({'message': 'Wazuh auth: no token in response'})
        return token

    def run(self):
        Responder.run(self)

        raw = self.get_data()

        # ── Case is passed as a string ID or full dict ──
        if isinstance(raw, str):
            case_id = raw
            case    = self._fetch_case_from_thehive(case_id)
        elif isinstance(raw, dict):
            case    = raw
            case_id = raw.get('_id', 'unknown')
        else:
            self.error({'message': f'Unexpected input type: {type(raw)}'})
            return

        description = case.get('description', '')
        tags        = case.get('tags', [])

        # ── Agent ID ──
        agent_id = (
            self._tag(tags, 'agent')
            or self._wajson(description, 'agent_id')
        )
        if not agent_id:
            self.error({'message': f'Agent ID missing  case={case_id}  tags={tags}'})
            return

        # ── IP resolution: srcip first, then agent IP fallback ──
        # 1. Try srcip from description table
        observable = None
        m = re.search(
            r'\|\s*Source IP\s*\|\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*\|',
            description,
        )
        if m:
            candidate = m.group(1).strip()
            if candidate and candidate.upper() not in ('N/A', 'NONE', ''):
                observable = candidate

        # 2. Try srcip tag / WAJSON
        if not observable:
            candidate = self._tag(tags, 'srcip') or self._wajson(description, 'srcip')
            if candidate and candidate.upper() not in ('N/A', 'NONE', ''):
                observable = candidate

        # 3. Fallback to agent IP (for FIM rules with no srcip)
        if not observable:
            candidate = (
                self._tag(tags, 'agentip')
                or self._wajson(description, 'agent_ip')
            )
            # also try description table
            if not candidate:
                m2 = re.search(
                    r'\|\s*Agent IP\s*\|\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*\|',
                    description,
                )
                if m2:
                    candidate = m2.group(1).strip()
            if candidate and candidate.upper() not in ('N/A', 'NONE', ''):
                observable = candidate

        if not observable:
            self.error({'message': f'No valid IP (srcip or agentip) found  case={case_id}  tags={tags}'})
            return

        try:
            ipaddress.ip_address(observable)
        except ValueError:
            self.error({'message': f'Not a valid IP address: {observable}'})
            return

        token   = self._get_jwt_token()
        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        payload = {"command": "firewall-drop", "arguments": [observable]}
        url     = f"{self.wazuh_manager}/active-response?agents_list={agent_id}"

        r = requests.put(url, headers=headers, json=payload, verify=False, timeout=10)
        if r.status_code == 200:
            self.report({
                'message':  f'Blocked IP {observable} on agent {agent_id}',
                'case_id':  case_id,
                'agent_id': agent_id,
                'ip':       observable,
            })
        else:
            self.error({'message': f'Wazuh API returned {r.status_code}: {r.text[:300]}'})

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='Wazuh: Blocked IP')]

if __name__ == '__main__':
    Wazuh().run()
