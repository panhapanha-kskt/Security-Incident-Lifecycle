# ASIL Bug Fix Report — 2026-06-25
**Project:** ASIL (Automated Security Incident Lifecycle)    
---

## Files Updated

| File | Location | What Changed |
|------|----------|--------------|
| `thehive_responder.py` | `thehive-configure/` | FIX-9, FIX-10 |
| `thehive_observable.py` | `thehive-configure/` | Added `_trigger_responders`, `_RESPONDER_RULES` |
| `wazuh.py` | `cortex/neurons/responders/Wazuh/` | FIX: `get_data()` string input + `_fetch_case_from_thehive()` |
| `wazuh_fim.py` | `cortex/neurons/responders/WazuhFIM/` | FIX: `get_data()` string input + `_fetch_case_from_thehive()` |
| `wazuh.json` | `cortex/neurons/responders/Wazuh/` | Added `thehive_url`, `thehive_key` config fields |
| `WazuhFIM.json` | `cortex/neurons/responders/WazuhFIM/` | Added `thehive_url`, `thehive_key` config fields |
| `thehive-intercept.service` | `/etc/systemd/system/` | Added `CORTEX_KEY` environment variable |

---

## Bug 1 — Responder Not Firing Automatically
**File:** `thehive_observable.py`  
**Symptom:** Cortex Jobs History showed only analyzers (MISP), never responders, even though `_trigger_responders` was added to the code.

### Root Cause
The responder trigger condition was:
```python
if summary["added"] > 0:
    resp_result = self._trigger_responders(case_id, alert)
```
When the same IP triggered multiple alerts, the second case posted its observable and got HTTP 207 (duplicate) back from TheHive. This set `result = "duplicate"` → `added` stayed 0 → the responder block was never reached. The IP was already seen before, but the attack was still ongoing and still needed blocking.

### Fix
```python
# Added module-level constant
_RESPONDER_RULES: frozenset[str] = _FIM_RULES | _BRUTE_FORCE_RULES

# Changed condition from added>0 to rule_id check
if rule_id in _RESPONDER_RULES:
    resp_result = self._trigger_responders(case_id, alert)
```
The responder now fires based on **rule_id alone**, unconditionally — regardless of whether observables were new or duplicates. Also added the same check inside the early-return path (`if not observables`) so the responder fires even when zero observables are extracted.

---

## Bug 2 — Wrong Directory (Service Loading Old File)
**File:** `thehive_observable.py`  
**Symptom:** Updated code deployed but Cortex still showed old behavior.

### Root Cause
The systemd service runs from:
```
/home/wazuh-user/Wazuh-Part/thehive-configure/
```
But edits were being made to:
```
/home/wazuh-server/thehive-configure/   ← wrong directory
```
Two different directories — the service was loading the old `thehive_observable.py`.

### Fix
```bash
cp /home/wazuh-server/thehive-configure/thehive_observable.py \
   /home/wazuh-user/Wazuh-Part/thehive-configure/thehive_observable.py

rm -rf /home/wazuh-user/Wazuh-Part/thehive-configure/__pycache__
systemctl restart thehive-intercept
```

---

## Bug 3 — TheHive Connector Returns 404 for All Responders
**File:** `thehive_responder.py`  
**Symptom:** All calls to `POST /api/connector/cortex/action` returned HTTP 404 with `"Responder Wazuh_1_0_1_0 not found"`, even though the responders existed in Cortex.

### Root Cause
TheHive's internal Cortex connector cache was **empty**. The endpoint `/api/connector/cortex/action` requires TheHive to resolve the responder name through its internal connector cache — but `GET /api/connector/cortex/responder/case` returned empty, meaning TheHive had no knowledge of any Cortex responders.

Confirmed via:
```bash
curl -sk "https://172.24.80.95:8443/api/connector/cortex/responder/case" \
  -H "Authorization: Bearer <KEY>"
# → empty response
```

### Fix (FIX-10)
Bypass TheHive's connector entirely. Call **Cortex REST API directly** using the responder UUID:

```
POST /api/responder/<uuid>/run
Authorization: Bearer <CORTEX_KEY>
Body: { "data": "<case_id>", "dataType": "thehive:case", "tlp": 2 }
```

Responder UUIDs obtained from:
```bash
curl -sk "https://172.24.80.95:9443/api/responder?range=all" \
  -H "Authorization: Bearer <CORTEX_KEY>"
```

Confirmed UUIDs:
| Responder | UUID |
|-----------|------|
| `Wazuh_1_0_1_0` | `c45653768b9ab1e95aee1969a04a4c5d` |
| `Wazuh_1_0` | `9005ef9766e6885f2d29ed57372b4dbe` |
| `WazuhFIM_1_0_1_0` | `a3ea8a5fbd48194607e9f0cd502b5295` |

Added `CORTEX_KEY` to systemd service:
```ini
Environment="CORTEX_KEY=zE58rzZN9Bxc+yU+I037r2XqmqRrGfAq"
```

---

## Bug 4 — Cortex Responder Crashes: `'str' object has no attribute 'get'`
**Files:** `wazuh.py`, `wazuh_fim.py`  
**Symptom:** All responder jobs showed **Failure** in Cortex Jobs History with error:
```
AttributeError: 'str' object has no attribute 'get'
  description = case.get("description", "")
```

### Root Cause
When triggered via `POST /api/responder/<uuid>/run` with `dataType=thehive:case`, Cortex passes the raw input directly to `self.get_data()`. The input is the **case ID string** (e.g. `"~737386560"`), not a case dict.

The old code assumed `get_data()` always returns a dict:
```python
case        = self.get_data()         # returns "~737386560" ← string!
description = case.get("description") # crash: str has no .get()
```

### Fix
Detect the input type and fetch the full case from TheHive when a string is received:

```python
def _fetch_case_from_thehive(self, case_id):
    headers = {"Authorization": f"Bearer {self.thehive_key}"}
    r = requests.get(
        f"{self.thehive_url}/api/v1/case/{case_id}",
        headers=headers, verify=False, timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    return {}

def run(self):
    raw = self.get_data()
    if isinstance(raw, str):
        case_id = raw
        case    = self._fetch_case_from_thehive(case_id)   # fetch full case
    elif isinstance(raw, dict):
        case    = raw
        case_id = raw.get("_id", "unknown")
```

`thehive_url` and `thehive_key` added to both `wazuh.json` and `WazuhFIM.json` config so they appear in Cortex UI and get passed to the responder at runtime.

---

## Bug 5 — `data=json.dumps()` vs `json=` kwarg
**File:** `thehive_responder.py`  
**Symptom:** Responder POST calls used `json=payload` kwarg but the confirmed working sample used `data=json.dumps(payload)`.

### Fix (FIX-9)
```python
# Before
resp = client.session.post(url, json=payload, timeout=client.timeout)

# After — matches working sample exactly
resp = client.session.post(url, data=json.dumps(payload), timeout=client.timeout)
```

Also swapped variant order so suffixed name (`Wazuh_1_0_1_0`) is tried first since that's the confirmed working name shown in Cortex Jobs History.

---

## Final Working Flow

```
Wazuh Alert
    ↓
thehive-intercept.py
    ↓
TheHive case created
    ↓
attach_observables()  [thehive_observable.py]
    ↓
ObservableExtractor.extract()
    ↓
_post_observable()  →  POST /api/v1/case/{id}/observable
    ↓
_trigger_analyzers()  →  POST /api/v1/connector/cortex/job
    ↓                      Cortex runs MISP/VirusTotal/Shodan ✓
    ↓
_trigger_responders()  [if rule_id in _RESPONDER_RULES]
    ↓
run_responder()  [thehive_responder.py]
    ↓
POST /api/responder/<uuid>/run  →  Cortex direct
    ↓
wazuh.py / wazuh_fim.py
    ↓
_fetch_case_from_thehive(case_id)  →  GET /api/v1/case/{id}
    ↓
Wazuh Active Response: firewall-drop / fim-respond ✓
```

---

## Deployment Commands Reference

```bash
# Clear pycache and restart service
rm -rf /home/wazuh-user/Wazuh-Part/thehive-configure/__pycache__
systemctl daemon-reload
systemctl restart thehive-intercept

# Copy neurons into Cortex container
docker cp cortex/neurons/responders/Wazuh/wazuh.py cortex:/opt/cortexneurons/responders/Wazuh/wazuh.py
docker cp cortex/neurons/responders/WazuhFIM/wazuh_fim.py cortex:/opt/cortexneurons/responders/WazuhFIM/wazuh_fim.py
docker cp cortex/neurons/responders/Wazuh/wazuh.json cortex:/opt/cortexneurons/responders/Wazuh/wazuh.json
docker cp cortex/neurons/responders/WazuhFIM/WazuhFIM.json cortex:/opt/cortexneurons/responders/WazuhFIM/WazuhFIM.json
docker restart cortex

# Watch live logs
journalctl -u thehive-intercept -f | grep -i "cortex direct\|triggered\|responder\|error"
```
