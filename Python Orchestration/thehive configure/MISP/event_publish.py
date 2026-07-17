#!/usr/bin/env python3
import json
import argparse
import sys
import re
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone

MISP_URL         = "https://172.24.80.95:9001"
API_KEY          = "your-misp-api"
VERIFY_SSL       = False
DISTRIBUTION_ALL = 3  

TLP_DISTRIBUTION = {
    "tlp:white": 3,
    "tlp:clear": 3,
    "tlp:green": 2, # default 2
    "tlp:amber": 1, # default 1
    "tlp:amber+strict": 0,
    "tlp:red":   0,
}
DEFAULT_DISTRIBUTION = 3 

ENRICHMENT = {
    "100101": {
        "attributes": [
            {
                "category": "Internal reference",
                "type":     "text",
                "value":    "Wazuh Rule ID: 100101",
                "comment":  "REVERSE SHELL TOOL — msfconsole/meterpreter/nc -e detected",
                "to_ids":   False,
            },
            {
                "category": "Network activity",
                "type":     "ip-src",
                "value":    "192.168.200.128",
                "comment":  "Agent-Kali (ID: 006) — host where reverse shell tool was detected",
                "to_ids":   True,
            },
            {
                "category": "Artifacts dropped",
                "type":     "filepath",
                "value":    "/tmp/msfconsole",
                "comment":  "Reverse shell binary dropped in /tmp (realtime FIM detection)",
                "to_ids":   True,
            },
            {
                "category": "Artifacts dropped",
                "type":     "filename",
                "value":    "msfconsole",
                "comment":  "Metasploit/reverse shell payload filename",
                "to_ids":   True,
            },
            {
                "category": "Payload delivery",
                "type":     "text",
                "value":    "Reverse shell tool (msfconsole/meterpreter/nc -e) added to /tmp. "
                            "Detected via Wazuh FIM realtime monitoring. "
                            "Alert timestamp: 2026-06-29T02:02:01.507+0000",
                "comment":  "Wazuh FIM syscheck detection summary",
                "to_ids":   False,
            },
            {
                "category": "Attribution",
                "type":     "text",
                "value":    "MITRE ATT&CK: T1059 (Command and Scripting Interpreter), "
                            "T1071 (Application Layer Protocol), "
                            "T1572 (Protocol Tunneling), TA0011 (Command and Control)",
                "comment":  "Technique mapping from Wazuh rule metadata",
                "to_ids":   False,
            },
        ],
        "galaxy_tags": [
            'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"',
            'misp-galaxy:mitre-attack-pattern="Application Layer Protocol - T1071"',
            'misp-galaxy:mitre-attack-pattern="Protocol Tunneling - T1572"',
        ],
        "taxonomy_tags": [
            'tlp:amber',
            'admiralty-scale:source-reliability="b"',
            'admiralty-scale:information-credibility="2"',
            'circl:incident-classification="system-compromise"',
            'workflow:state="incomplete"',
        ],
    },
    "110012": {
        "attributes": [
            {
                "category": "Internal reference",
                "type":     "text",
                "value":    "Wazuh Rule ID: 110012",
                "comment":  "Tetragon: shell execution detected — possible container escape or lateral movement",
                "to_ids":   False,
            },
            {
                "category": "Network activity",
                "type":     "ip-src",
                "value":    "192.168.200.128",
                "comment":  "Agent-Kali (ID: 006) — host where shell execution was detected",
                "to_ids":   True,
            },
            {
                "category": "Artifacts dropped",
                "type":     "filepath",
                "value":    "/var/log/tetragon/tetragon.log",
                "comment":  "Tetragon eBPF log source that generated this alert",
                "to_ids":   False,
            },
            {
                "category": "Artifacts dropped",
                "type":     "filename",
                "value":    "tetragon-events",
                "comment":  "Tetragon process that reported the shell exec event",
                "to_ids":   False,
            },
            {
                "category": "External analysis",
                "type":     "text",
                "value":    "Tetragon eBPF sensor detected shell execution (process_exec event). "
                            "Suspected container escape or lateral movement. "
                            "Alert timestamp: 2026-06-29T02:02:01.688+0000",
                "comment":  "Tetragon process_exec detection summary",
                "to_ids":   False,
            },
            {
                "category": "Attribution",
                "type":     "text",
                "value":    "MITRE ATT&CK: T1059.004 (Unix Shell), "
                            "T1611 (Escape to Host), T1021 (Remote Services)",
                "comment":  "Technique mapping from Wazuh rule metadata",
                "to_ids":   False,
            },
        ],
        "galaxy_tags": [
            'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter: Unix Shell - T1059.004"',
            'misp-galaxy:mitre-attack-pattern="Escape to Host - T1611"',
            'misp-galaxy:mitre-attack-pattern="Remote Services - T1021"',
        ],
        "taxonomy_tags": [
            'tlp:amber',
            'admiralty-scale:source-reliability="b"',
            'admiralty-scale:information-credibility="2"',
            'circl:incident-classification="intrusion-attempt"',
        ],
    },
    "100117": {
        "attributes": [
            {
                "category": "Internal reference",
                "type":     "text",
                "value":    "Wazuh Rule ID: 100117",
                "comment":  "CRITICAL FILE MODIFIED — /etc/passwd, /etc/shadow, /etc/sudoers",
                "to_ids":   False,
            },
            {
                "category": "Network activity",
                "type":     "ip-src",
                "value":    "192.168.200.128",
                "comment":  "Agent-Kali (ID: 006) — host where critical file was modified",
                "to_ids":   True,
            },
            {
                "category": "Artifacts dropped",
                "type":     "filepath",
                "value":    "/etc/sudoers",
                "comment":  "Critical system file modified (realtime FIM detection)",
                "to_ids":   True,
            },
            {
                "category": "Artifacts dropped",
                "type":     "text",
                "value":    "File /etc/sudoers mtime changed. "
                            "Old mtime: 1782697148 → New mtime: 1782698570. "
                            "Detected via Wazuh FIM realtime syscheck.",
                "comment":  "FIM change detail",
                "to_ids":   False,
            },
            {
                "category": "Attribution",
                "type":     "text",
                "value":    "MITRE ATT&CK: T1098 (Account Manipulation), "
                            "T1136 (Create Account), T1222 (File and Directory Permissions Modification), "
                            "TA0005 (Defense Evasion)",
                "comment":  "Technique mapping from Wazuh rule metadata",
                "to_ids":   False,
            },
        ],
        "galaxy_tags": [
            'misp-galaxy:mitre-attack-pattern="Account Manipulation - T1098"',
            'misp-galaxy:mitre-attack-pattern="Create Account - T1136"',
            'misp-galaxy:mitre-attack-pattern="File and Directory Permissions Modification - T1222"',
        ],
        "taxonomy_tags": [
            'tlp:amber',
            'admiralty-scale:source-reliability="b"',
            'admiralty-scale:information-credibility="3"',
            'circl:incident-classification="system-compromise"',
        ],
    },
    "100123": {
        "attributes": [
            {
                "category": "Internal reference",
                "type":     "text",
                "value":    "Wazuh Rule ID: 100123",
                "comment":  "REPEATED CRITICAL FILE MODS — 3+ modifications in 300s",
                "to_ids":   False,
            },
            {
                "category": "Network activity",
                "type":     "ip-src",
                "value":    "192.168.200.128",
                "comment":  "Agent-Kali (ID: 006) — host with repeated critical file modifications",
                "to_ids":   True,
            },
            {
                "category": "Artifacts dropped",
                "type":     "filepath",
                "value":    "/etc/sudoers",
                "comment":  "Critical system file modified repeatedly (3+ times in 300s)",
                "to_ids":   True,
            },
            {
                "category": "Artifacts dropped",
                "type":     "text",
                "value":    "File /etc/sudoers modified repeatedly. "
                            "mtime: 1782698571 → 1782698575. "
                            "Correlation rule triggered: 3+ critical file modifications within 300 seconds.",
                "comment":  "Correlation event detail",
                "to_ids":   False,
            },
            {
                "category": "Attribution",
                "type":     "text",
                "value":    "MITRE ATT&CK: T1098 (Account Manipulation), "
                            "T1222 (File and Directory Permissions Modification), "
                            "TA0005 (Defense Evasion)",
                "comment":  "Technique mapping from Wazuh rule metadata",
                "to_ids":   False,
            },
        ],
        "galaxy_tags": [
            'misp-galaxy:mitre-attack-pattern="Account Manipulation - T1098"',
            'misp-galaxy:mitre-attack-pattern="File and Directory Permissions Modification - T1222"',
        ],
        "taxonomy_tags": [
            'tlp:amber',
            'admiralty-scale:source-reliability="b"',
            'admiralty-scale:information-credibility="2"',
            'circl:incident-classification="system-compromise"',
        ],
    },
    "5710": {
        "attributes": [
            {
                "category": "Internal reference",
                "type":     "text",
                "value":    "Wazuh Rule ID: 5710",
                "comment":  "sshd: Attempt to login using a non-existent user",
                "to_ids":   False,
            },
            {
                "category": "Network activity",
                "type":     "ip-src",
                "value":    "10.10.10.99",
                "comment":  "Attacker source IP — SSH login attempt for non-existent user",
                "to_ids":   True,
            },
            {
                "category": "Network activity",
                "type":     "ip-dst",
                "value":    "192.168.200.128",
                "comment":  "Agent-Kali (ID: 006) — SSH target host",
                "to_ids":   True,
            },
            {
                "category": "Network activity",
                "type":     "text",
                "value":    "SSH login attempt for non-existent user 'Administrator' from 10.10.10.99 port 54321. "
                            "Log source: /var/log/auth.log. "
                            "Alert timestamp: 2026-06-29T02:03:11.885+0000",
                "comment":  "sshd auth.log detection summary",
                "to_ids":   False,
            },
            {
                "category": "Attribution",
                "type":     "text",
                "value":    "MITRE ATT&CK: T1021.004 (Remote Services: SSH), "
                            "T1078 (Valid Accounts), T1110 (Brute Force), "
                            "T1110.001 (Password Guessing), TA0006 (Credential Access)",
                "comment":  "Technique mapping from Wazuh rule metadata",
                "to_ids":   False,
            },
        ],
        "galaxy_tags": [
            'misp-galaxy:mitre-attack-pattern="Remote Services: SSH - T1021.004"',
            'misp-galaxy:mitre-attack-pattern="Valid Accounts - T1078"',
            'misp-galaxy:mitre-attack-pattern="Brute Force - T1110"',
            'misp-galaxy:mitre-attack-pattern="Password Guessing - T1110.001"',
        ],
        "taxonomy_tags": [
            'tlp:green',
            'admiralty-scale:source-reliability="c"',
            'admiralty-scale:information-credibility="3"',
            'circl:incident-classification="scanning"',
        ],
    },
    "5712": {
        "attributes": [
            {
                "category": "Internal reference",
                "type":     "text",
                "value":    "Wazuh Rule ID: 5712",
                "comment":  "sshd: brute force trying to get access to the system. Non existent user.",
                "to_ids":   False,
            },
            {
                "category": "Network activity",
                "type":     "ip-src",
                "value":    "10.10.10.99",
                "comment":  "Attacker source IP — 8 SSH failures in 300s (brute force)",
                "to_ids":   True,
            },
            {
                "category": "Network activity",
                "type":     "ip-dst",
                "value":    "192.168.200.128",
                "comment":  "Agent-Kali (ID: 006) — SSH brute force target host",
                "to_ids":   True,
            },
            {
                "category": "Network activity",
                "type":     "text",
                "value":    "SSH brute force: 8 failed password attempts for invalid user 'testuser' "
                            "from 10.10.10.99 port 54321 within 300s. "
                            "Log source: /var/log/auth.log. "
                            "Alert timestamp: 2026-06-29T02:03:15.862+0000",
                "comment":  "sshd brute force detection summary",
                "to_ids":   False,
            },
            {
                "category": "Attribution",
                "type":     "text",
                "value":    "MITRE ATT&CK: T1078 (Valid Accounts), "
                            "T1110 (Brute Force), TA0006 (Credential Access)",
                "comment":  "Technique mapping from Wazuh rule metadata",
                "to_ids":   False,
            },
        ],
        "galaxy_tags": [
            'misp-galaxy:mitre-attack-pattern="Valid Accounts - T1078"',
            'misp-galaxy:mitre-attack-pattern="Brute Force - T1110"',
        ],
        "taxonomy_tags": [
            'tlp:amber',
            'admiralty-scale:source-reliability="b"',
            'admiralty-scale:information-credibility="2"',
            'circl:incident-classification="brute-force"',
        ],
    },
}

def get_distribution_for_rule(rule_id: str) -> int:
    spec = ENRICHMENT.get(rule_id, {})
    for tag in spec.get("taxonomy_tags", []):
        if tag.startswith("tlp:"):
            return TLP_DISTRIBUTION.get(tag, DEFAULT_DISTRIBUTION)
    return DEFAULT_DISTRIBUTION

def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not VERIFY_SSL:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx

def misp_request(method: str, endpoint: str, payload: dict = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else b""
    req  = urllib.request.Request(
        f"{MISP_URL}{endpoint}", data=data, method=method,
        headers={
            "Authorization": API_KEY,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, context=_ctx(), timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"_error": body, "_code": e.code}
    except urllib.error.URLError as e:
        print(f"  [ERROR] Cannot reach MISP: {e.reason}", file=sys.stderr)
    return {"_error": str(e.reason), "_code": 0}

def misp_post(endpoint: str, payload: dict = None) -> dict:
    return misp_request("POST", endpoint, payload if payload is not None else {})

def misp_get(endpoint: str) -> dict:
    return misp_request("GET", endpoint)

def is_published(e: dict) -> bool:
    val = e.get("published", False)
    if isinstance(val, bool):
        return val
    return str(val) in ("1", "true", "True")

def extract_rule_id(event_info: str) -> str:
    m = re.search(r'Rule\s+(\d+)', event_info or "")
    return m.group(1) if m else ""

def enrich_event(event_id: str, rule_id: str) -> None:
    spec = ENRICHMENT.get(rule_id)
    if not spec:
        return

    distribution = get_distribution_for_rule(rule_id)

    attrs_ok = attrs_skip = attrs_fail = 0
    for attr in spec["attributes"]:
        payload = {
            "event_id":     event_id,
            "category":     attr["category"],
            "type":         attr["type"],
            "value":        attr["value"],
            "comment":      attr.get("comment", ""),
            "to_ids":       attr.get("to_ids", False),
            "distribution": distribution,
        }
        resp = misp_post(f"/attributes/add/{event_id}", payload)
        short_val = str(attr["value"])[:60]
        if "_error" in resp:
            err = resp["_error"].lower()
            if "already" in err or "exist" in err or resp.get("_code") == 403:
                attrs_skip += 1
            else:
                attrs_fail += 1
        else:
            attrs_ok += 1

    tags_ok = tags_skip = tags_fail = 0
    for tag in spec["galaxy_tags"]:
        resp = misp_post(f"/events/addTag/{event_id}", {"tag": tag})
        if "_error" in resp:
            err = resp["_error"].lower()
            if "already" in err or "exist" in err:
                tags_skip += 1
            else:
                tags_fail += 1
        else:
            tags_ok += 1

    taxonomy_tags = spec.get("taxonomy_tags", [])
    if taxonomy_tags:
        tax_ok = tax_skip = tax_fail = 0
        for tag in taxonomy_tags:
            resp = misp_post(f"/events/addTag/{event_id}", {"tag": tag})
            if "_error" in resp:
                err = resp["_error"].lower()
                if "already" in err or "exist" in err:
                    tax_skip += 1
                else:
                    tax_fail += 1
                    print(f"      [!] Taxonomy tag failed: {tag} — {resp['_error'][:120]}")
            else:
                tax_ok += 1

def fetch_events(hours: int, limit: int) -> list:
    print(f"[*] MISP URL  : {MISP_URL}")
    print(f"[*] Time range: last {hours} hour(s)  |  limit: {limit}\n")
    resp = misp_post("/events/restSearch", {
        "returnFormat": "json",
        "timestamp":    f"{hours}h",
        "metadata":     1,
        "limit":        limit,
        "page":         1,
    })
    raw = resp.get("response", resp)
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return raw.get("Event", [])
    return []

def fetch_single_event(event_id: int) -> list:
    print(f"[*] Fetching event ID: {event_id}\n")
    resp = misp_get(f"/events/view/{event_id}")
    e = resp.get("Event", {})
    if not e or "id" not in e:
        print(f"[ERROR] Event {event_id} not found.", file=sys.stderr)
        sys.exit(1)
    return [{"Event": e}]

def get_live_status(event_id: str) -> dict:
    resp = misp_get(f"/events/view/{event_id}")
    return resp.get("Event", {})

def set_distribution(event_id: str, distribution: int = DISTRIBUTION_ALL) -> bool:
    resp = misp_post(f"/events/edit/{event_id}", {
        "Event": {
            "distribution": distribution,
            "published":    True,
        }
    })
    if "_error" in resp:
        return False
    e = resp.get("Event", {})
    return int(e.get("distribution", -1)) == distribution

def publish_event(event_id: str, distribution: int = DISTRIBUTION_ALL) -> bool:
    misp_post(f"/events/publish/{event_id}", {})
    misp_post(f"/events/edit/{event_id}", {
        "Event": {
            "published":    True,
            "distribution": distribution,
        }
    })
    live = get_live_status(event_id)
    return is_published(live)

THREAT_LEVELS = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
ANALYSIS      = {0: "Initial", 1: "Ongoing", 2: "Completed"}
DIST_LABELS   = {
    0: "Org only", 1: "Community", 2: "Connected",
    3: "All communities", 4: "Sharing group",
}

def fmt_ts(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts) or "—"

def print_table(events: list, hours: int) -> None:
    now   = datetime.now(tz=timezone.utc)
    label = f"last {hours} hour(s)" if hours else "single event lookup"
    print(f"Events — {label}  |  as of {now.strftime('%Y-%m-%d %H:%M UTC')}\n")

    if not events:
        print("  No events found.")
        return
    W   = {"id": 6, "date": 19, "org": 22, "threat": 9,
           "analysis": 10, "dist": 16, "pub": 9, "attrs": 5}
    sep = "─" * 152
    hdr = (f"{'ID':<{W['id']}}  {'Last Modified':<{W['date']}}  "
           f"{'Org':<{W['org']}}  {'Threat':<{W['threat']}}  "
           f"{'Analysis':<{W['analysis']}}  {'Distribution':<{W['dist']}}  "
           f"{'Published':<{W['pub']}}  {'#':<{W['attrs']}}  Event Info")
    print(sep)
    print(hdr)
    print(sep)
    for ev in events:
        e         = ev.get("Event", ev)
        eid       = str(e.get("id", "?"))
        modified  = fmt_ts(e.get("timestamp", ""))
        org       = str(e.get("Orgc", {}).get("name", e.get("orgc", "?")))[:W["org"]]
        threat    = THREAT_LEVELS.get(int(e.get("threat_level_id", 4)), "?")
        analysis  = ANALYSIS.get(int(e.get("analysis", 0)), "?")
        dist      = DIST_LABELS.get(int(e.get("distribution", 0)), "?")
        published = "Yes ✓" if is_published(e) else "No"
        attrs     = str(e.get("attribute_count", "?"))
        info      = str(e.get("info", ""))[:50]
        rule_id   = extract_rule_id(e.get("info", ""))
        enrich_flag = " [+enrich]" if rule_id in ENRICHMENT else ""
        print(f"{eid:<{W['id']}}  {modified:<{W['date']}}  "
              f"{org:<{W['org']}}  {threat:<{W['threat']}}  "
              f"{analysis:<{W['analysis']}}  {dist:<{W['dist']}}  "
              f"{published:<{W['pub']}}  {attrs:<{W['attrs']}}  {info}{enrich_flag}")
        print(f"{'':>{W['id']}}  {MISP_URL}/events/view/{eid}\n")
    print(sep)
    print(f"Total: {len(events)} event(s)\n")

def publish_events(events: list) -> None:
    print("\n" + "=" * 62)
    print(f"  Publishing {len(events)} event(s) — distribution per TLP tag")
    print("=" * 62 + "\n")
    success = 0
    failed  = 0
    for ev in events:
        e    = ev.get("Event", ev)
        eid  = str(e.get("id", ""))
        info = str(e.get("info", ""))[:55]
        if not eid:
            continue
        print(f"[>] Event {eid} — {info}")
        rule_id = extract_rule_id(e.get("info", ""))
        distribution = get_distribution_for_rule(rule_id) if rule_id in ENRICHMENT else DEFAULT_DISTRIBUTION
        if rule_id in ENRICHMENT:
            enrich_event(eid, rule_id)
        else:
            print(f"  [·] No enrichment defined for Rule {rule_id or '?'} — using default distribution")
        if is_published(e):
            dist = int(e.get("distribution", 0))
            if dist == distribution:
                print(f"  [✓] Already published at correct distribution ({DIST_LABELS.get(dist, '?')}) — skipping")
                print(f"  [→] {MISP_URL}/events/view/{eid}\n")
                success += 1
                continue
        ok = set_distribution(eid, distribution)
        if ok:
            print(f"  [✓] Distribution → {DIST_LABELS.get(distribution, '?')} ({distribution})")
        else:
            print(f"  [✗] Failed to set distribution")
            failed += 1
            continue
        ok = publish_event(eid, distribution)
        if ok:
            print(f"  [✓] Published — verified via live re-fetch")
            print(f"  [→] {MISP_URL}/events/view/{eid}")
            success += 1
        else:
            print(f"  [✗] Published flag still False after both attempts.")
            failed += 1
        print()
    print("─" * 62)
    print(f"  Result: {success} published ✓   {failed} failed ✗\n")

def save_json(events: list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved to: {path}")

def enrich_only(events: list) -> None:
    targets = []
    for ev in events:
        e       = ev.get("Event", ev)
        rule_id = extract_rule_id(e.get("info", ""))
        if rule_id in ENRICHMENT:
            targets.append(ev)
    if not targets:
        print("\n  [!] No enrichment-eligible events found in this result set.\n")
        return
    print("\n" + "=" * 62)
    print(f"  Enriching {len(targets)} event(s) — publish status untouched")
    print("=" * 62 + "\n")
    ok = fail = 0
    for ev in targets:
        e       = ev.get("Event", ev)
        eid     = str(e.get("id", ""))
        info    = str(e.get("info", ""))[:55]
        rule_id = extract_rule_id(e.get("info", ""))
        live    = get_live_status(eid)
        n_attrs = int(live.get("attribute_count", 0))
        n_tags  = len(live.get("Tag", []))

        print(f"[>] Event {eid} — {info}")
        print(f"    Rule {rule_id}  |  attrs={n_attrs}  tags={n_tags}")
        try:
            enrich_event(eid, rule_id)
            print(f"  [✓] Enriched → {MISP_URL}/events/view/{eid}")
            ok += 1
        except Exception as exc:
            print(f"  [✗] Failed: {exc}")
            fail += 1
        print()
    print("─" * 62)
    print(f"  Result: {ok} enriched ✓   {fail} failed ✗\n")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="List and publish MISP events from TheHive."
    )
    p.add_argument("--hours",        type=int, default=4,
                   help="Events from last N hours (default: 4)")
    p.add_argument("--limit",        type=int, default=500,
                   help="Max events to return (default: 500)")
    p.add_argument("--publish",      action="store_true",
                   help="Enrich applicable events then publish all to All Communities")
    p.add_argument("--enrich-only",  action="store_true",
                   help="Add attributes/galaxy/taxonomy tags to already-published events (no publish step)")
    p.add_argument("--id",           type=int, default=0,
                   help="Target a single event by ID")
    p.add_argument("--output",       default="",
                   help="Save raw JSON to file")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    if args.id:
        events = fetch_single_event(args.id)
        hours  = 0
    else:
        events = fetch_events(hours=args.hours, limit=args.limit)
        hours  = args.hours
    print_table(events, hours=hours)
    if getattr(args, "enrich_only", False) and events:
        enrich_only(events)
    elif args.publish and events:
        confirm = input(
            f"Publish {len(events)} event(s) to ALL communities? [y/N]: "
        ).strip().lower()
        if confirm == "y":
            publish_events(events)
        else:
            print("Aborted.")
    if args.output:
        save_json(events, args.output)

if __name__ == "__main__":
    main()
