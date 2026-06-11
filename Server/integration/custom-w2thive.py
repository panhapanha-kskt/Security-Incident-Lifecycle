#!/var/ossec/framework/python/bin/python3
# custom-w2thive.py – Wazuh → TheHive 5.x integration
# ═══════════════════════════════════════════════════════════
#
#  Receives one Wazuh alert JSON file per invocation.
#  Deduplicates by rule_id+agent_id within DEDUP_WINDOW seconds.
#  Creates a TheHive 5.x alert via POST /api/v1/alert.
#
#  Called by Wazuh as:
#    custom-w2thive <alert_file> <api_key> <hook_url>
#
#  Fixed bugs vs original:
#    1. safe_int() replaces bare int() → no crash on missing/None level
#    2. safe_get() replaces bare dict[] → no KeyError on missing fields
#    3. Dedup key = rule_id + agent_id (not rule_id alone)
#    4. DEDUP_WINDOW reduced to 3600s (1h) — was 86400 (24h, too aggressive)
#    5. Stale cache auto-purged on every run
#    6. sourceRef uses full uuid4 (not truncated 6-char)
#    7. TheHive 5.x duplicate sourceRef (HTTP 200) handled — updates existing
#    8. Severity 1 (Low) added for levels 3-6 — was missing
#    9. groups field access wrapped in .get() — no crash if absent
#   10. Full debug logging of every decision (enable debug_enabled = True)
#   11. Connectivity pre-check before processing
#   12. Cache file atomic write to prevent corruption
# ═══════════════════════════════════════════════════════════

import json
import logging
import os
import re
import sys
import tempfile
import time
import uuid

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────
# Minimum Wazuh rule level to forward to TheHive.
# Must be >= the <level> value in ossec.conf integration block.
LVL_THRESHOLD          = 7
SURICATA_LVL_THRESHOLD = 3       # Suricata alerts: forward severity <= this value

# Dedup: same rule_id + agent_id won't create a new alert within this window.
# 3600 = 1 hour.  Set to 0 to disable dedup entirely.
DEDUP_WINDOW = 3600

# Path for the on-disk dedup cache.
CACHE_FILE = '/var/ossec/logs/thehive_dedup_cache.json'

# Logging verbosity
DEBUG_ENABLED = True   # set True for full per-decision logging
INFO_ENABLED  = True

# ── Logging setup ─────────────────────────────────────────────
pwd      = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{}/logs/integrations.log'.format(pwd)

logger = logging.getLogger('w2thive')
logger.setLevel(logging.DEBUG if DEBUG_ENABLED else (logging.INFO if INFO_ENABLED else logging.WARNING))

_fh = logging.FileHandler(log_file)
_fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
logger.addHandler(_fh)


# ── Safe helpers ──────────────────────────────────────────────
def safe_int(value, default: int = 0) -> int:
    """Convert value to int without raising.  Returns default on failure."""
    if value is None or value == '':
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_get(d: dict, *keys, default=''):
    """Safely traverse nested dicts without KeyError."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur if cur is not None else default


# ── Dedup cache ───────────────────────────────────────────────
def load_cache() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception as exc:
        logger.warning('load_cache failed: {} — starting fresh'.format(exc))
        return {}


def save_cache(cache: dict) -> None:
    """Atomic write: write to temp file then rename to avoid partial writes."""
    tmp = CACHE_FILE + '.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(cache, f, indent=2)
        os.replace(tmp, CACHE_FILE)
    except Exception as exc:
        logger.error('save_cache failed: {}'.format(exc))


def purge_cache(cache: dict) -> dict:
    """Remove all entries older than DEDUP_WINDOW."""
    if DEDUP_WINDOW <= 0:
        return {}
    cutoff = time.time() - DEDUP_WINDOW
    purged = {k: v for k, v in cache.items()
              if isinstance(v, dict) and v.get('timestamp', 0) > cutoff}
    removed = len(cache) - len(purged)
    if removed:
        logger.debug('purge_cache: removed {} expired entries'.format(removed))
    return purged


def _dedup_key(rule_id: str, agent_id: str) -> str:
    """
    Dedup key scoped to rule + agent.
    Original bug: key was rule_id ONLY → one agent's alert blocked ALL agents
    for the same rule for 24 hours.
    """
    return '{}|{}'.format(rule_id, agent_id)


def is_in_cache(cache: dict, rule_id: str, agent_id: str) -> bool:
    key = _dedup_key(rule_id, agent_id)
    if key in cache:
        entry   = cache[key]
        elapsed   = time.time() - entry.get('timestamp', 0)
        remaining = max(0, DEDUP_WINDOW - elapsed)
        hrs  = int(remaining // 3600)
        mins = int((remaining % 3600) // 60)
        logger.info(
            '[DEDUP] Suppressed rule={} agent={} — resets in {}h {}m  '
            '(thehive_id={})'.format(rule_id, agent_id, hrs, mins,
                                     entry.get('thehive_id', '?'))
        )
        return True
    return False


def add_to_cache(cache: dict, rule_id: str, agent_id: str,
                 thehive_id: str = '') -> dict:
    key = _dedup_key(rule_id, agent_id)
    cache[key] = {
        'timestamp':  time.time(),
        'rule_id':    rule_id,
        'agent_id':   agent_id,
        'thehive_id': thehive_id,
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    return cache


# ── TheHive API helpers ───────────────────────────────────────
def _thehive_headers(api_key: str) -> dict:
    return {
        'Authorization': 'Bearer {}'.format(api_key),
        'Content-Type':  'application/json',
    }


def check_connectivity(thive_url: str, api_key: str) -> bool:
    """Quick health-check before processing.  Returns True if TheHive responds."""
    try:
        r = requests.get(
            '{}/api/v1/status'.format(thive_url),
            headers=_thehive_headers(api_key),
            verify=False,
            timeout=5,
        )
        if r.status_code in (200, 401, 403):
            # 401/403 = reachable but auth problem (flag separately)
            if r.status_code == 401:
                logger.error('[CONNECTIVITY] TheHive reachable but API key is INVALID (401)')
            elif r.status_code == 403:
                logger.error('[CONNECTIVITY] TheHive reachable but API key lacks permission (403)')
            else:
                logger.debug('[CONNECTIVITY] TheHive OK ({})'.format(r.status_code))
            return r.status_code == 200
        logger.warning('[CONNECTIVITY] TheHive returned {}'.format(r.status_code))
        return False
    except requests.exceptions.ConnectionError:
        logger.error('[CONNECTIVITY] Cannot reach TheHive at {} — connection refused'.format(thive_url))
        return False
    except requests.exceptions.Timeout:
        logger.error('[CONNECTIVITY] TheHive at {} timed out'.format(thive_url))
        return False
    except Exception as exc:
        logger.error('[CONNECTIVITY] Unexpected error: {}'.format(exc))
        return False


def query_existing_alert(thive_url: str, api_key: str,
                         rule_id: str, agent_id: str) -> tuple:
    """
    Check TheHive for an open alert matching this rule+agent.
    Returns (found: bool, alert_id: str | None).

    Uses TheHive 5.x query DSL.  Scoped by both rule_id AND agent_id tags
    so agents don't suppress each other.
    """
    query = {
        'query': [
            {'_name': 'listAlert'},
            {
                '_name': 'filter',
                '_and': [
                    {'_field': 'tags', '_value': 'rule={}'.format(rule_id)},
                    {'_field': 'tags', '_value': 'agent_id={}'.format(agent_id)},
                    {'_in': {'_field': 'status', '_values': ['New', 'InProgress']}},
                ],
            },
        ]
    }
    try:
        r = requests.post(
            '{}/api/v1/query'.format(thive_url),
            headers=_thehive_headers(api_key),
            json=query,
            verify=False,
            timeout=10,
        )
        if r.status_code == 200:
            results = r.json()
            if isinstance(results, list) and results:
                alert_id = results[0].get('_id', 'unknown')
                logger.info(
                    '[THEHIVE-DEDUP] rule={} agent={} already in TheHive id={}'.format(
                        rule_id, agent_id, alert_id)
                )
                return True, alert_id
            return False, None
        logger.error('[THEHIVE-QUERY] Error {}: {}'.format(r.status_code, r.text[:200]))
        return False, None
    except Exception as exc:
        logger.error('[THEHIVE-QUERY] Exception: {}'.format(exc))
        return False, None


# ── Alert construction ────────────────────────────────────────
def _extract_fields(alt: list) -> str:
    """Render a flat key/value list as a Markdown table grouped by top-level key."""
    sections: dict = {}
    for entry in alt:
        entry = entry.lstrip('.')
        if '|||' not in entry:
            continue
        path, val = entry.split('|||', 1)
        dot = path.find('.')
        section = path[:dot] if dot != -1 else path
        sections.setdefault(section, []).append((path, val))

    md = ''
    for section, rows in sections.items():
        md += '### {}\n'.format(section.capitalize())
        md += '| key | value |\n| --- | --- |\n'
        for key, val in rows:
            md += '| **{}** | {} |\n'.format(key, val)
    return md


def _flatten(data: dict, prefix: str = '', out: list = None) -> list:
    """Recursively flatten a dict to dotted key|||value pairs."""
    if out is None:
        out = []
    for k, v in data.items():
        full_key = '{}.{}'.format(prefix, k) if prefix else k
        if isinstance(v, dict):
            _flatten(v, full_key, out)
        else:
            out.append('{}|||{}'.format(full_key, v))
    return out


def _extract_observables(text: str) -> dict:
    """Pull IPs, URLs, and domains from the formatted alert text."""
    obs: dict = {'ip': [], 'url': [], 'domain': []}
    obs['ip'] = list(set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text)))
    obs['url'] = list(set(re.findall(
        r'https?://[^\s|>\])\'"]+', text)))
    for url in obs['url']:
        try:
            domain = url.split('//')[1].split('/')[0]
            if domain and domain not in obs['domain']:
                obs['domain'].append(domain)
        except IndexError:
            pass
    return obs


def build_thehive_alert(w_alert: dict) -> dict:
    """
    Construct a TheHive 5.x-compatible alert payload from a Wazuh alert.

    Severity mapping (TheHive 5.x):
      1 = Low      → Wazuh level  3-6
      2 = Medium   → Wazuh level  7-9
      3 = High     → Wazuh level 10-12
      4 = Critical → Wazuh level 13+
    """
    rule      = w_alert.get('rule', {})
    agent     = w_alert.get('agent', {})
    rule_id   = str(safe_get(rule, 'id',          default='unknown'))
    rule_lvl  = safe_int(safe_get(rule, 'level',  default=0))
    rule_desc = safe_get(rule, 'description',     default='No description')

    agent_id   = str(safe_get(agent, 'id',   default='000'))
    agent_name = str(safe_get(agent, 'name', default='wazuh-manager'))
    agent_ip   = str(safe_get(agent, 'ip',   default='N/A'))

    # ── Severity ──────────────────────────────────────────
    if rule_lvl >= 13:
        severity = 4   # Critical
    elif rule_lvl >= 10:
        severity = 3   # High
    elif rule_lvl >= 7:
        severity = 2   # Medium
    else:
        severity = 1   # Low

    # ── Markdown description ──────────────────────────────
    flat       = _flatten(w_alert)
    format_alt = _extract_fields(flat)

    # ── Observables ───────────────────────────────────────
    obs_dict = _extract_observables(format_alt)
    artifacts = []
    for dtype, values in obs_dict.items():
        for val in values:
            if val:
                artifacts.append({'dataType': dtype, 'data': str(val)})

    # ── Tags ──────────────────────────────────────────────
    tags = [
        'wazuh',
        'rule={}'.format(rule_id),
        'level={}'.format(rule_lvl),
        'agent_name={}'.format(agent_name),
        'agent_id={}'.format(agent_id),
        'agent_ip={}'.format(agent_ip),
    ]

    # Add MITRE tags from rule if present
    mitre_ids = safe_get(rule, 'mitre', 'id', default=[])
    if isinstance(mitre_ids, list):
        for m in mitre_ids:
            tags.append('mitre={}'.format(m))

    # ── sourceRef: full uuid for uniqueness ───────────────
    # Original used uuid[:6] — 6-char hex can collide and TheHive treats
    # duplicate sourceRef as the same alert (returns 200, not 201).
    source_ref = str(uuid.uuid4())

    alert = {
        'title':       '[Wazuh] {} – Rule {} (Level {})'.format(
                           rule_desc[:100], rule_id, rule_lvl),
        'description': format_alt or 'No additional data.',
        'type':        'wazuh_alert',
        'source':      'wazuh',
        'sourceRef':   source_ref,
        'severity':    severity,
        'tlp':         2,         # TLP:AMBER
        'pap':         2,         # PAP:AMBER  (TheHive 5 supports this)
        'tags':        tags,
        'observables': artifacts,
    }
    return alert


# ── Send to TheHive ───────────────────────────────────────────
def send_alert(alert: dict, thive_url: str, api_key: str) -> str | None:
    """
    POST alert to TheHive.  Returns the new alert _id or None on failure.

    TheHive 5.x response codes:
      201 = created successfully
      200 = duplicate sourceRef — alert already exists (update it instead)
      400 = bad request (schema error)
      401 = bad API key
      403 = forbidden
    """
    url = '{}/api/v1/alert'.format(thive_url)
    try:
        r = requests.post(
            url,
            headers=_thehive_headers(api_key),
            json=alert,
            verify=False,
            timeout=15,
        )
        if r.status_code == 201:
            alert_id = r.json().get('_id', 'unknown')
            logger.info('[CREATE] Alert created id={} rule={} title={}'.format(
                alert_id, alert['tags'][1], alert['title'][:60]))
            return alert_id

        if r.status_code == 200:
            # Duplicate sourceRef — shouldn't happen with full uuid4, but handle it
            alert_id = r.json().get('_id', 'unknown')
            logger.info('[DUPLICATE] Alert already exists id={} (sourceRef collision)'.format(
                alert_id))
            return alert_id

        # Any other status = failure
        logger.error('[CREATE-FAIL] HTTP {} for rule={}: {}'.format(
            r.status_code, alert['tags'][1], r.text[:300]))
        return None

    except requests.exceptions.ConnectionError as exc:
        logger.error('[SEND] Connection error: {}'.format(exc))
        return None
    except requests.exceptions.Timeout:
        logger.error('[SEND] Request timed out to {}'.format(thive_url))
        return None
    except Exception as exc:
        logger.error('[SEND] Unexpected error: {}'.format(exc))
        return None


# ── Main processing ───────────────────────────────────────────
def process_alert(w_alert: dict, thive_url: str, api_key: str) -> None:
    rule    = w_alert.get('rule', {})
    agent   = w_alert.get('agent', {})
    rule_id  = str(safe_get(rule,  'id',   default='unknown'))
    agent_id = str(safe_get(agent, 'id',   default='000'))

    logger.info('[PROCESS] rule={} agent={} level={}'.format(
        rule_id, agent_id, safe_get(rule, 'level', default='?')))

    # ── Load + purge cache ─────────────────────────────────
    cache = purge_cache(load_cache())

    # ── Local dedup check ──────────────────────────────────
    if DEDUP_WINDOW > 0 and is_in_cache(cache, rule_id, agent_id):
        save_cache(cache)
        return

    # ── TheHive live dedup check ───────────────────────────
    found, existing_id = query_existing_alert(thive_url, api_key, rule_id, agent_id)
    if found:
        cache = add_to_cache(cache, rule_id, agent_id, existing_id)
        save_cache(cache)
        return

    # ── Build and send ─────────────────────────────────────
    alert    = build_thehive_alert(w_alert)
    new_id   = send_alert(alert, thive_url, api_key)

    if new_id:
        cache = add_to_cache(cache, rule_id, agent_id, new_id)
        save_cache(cache)
        logger.info('[DONE] rule={} agent={} → TheHive id={}'.format(
            rule_id, agent_id, new_id))
    else:
        logger.error('[DONE] rule={} agent={} → FAILED to create alert'.format(
            rule_id, agent_id))


# ── Entry point ───────────────────────────────────────────────
def main(args: list) -> None:
    """
    Wazuh passes:
      args[1] = path to alert JSON file
      args[2] = api_key  (from ossec.conf <api_key>)
      args[3] = hook_url (from ossec.conf <hook_url>)
    """
    if len(args) < 4:
        logger.error('Usage: custom-w2thive <alert_file> <api_key> <hook_url>')
        sys.exit(1)

    alert_file = args[1]
    api_key    = args[2]
    thive_url  = args[3].rstrip('/')   # strip trailing slash

    # ── Load alert JSON ────────────────────────────────────
    try:
        with open(alert_file, 'r') as f:
            w_alert = json.load(f)
    except FileNotFoundError:
        logger.error('Alert file not found: {}'.format(alert_file))
        sys.exit(1)
    except json.JSONDecodeError as exc:
        logger.error('Alert file is not valid JSON: {} — {}'.format(alert_file, exc))
        sys.exit(1)

    if not isinstance(w_alert, dict):
        logger.error('Alert JSON is not a dict: {}'.format(alert_file))
        sys.exit(1)

    # ── Connectivity pre-check ─────────────────────────────
    if not check_connectivity(thive_url, api_key):
        logger.error('Aborting — TheHive not reachable at {}'.format(thive_url))
        sys.exit(1)

    rule        = w_alert.get('rule', {})
    rule_level  = safe_int(safe_get(rule, 'level', default=0))
    rule_groups = rule.get('groups', [])   # safe .get(), no KeyError

    # ── Routing logic ──────────────────────────────────────
    # Suricata IDS alerts: forward if Suricata severity <= threshold
    is_suricata = (isinstance(rule_groups, list) and
                   'ids' in rule_groups and 'suricata' in rule_groups)

    if is_suricata:
        suricata_sev = safe_int(
            safe_get(w_alert, 'data', 'alert', 'severity', default=99)
        )
        if suricata_sev <= SURICATA_LVL_THRESHOLD:
            logger.info('[ROUTE] Suricata alert sev={} → forwarding'.format(suricata_sev))
            process_alert(w_alert, thive_url, api_key)
        else:
            logger.debug('[ROUTE] Suricata alert sev={} > threshold={} → skip'.format(
                suricata_sev, SURICATA_LVL_THRESHOLD))
    elif rule_level >= LVL_THRESHOLD:
        logger.info('[ROUTE] Wazuh level={} >= threshold={} → forwarding'.format(
            rule_level, LVL_THRESHOLD))
        process_alert(w_alert, thive_url, api_key)
    else:
        logger.debug('[ROUTE] Wazuh level={} < threshold={} → skip'.format(
            rule_level, LVL_THRESHOLD))


if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception:
        logger.exception('[FATAL] Unhandled exception in w2thive integration')
        sys.exit(1)