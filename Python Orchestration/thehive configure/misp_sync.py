#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_MISP_DIR = Path(__file__).resolve().parent / "MISP"
if str(_MISP_DIR) not in sys.path:
    sys.path.insert(0, str(_MISP_DIR))

import event_publish as ep  

_THEHIVE_SEV_TO_MISP_THREAT: dict[int, int] = {
    1: 3,  # TheHive Low      -> MISP Low
    2: 2,  # TheHive Medium   -> MISP Medium
    3: 1,  # TheHive High     -> MISP High
    4: 1,  # TheHive Critical -> MISP High (MISP has no "Critical" level)
}

_MARKER_TEMPLATE = "TheHive ID: {case_id}"

def _misp_event_exists(case_id: str) -> Optional[str]:
    marker = _MARKER_TEMPLATE.format(case_id=case_id)
    resp = ep.misp_post("/events/restSearch", {
        "returnFormat": "json",
        "eventinfo":    marker,
        "metadata":     1,
        "limit":        10,
    })
    if "_error" in resp:
        logger.warning(f"MISP dedup check failed  case={case_id}  error={resp['_error']}")
        return None

    raw = resp.get("response", resp)
    events = raw if isinstance(raw, list) else raw.get("Event", [])
    for ev in events:
        e = ev.get("Event", ev)
        if marker in str(e.get("info", "")):
            return str(e.get("id"))
    return None

def _extract_rule_id(case_data: dict) -> str:
    for tag in case_data.get("tags", []):
        if tag.startswith("rule:"):
            return tag.split("rule:", 1)[1]
    return ""

def sync_case_to_misp(case_id: str, case_data: dict) -> Optional[str]:
    try:
        existing_id = _misp_event_exists(case_id)
        if existing_id:
            logger.info(f"MISP event already exists  case={case_id}  misp_id={existing_id}")
            return existing_id

        title    = case_data.get("title", f"TheHive Case {case_id}")
        desc     = case_data.get("description", "") or "No description provided"
        severity = int(case_data.get("severity", 2))
        rule_id  = _extract_rule_id(case_data)

        threat_level = _THEHIVE_SEV_TO_MISP_THREAT.get(severity, 4)
        distribution = (
            ep.get_distribution_for_rule(rule_id)
            if rule_id in ep.ENRICHMENT
            else ep.DEFAULT_DISTRIBUTION
        )

        payload = {
            "Event": {
                "info":            f"{title} ({_MARKER_TEMPLATE.format(case_id=case_id)})",
                "threat_level_id": threat_level,
                "analysis":        "0",  
                "distribution":    distribution,
                "comment":         desc,
            }
        }

        resp = ep.misp_post("/events/add", payload)
        if "_error" in resp:
            logger.error(f"MISP event creation failed  case={case_id}  error={resp['_error']}")
            return None

        event   = resp.get("Event", {})
        misp_id = event.get("id")
        if not misp_id:
            logger.error(f"MISP event creation returned no id  case={case_id}  resp={resp}")
            return None

        logger.info(
            f"MISP event created  case={case_id}  misp_id={misp_id}  "
            f"rule={rule_id or '?'}  threat_level={threat_level}  dist={distribution}"
        )

        if rule_id in ep.ENRICHMENT:
            try:
                ep.enrich_event(misp_id, rule_id)
            except Exception as exc:
                logger.warning(f"MISP enrichment failed  misp_id={misp_id}  error={exc}")
        else:
            logger.debug(f"No enrichment template for rule={rule_id or '?'}  misp_id={misp_id}")

        if not ep.set_distribution(misp_id, distribution):
            logger.warning(f"Failed to set distribution  misp_id={misp_id}")

        if ep.publish_event(misp_id, distribution):
            logger.info(f"MISP event published  misp_id={misp_id}  distribution={distribution}")
        else:
            logger.warning(f"MISP event publish did not verify  misp_id={misp_id}")

        return misp_id
    
    except Exception as exc:
        logger.error(f"sync_case_to_misp raised unexpectedly  case={case_id}: {exc}")
        return None
