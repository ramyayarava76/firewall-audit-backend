from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from parser import parse_rules


router = APIRouter()


class AuditRequest(BaseModel):
    rules: List[str] = Field(default_factory=list)
    vendor: Optional[str] = None


def _build_summary(parsed_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    success_count = sum(1 for item in parsed_rules if not item.get("error"))
    failed_count = len(parsed_rules) - success_count

    vendor_counts = Counter(item.get("vendor", "unknown") for item in parsed_rules)
    action_counts = Counter(item.get("action", "unknown") for item in parsed_rules)

    ips: set[str] = set()
    ports: set[str] = set()
    protocols: set[str] = set()

    for item in parsed_rules:
        extracted = item.get("extracted", {})
        ips.update(extracted.get("ips", []))
        ports.update(extracted.get("ports", []))
        protocols.update(extracted.get("protocols", []))

    return {
        "total_rules": len(parsed_rules),
        "parsed_successfully": success_count,
        "failed_to_parse": failed_count,
        "vendors": dict(vendor_counts),
        "actions": dict(action_counts),
        "unique_objects": {
            "ips": sorted(ips),
            "ports": sorted(ports),
            "protocols": sorted(protocols),
        },
    }


@router.get("/audit")
async def get_audit_info() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "message": "Send firewall rules to POST /api/v1/audit for analysis.",
            "input_schema": {
                "rules": ["rule line 1", "rule line 2"],
                "vendor": "palo_alto or cisco (optional)",
            },
        },
    }


@router.post("/audit")
async def audit_rules(payload: AuditRequest) -> Dict[str, Any]:
    parsed_rules = parse_rules(payload.rules, vendor=payload.vendor)
    summary = _build_summary(parsed_rules)

    return {
        "status": "success",
        "data": {
            "requested_vendor": payload.vendor,
            "summary": summary,
            "results": parsed_rules,
        },
    }