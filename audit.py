from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from parser import parse_rules
from rule_checker import detect_dead_rules


router = APIRouter()


class AuditRequest(BaseModel):
    rules: List[str] = Field(default_factory=list)
    vendor: Optional[str] = None


def _normalize_rules(rules: List[str]) -> List[str]:
    """Trim incoming rules and discard blank entries from UI text input."""
    normalized: List[str] = []
    for rule in rules:
        if rule is None:
            continue
        cleaned = str(rule).strip()
        if cleaned:
            normalized.append(cleaned)
    return normalized


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
    normalized_rules = _normalize_rules(payload.rules)
    parsed_rules = parse_rules(normalized_rules, vendor=payload.vendor)
    summary = _build_summary(parsed_rules)

    return {
        "status": "success",
        "data": {
            "requested_vendor": payload.vendor,
            "summary": summary,
            "results": parsed_rules,
        },
    }


@router.get("/audit/check-dead-rules")
async def get_dead_rules_info() -> Dict[str, Any]:
    """Get information about the dead rules checking endpoint."""
    return {
        "status": "success",
        "data": {
            "message": "Send firewall rules to POST /api/v1/audit/check-dead-rules to detect dead rules.",
            "input_schema": {
                "rules": ["rule line 1", "rule line 2"],
                "vendor": "palo_alto or cisco (optional)",
            },
            "description": "Detects dead rules: parse errors, incomplete rules, redundant rules, shadowed rules, unreferenced rules, and ineffective catch-all rules.",
        },
    }


@router.post("/audit/check-dead-rules")
async def check_dead_rules(payload: AuditRequest) -> Dict[str, Any]:
    """
    Analyze firewall rules to detect 'dead rules'.

    Dead rules include:
    - Parse errors (invalid syntax)
    - Incomplete rules (missing critical fields)
    - Redundant rules (exact duplicates)
    - Shadowed rules (unreachable in ACL order)
    - Unreferenced rules (not called by policies)
    - Ineffective rules (suspicious catch-all rules)
    """
    normalized_rules = _normalize_rules(payload.rules)
    results = detect_dead_rules(normalized_rules, vendor=payload.vendor)

    return {
        "status": "success",
        "data": {
            "requested_vendor": payload.vendor,
            "total_rules_analyzed": results["total_rules"],
            "dead_rules_count": results["dead_rules_count"],
            "dead_rules": results["dead_rules"],
            "redundant_groups": results["redundant_groups"],
            "summary": {
                "parse_errors": sum(1 for r in results["dead_rules"] if r["reason"] == "Parse error"),
                "incomplete_rules": sum(1 for r in results["dead_rules"] if r["reason"] == "Incomplete rule"),
                "redundant_rules": sum(1 for r in results["dead_rules"] if r["reason"] == "Redundant rule"),
                "shadowed_rules": sum(1 for r in results["dead_rules"] if r["reason"] == "Shadowed by earlier rule"),
                "unreferenced_rules": sum(1 for r in results["dead_rules"] if r["reason"] == "Potentially unreferenced rule"),
                "ineffective_rules": sum(1 for r in results["dead_rules"] if r["reason"] == "Ineffective catch-all rule"),
            },
        },
    }