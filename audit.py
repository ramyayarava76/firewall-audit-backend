from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from parser import parse_rules
from report_generator import generate_audit_csv, generate_dead_rules_csv
from rule_checker import detect_dead_rules
from logger import get_logger, RequestLogger, AnalysisLogger

logger = get_logger(__name__)


router = APIRouter()

AUDIT_ENDPOINT = "/api/v1/audit"
DEAD_RULES_ENDPOINT = "/api/v1/audit/check-dead-rules"
DEAD_RULES_REPORT_ENDPOINT = "/api/v1/audit/check-dead-rules/report"


class AuditRequest(BaseModel):
    rules: List[str] = Field(default_factory=list)
    vendor: Optional[str] = None


DEAD_RULE_REASON_TO_SUMMARY_KEY = {
    "Parse error": "parse_errors",
    "Incomplete rule": "incomplete_rules",
    "Redundant rule": "redundant_rules",
    "Shadowed by earlier rule": "shadowed_rules",
    "Potentially unreferenced rule": "unreferenced_rules",
    "Ineffective catch-all rule": "ineffective_rules",
}


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
    success_count = 0
    vendor_counts: Counter = Counter()
    action_counts: Counter = Counter()

    ips: set[str] = set()
    ports: set[str] = set()
    protocols: set[str] = set()

    for item in parsed_rules:
        if not item.get("error"):
            success_count += 1

        vendor_counts[item.get("vendor", "unknown")] += 1
        action_counts[item.get("action", "unknown")] += 1

        extracted = item.get("extracted", {})
        ips.update(extracted.get("ips", []))
        ports.update(extracted.get("ports", []))
        protocols.update(extracted.get("protocols", []))

    failed_count = len(parsed_rules) - success_count

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


def _empty_summary() -> Dict[str, Any]:
    return {
        "total_rules": 0,
        "parsed_successfully": 0,
        "failed_to_parse": 0,
        "vendors": {},
        "actions": {},
        "unique_objects": {
            "ips": [],
            "ports": [],
            "protocols": [],
        },
    }


def _dead_rules_summary(dead_rules: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {key: 0 for key in DEAD_RULE_REASON_TO_SUMMARY_KEY.values()}
    reason_counts = Counter(item.get("reason") for item in dead_rules)

    for reason, summary_key in DEAD_RULE_REASON_TO_SUMMARY_KEY.items():
        summary[summary_key] = reason_counts.get(reason, 0)

    return summary


def _empty_dead_rules_result() -> Dict[str, Any]:
    return {
        "total_rules": 0,
        "dead_rules_count": 0,
        "dead_rules": [],
        "redundant_groups": [],
    }


def _analyze_dead_rules(normalized_rules: List[str], vendor: Optional[str]) -> Dict[str, Any]:
    if not normalized_rules:
        return _empty_dead_rules_result()
    return detect_dead_rules(normalized_rules, vendor=vendor)


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
    logger.info(f"Audit request received with {len(payload.rules)} rules from vendor: {payload.vendor}")
    try:
        normalized_rules = _normalize_rules(payload.rules)
        logger.debug(f"Normalized {len(normalized_rules)} rules")
        if not normalized_rules:
            parsed_rules = []
            summary = _empty_summary()
        else:
            parsed_rules = parse_rules(normalized_rules, vendor=payload.vendor)
            summary = _build_summary(parsed_rules)
        
        logger.info(
            f"Audit completed: {summary['parsed_successfully']} parsed, "
            f"{summary['failed_to_parse']} failed out of {summary['total_rules']} total"
        )
        RequestLogger.log_request("POST", AUDIT_ENDPOINT, 200, details={"rules_analyzed": summary['total_rules']})
        
        return {
            "status": "success",
            "data": {
                "requested_vendor": payload.vendor,
                "summary": summary,
                "results": parsed_rules,
            },
        }
    except Exception as e:
        logger.error(f"Error during audit: {e}", exc_info=True)
        RequestLogger.log_error("POST", AUDIT_ENDPOINT, str(e), 500)
        raise


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
    logger.info(f"Dead rules check requested with {len(payload.rules)} rules from vendor: {payload.vendor}")
    AnalysisLogger.log_analysis_start("dead_rules_detection", len(payload.rules))
    
    try:
        normalized_rules = _normalize_rules(payload.rules)
        results = _analyze_dead_rules(normalized_rules, vendor=payload.vendor)

        summary = _dead_rules_summary(results["dead_rules"])
        
        logger.info(
            f"Dead rules detection completed: {results['dead_rules_count']} dead rules found out of "
            f"{results['total_rules']} total rules"
        )
        AnalysisLogger.log_analysis_complete("dead_rules_detection", results["total_rules"], summary)
        RequestLogger.log_request("POST", DEAD_RULES_ENDPOINT, 200, details={"dead_rules_found": results["dead_rules_count"]})

        return {
            "status": "success",
            "data": {
                "requested_vendor": payload.vendor,
                "total_rules_analyzed": results["total_rules"],
                "dead_rules_count": results["dead_rules_count"],
                "dead_rules": results["dead_rules"],
                "redundant_groups": results["redundant_groups"],
                "summary": summary,
            },
        }
    except Exception as e:
        logger.error(f"Error during dead rules check: {e}", exc_info=True)
        AnalysisLogger.log_analysis_error("dead_rules_detection", str(e))
        RequestLogger.log_error("POST", DEAD_RULES_ENDPOINT, str(e), 500)
        raise


@router.post("/audit/report")
async def download_audit_report(payload: AuditRequest):
    """
    Parse the supplied rules and return the results as a downloadable CSV file.
    """
    logger.info(f"Audit CSV report requested for {len(payload.rules)} rules")
    try:
        normalized_rules = _normalize_rules(payload.rules)
        parsed_rules = (
            parse_rules(normalized_rules, vendor=payload.vendor)
            if normalized_rules
            else []
        )
        csv_content = generate_audit_csv(parsed_rules)
        logger.info(f"Audit CSV report generated: {len(csv_content)} bytes")
        RequestLogger.log_request("POST", f"{AUDIT_ENDPOINT}/report", 200, details={"rules_analyzed": len(parsed_rules)})
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_report.csv"},
        )
    except Exception as e:
        logger.error(f"Error generating audit CSV report: {e}", exc_info=True)
        RequestLogger.log_error("POST", f"{AUDIT_ENDPOINT}/report", str(e), 500)
        raise


@router.post("/audit/check-dead-rules/report")
@router.post("/audit/dead-rules-report")
async def download_dead_rules_report(payload: AuditRequest):
    """
    Analyze the supplied rules for dead rules and return the findings as a
    downloadable CSV file.
    """
    logger.info(f"Dead rules CSV report requested for {len(payload.rules)} rules")
    try:
        normalized_rules = _normalize_rules(payload.rules)
        results = _analyze_dead_rules(normalized_rules, vendor=payload.vendor)
        csv_content = generate_dead_rules_csv(results)
        logger.info(f"Dead rules CSV report generated: {len(csv_content)} bytes")
        RequestLogger.log_request(
            "POST", DEAD_RULES_REPORT_ENDPOINT, 200,
            details={"dead_rules_found": results.get("dead_rules_count", 0)},
        )
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=dead_rules_report.csv"},
        )
    except Exception as e:
        logger.error(f"Error generating dead rules CSV report: {e}", exc_info=True)
        RequestLogger.log_error("POST", DEAD_RULES_REPORT_ENDPOINT, str(e), 500)
        raise