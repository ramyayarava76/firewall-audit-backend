import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from logger import get_logger

logger = get_logger(__name__)


AUDIT_COLUMNS = [
    "index",
    "vendor",
    "rule_name",
    "acl_name",
    "action",
    "protocol",
    "source",
    "destination",
    "application",
    "service",
    "port",
    "error",
    "raw",
    "extracted_ips",
    "extracted_ports",
    "extracted_protocols",
]

DEAD_RULE_COLUMNS = [
    "index",
    "reason",
    "rule_name",
    "error",
    "missing_fields",
    "duplicate_of",
    "shadowed_by",
    "note",
    "rule",
]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return str(value)


def _rows_to_csv(rows: Iterable[Dict[str, Any]], columns: List[str]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: _text(row.get(column)) for column in columns})
    return output.getvalue()


def generate_audit_csv(parsed_rules: List[Dict[str, Any]]) -> str:
    """
    Build a CSV report from parsed firewall rules returned by parser.parse_rules.

    Each row contains rule metadata plus extracted objects (IPs, ports, protocols).
    """
    logger.info(f"Generating audit CSV report for {len(parsed_rules)} rules")
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(parsed_rules):
        extracted = item.get("extracted", {}) or {}
        rows.append(
            {
                "index": index,
                "vendor": item.get("vendor"),
                "rule_name": item.get("rule_name"),
                "acl_name": item.get("acl_name"),
                "action": item.get("action"),
                "protocol": item.get("protocol"),
                "source": item.get("source"),
                "destination": item.get("destination"),
                "application": item.get("application"),
                "service": item.get("service"),
                "port": item.get("port"),
                "error": item.get("error"),
                "raw": item.get("raw"),
                "extracted_ips": extracted.get("ips", []),
                "extracted_ports": extracted.get("ports", []),
                "extracted_protocols": extracted.get("protocols", []),
            }
        )
    csv_content = _rows_to_csv(rows, AUDIT_COLUMNS)
    logger.debug(f"Generated audit CSV: {len(csv_content)} bytes")
    return csv_content


def generate_dead_rules_csv(analysis_results: Dict[str, Any]) -> str:
    """
    Build a CSV report from rule_checker.detect_dead_rules output.

    The CSV includes one row per dead-rule finding.
    """
    dead_rules = analysis_results.get("dead_rules", []) or []
    logger.info(f"Generating dead rules CSV report for {len(dead_rules)} dead rules")
    rows: List[Dict[str, Any]] = []
    for item in dead_rules:
        rows.append(
            {
                "index": item.get("index"),
                "reason": item.get("reason"),
                "rule_name": item.get("rule_name"),
                "error": item.get("error"),
                "missing_fields": item.get("missing_fields"),
                "duplicate_of": item.get("duplicate_of"),
                "shadowed_by": item.get("shadowed_by"),
                "note": item.get("note"),
                "rule": item.get("rule"),
            }
        )
    csv_content = _rows_to_csv(rows, DEAD_RULE_COLUMNS)
    logger.debug(f"Generated dead rules CSV: {len(csv_content)} bytes")
    return csv_content


def write_csv_report(csv_content: str, output_path: str) -> str:
    """Persist CSV content and return the absolute output path."""
    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(csv_content, encoding="utf-8", newline="")
        logger.info(f"CSV report written to {path.resolve()}")
        return str(path.resolve())
    except Exception as e:
        logger.error(f"Error writing CSV report to {output_path}: {e}", exc_info=True)
        raise


def generate_and_save_audit_csv(parsed_rules: List[Dict[str, Any]], output_path: str) -> str:
    """Generate an audit CSV report and save it to disk."""
    csv_content = generate_audit_csv(parsed_rules)
    return write_csv_report(csv_content, output_path)


def generate_and_save_dead_rules_csv(analysis_results: Dict[str, Any], output_path: str) -> str:
    """Generate a dead-rules CSV report and save it to disk."""
    csv_content = generate_dead_rules_csv(analysis_results)
    return write_csv_report(csv_content, output_path)


def generate_csv_report(report_type: str, data: Any, output_path: Optional[str] = None) -> str:
    """
    Generic CSV entrypoint.

    report_type:
      - "audit": data must be List[Dict[str, Any]] from parse_rules
      - "dead_rules": data must be Dict[str, Any] from detect_dead_rules
    """
    logger.info(f"Generating {report_type} CSV report")
    normalized = (report_type or "").strip().lower()
    try:
        if normalized == "audit":
            csv_content = generate_audit_csv(data)
        elif normalized in {"dead_rules", "dead-rules", "deadrules"}:
            csv_content = generate_dead_rules_csv(data)
        else:
            logger.error(f"Unsupported report_type: {report_type}")
            raise ValueError("Unsupported report_type. Use 'audit' or 'dead_rules'.")

        if output_path:
            write_csv_report(csv_content, output_path)
        
        logger.info(f"Successfully generated {report_type} CSV report")
        return csv_content
    except Exception as e:
        logger.error(f"Error generating {report_type} report: {e}", exc_info=True)
        raise
