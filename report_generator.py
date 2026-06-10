import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


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
    return _rows_to_csv(rows, AUDIT_COLUMNS)


def generate_dead_rules_csv(analysis_results: Dict[str, Any]) -> str:
    """
    Build a CSV report from rule_checker.detect_dead_rules output.

    The CSV includes one row per dead-rule finding.
    """
    dead_rules = analysis_results.get("dead_rules", []) or []
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
    return _rows_to_csv(rows, DEAD_RULE_COLUMNS)


def write_csv_report(csv_content: str, output_path: str) -> str:
    """Persist CSV content and return the absolute output path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(csv_content, encoding="utf-8", newline="")
    return str(path.resolve())


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
    normalized = (report_type or "").strip().lower()
    if normalized == "audit":
        csv_content = generate_audit_csv(data)
    elif normalized in {"dead_rules", "dead-rules", "deadrules"}:
        csv_content = generate_dead_rules_csv(data)
    else:
        raise ValueError("Unsupported report_type. Use 'audit' or 'dead_rules'.")

    if output_path:
        write_csv_report(csv_content, output_path)
    return csv_content
