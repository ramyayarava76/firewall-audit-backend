import csv
import json
from io import StringIO
from typing import List


SUPPORTED_EXTENSIONS = {".csv", ".json", ".txt"}


def handle_uploaded_file(filename: str, content: bytes) -> List[str]:
    """
    Parse an uploaded firewall config file and return a flat list of rule strings
    suitable for passing to ``parse_rules``.

    Supported formats:
    - ``.txt`` — one rule per non-blank line
    - ``.csv`` — reads the column named ``rule`` (case-insensitive); falls back
                  to the first column when no such column exists
    - ``.json`` — accepts a JSON array of strings **or** an array of objects
                   that contain a ``rule`` key
    """
    lower = filename.lower()
    if lower.endswith(".txt"):
        return _parse_txt(content)
    if lower.endswith(".csv"):
        return _parse_csv(content)
    if lower.endswith(".json"):
        return _parse_json(content)
    raise ValueError(
        f"Unsupported file type '{filename}'. Allowed extensions: "
        + ", ".join(sorted(SUPPORTED_EXTENSIONS))
    )


def _decode(content: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError("Unable to decode file content — unsupported character encoding.")


def _parse_txt(content: bytes) -> List[str]:
    try:
        text = _decode(content)
        return [line.rstrip() for line in text.splitlines() if line.strip()]
    except Exception as exc:
        raise ValueError(f"TXT parsing error: {exc}") from exc


def _parse_csv(content: bytes) -> List[str]:
    try:
        text = _decode(content)
        reader = csv.DictReader(StringIO(text))
        if reader.fieldnames is None:
            raise ValueError("CSV file has no header row.")
        # Locate the rule column (case-insensitive)
        rule_col = next(
            (f for f in reader.fieldnames if f.strip().lower() == "rule"), None
        )
        rules: List[str] = []
        for row in reader:
            if rule_col:
                value = row.get(rule_col, "").strip()
            else:
                # Fall back to the first column
                first_key = reader.fieldnames[0]
                value = row.get(first_key, "").strip()
            if value:
                rules.append(value)
        return rules
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"CSV parsing error: {exc}") from exc


def _parse_json(content: bytes) -> List[str]:
    try:
        text = _decode(content)
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("JSON file must contain a top-level array of rules.")
        rules: List[str] = []
        for item in data:
            if isinstance(item, str):
                if item.strip():
                    rules.append(item.strip())
            elif isinstance(item, dict):
                # Accept a 'rule' key or fall back to the first string value
                value = item.get("rule") or item.get("Rule") or ""
                if not value:
                    # Try first string value in the dict
                    value = next((v for v in item.values() if isinstance(v, str)), "")
                if isinstance(value, str) and value.strip():
                    rules.append(value.strip())
            else:
                raise ValueError(
                    f"Each JSON element must be a string or an object with a 'rule' key; got {type(item).__name__}."
                )
        return rules
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"JSON parsing error: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"JSON parsing error: {exc}") from exc
