import csv
import json
from io import StringIO
from typing import List
from logger import get_logger

logger = get_logger(__name__)

SUPPORTED_EXTENSIONS = {".csv", ".json", ".txt"}
_PARSER_BY_EXTENSION = {
    ".txt": "_parse_txt",
    ".csv": "_parse_csv",
    ".json": "_parse_json",
}


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
    logger.info(f"Processing uploaded file: {filename} ({len(content)} bytes)")
    lower = filename.lower()
    
    try:
        extension = next((ext for ext in SUPPORTED_EXTENSIONS if lower.endswith(ext)), None)
        if extension is None:
            error_msg = (
                f"Unsupported file type '{filename}'. Allowed extensions: "
                + ", ".join(sorted(SUPPORTED_EXTENSIONS))
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

        parser_name = _PARSER_BY_EXTENSION[extension]
        logger.debug(f"Parsing as {extension.upper()} file: {filename}")
        rules = globals()[parser_name](content)
        
        logger.info(f"Successfully extracted {len(rules)} rules from {filename}")
        return rules
    except Exception as e:
        logger.error(f"Error processing file {filename}: {e}", exc_info=True)
        raise


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
        rules = [line.rstrip() for line in text.splitlines() if line.strip()]
        logger.debug(f"TXT parsing: extracted {len(rules)} rules from {len(text)} characters")
        return rules
    except Exception as exc:
        logger.error(f"TXT parsing error: {exc}", exc_info=True)
        raise ValueError(f"TXT parsing error: {exc}") from exc


def _parse_csv(content: bytes) -> List[str]:
    try:
        text = _decode(content)
        reader = csv.DictReader(StringIO(text))
        if reader.fieldnames is None:
            logger.error("CSV parsing: no header row found")
            raise ValueError("CSV file has no header row.")
        
        logger.debug(f"CSV parsing: found columns {reader.fieldnames}")
        
        # Locate the rule column (case-insensitive)
        rule_col = next(
            (f for f in reader.fieldnames if f.strip().lower() == "rule"), None
        )
        
        if rule_col:
            logger.debug(f"CSV parsing: using column '{rule_col}' for rules")
        else:
            logger.debug(f"CSV parsing: 'rule' column not found, using first column")
        
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
        
        logger.debug(f"CSV parsing: extracted {len(rules)} rules")
        return rules
    except ValueError:
        raise
    except Exception as exc:
        logger.error(f"CSV parsing error: {exc}", exc_info=True)
        raise ValueError(f"CSV parsing error: {exc}") from exc


def _parse_json(content: bytes) -> List[str]:
    try:
        text = _decode(content)
        data = json.loads(text)
        if not isinstance(data, list):
            logger.error("JSON parsing: top-level element is not an array")
            raise ValueError("JSON file must contain a top-level array of rules.")
        
        logger.debug(f"JSON parsing: found {len(data)} elements")
        rules: List[str] = []
        for i, item in enumerate(data):
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
        
        logger.debug(f"JSON parsing: extracted {len(rules)} rules")
        return rules
    except (ValueError, json.JSONDecodeError) as exc:
        logger.error(f"JSON parsing error: {exc}", exc_info=True)
        raise ValueError(f"JSON parsing error: {exc}") from exc
    except Exception as exc:
        logger.error(f"JSON parsing error: {exc}", exc_info=True)
        raise ValueError(f"JSON parsing error: {exc}") from exc
