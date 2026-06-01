import re
from typing import Any, Dict, Iterable, List, Optional, Set


# ---------------------------------------------------------------------------
# Known values
# ---------------------------------------------------------------------------

KNOWN_PROTOCOLS: Set[str] = {
    "tcp", "udp", "icmp", "icmpv6", "esp", "ah", "gre", "ospf",
    "ip", "ipv6", "sctp", "igmp", "pim", "eigrp", "http", "https",
    "ftp", "ssh", "telnet", "dns", "smtp", "snmp", "bgp", "ldap",
}

WELL_KNOWN_PORTS: Dict[str, int] = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53,
    "http": 80, "https": 443, "snmp": 161, "ldap": 389, "smb": 445,
    "rdp": 3389, "mysql": 3306, "mssql": 1433, "oracle": 1521,
    "postgresql": 5432, "redis": 6379, "mongodb": 27017,
}

# Regex patterns
_IPV4_CIDR_PATTERN = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:/\d{1,2})?)\b"
)
_IPV6_PATTERN = re.compile(
    r"\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r"|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:)\b"
)
_PORT_RANGE_PATTERN = re.compile(r"\b(\d{1,5})-(\d{1,5})\b")


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def extract_ips(text: str) -> List[str]:
    """Extract all IPv4 (with optional CIDR) and IPv6 addresses from *text*."""
    ipv4 = _IPV4_CIDR_PATTERN.findall(text)
    ipv6 = _IPV6_PATTERN.findall(text)
    seen: set = set()
    result: List[str] = []
    for ip in ipv4 + ipv6:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def extract_ports(text: str) -> List[str]:
    """
    Extract port numbers and port ranges from *text*.

    Returns strings like ``"443"``, ``"8080-8090"``, or named ports like
    ``"http"`` when they appear as standalone protocol keywords.
    """
    result: List[str] = []
    seen: set = set()

    # Named ports (e.g. "eq http", "service https")
    named_port_pattern = re.compile(
        r"\b(?:eq|port|service|dport|sport)\s+(" + "|".join(WELL_KNOWN_PORTS.keys()) + r")\b",
        re.IGNORECASE,
    )
    for match in named_port_pattern.finditer(text):
        name = match.group(1).lower()
        key = str(WELL_KNOWN_PORTS[name])
        if key not in seen:
            seen.add(key)
            result.append(key)

    # Numeric port ranges  (must come before single-port to avoid double-match)
    for match in _PORT_RANGE_PATTERN.finditer(text):
        low, high = int(match.group(1)), int(match.group(2))
        if 1 <= low <= 65535 and 1 <= high <= 65535 and low < high:
            key = f"{low}-{high}"
            if key not in seen:
                seen.add(key)
                result.append(key)

    # Numeric ports preceded by eq/port/dport/sport/service or a colon
    numeric_port_pattern = re.compile(
        r"(?:eq|port|dport|sport|service|:)\s*(\d{1,5})\b", re.IGNORECASE
    )
    for match in numeric_port_pattern.finditer(text):
        val = int(match.group(1))
        if 1 <= val <= 65535:
            key = str(val)
            if key not in seen:
                seen.add(key)
                result.append(key)

    return result


def extract_protocols(text: str) -> List[str]:
    """Extract recognised protocol names from *text*."""
    found: List[str] = []
    lower = text.lower()
    for proto in sorted(KNOWN_PROTOCOLS):
        if re.search(rf"\b{re.escape(proto)}\b", lower):
            found.append(proto)
    return found


def extract_network_objects(text: str) -> Dict[str, Any]:
    """
    Convenience wrapper that returns IPs, ports, and protocols extracted
    from a raw rule / log line in a single call.
    """
    return {
        "ips": extract_ips(text),
        "ports": extract_ports(text),
        "protocols": extract_protocols(text),
    }


def _clean_value(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _parse_kv_pairs(text: str) -> Dict[str, str]:
    """Parse key=value pairs where value may be quoted."""
    pattern = re.compile(r"(\w+)=((?:\"[^\"]*\")|(?:'[^']*')|[^\s]+)")
    out: Dict[str, str] = {}
    for key, value in pattern.findall(text):
        out[key.lower()] = _clean_value(value)
    return out


def parse_palo_alto_rule(rule_line: str) -> Dict[str, Any]:
    """
    Parse a Palo Alto rule line.

    Supported formats:
    - key=value style log/rule snippets (src=, dst=, action=, service=, app=, rule=)
    - "set rulebase security rules ..." style config lines
    """
    line = rule_line.strip()
    if not line:
        return {"vendor": "palo_alto", "raw": rule_line, "error": "Empty rule line"}

    parsed: Dict[str, Any] = {
        "vendor": "palo_alto",
        "raw": rule_line,
        "rule_name": None,
        "action": None,
        "source": None,
        "destination": None,
        "application": None,
        "service": None,
        "from_zone": None,
        "to_zone": None,
    }

    kv = _parse_kv_pairs(line)
    if kv:
        parsed["rule_name"] = kv.get("rule") or kv.get("rulename") or kv.get("name")
        parsed["action"] = kv.get("action")
        parsed["source"] = kv.get("src") or kv.get("source")
        parsed["destination"] = kv.get("dst") or kv.get("destination")
        parsed["application"] = kv.get("app") or kv.get("application")
        parsed["service"] = kv.get("service")
        parsed["from_zone"] = kv.get("from")
        parsed["to_zone"] = kv.get("to")
        return parsed

    # Example:
    # set rulebase security rules Allow-Web from trust to untrust source any
    # destination any application web-browsing service application-default action allow
    set_pattern = re.compile(
        r"set\s+rulebase\s+security\s+rules\s+(?P<name>\S+)\s+"
        r"from\s+(?P<from_zone>\S+)\s+to\s+(?P<to_zone>\S+)\s+"
        r"source\s+(?P<source>\S+)\s+destination\s+(?P<destination>\S+)\s+"
        r"application\s+(?P<application>\S+)\s+service\s+(?P<service>\S+)\s+"
        r"action\s+(?P<action>\S+)",
        re.IGNORECASE,
    )
    match = set_pattern.search(line)
    if match:
        parsed.update({
            "rule_name": match.group("name"),
            "from_zone": match.group("from_zone"),
            "to_zone": match.group("to_zone"),
            "source": match.group("source"),
            "destination": match.group("destination"),
            "application": match.group("application"),
            "service": match.group("service"),
            "action": match.group("action"),
        })
        return parsed

    parsed["error"] = "Could not parse Palo Alto rule format"
    return parsed


def parse_cisco_rule(rule_line: str) -> Dict[str, Any]:
    """
    Parse a Cisco ACL rule line.

    Supported format example:
    access-list OUTSIDE-IN extended permit tcp any host 10.0.0.10 eq 443 log
    """
    line = rule_line.strip()
    if not line:
        return {"vendor": "cisco", "raw": rule_line, "error": "Empty rule line"}

    parsed: Dict[str, Any] = {
        "vendor": "cisco",
        "raw": rule_line,
        "acl_name": None,
        "action": None,
        "protocol": None,
        "source": None,
        "destination": None,
        "port": None,
    }

    # Remove leading sequence number if present, e.g. "10 permit tcp ..."
    line = re.sub(r"^\d+\s+", "", line)

    tokens = line.split()
    if not tokens:
        parsed["error"] = "Empty rule tokens"
        return parsed

    if tokens[0].lower() == "access-list":
        # Normalize into ACL body:
        # access-list <name> [line <n>] extended|standard <rule...>
        if len(tokens) >= 2:
            parsed["acl_name"] = tokens[1]
        if "extended" in [t.lower() for t in tokens]:
            idx = [t.lower() for t in tokens].index("extended") + 1
            tokens = tokens[idx:]
        elif "standard" in [t.lower() for t in tokens]:
            idx = [t.lower() for t in tokens].index("standard") + 1
            tokens = tokens[idx:]
        else:
            # fallback: drop "access-list <name>"
            tokens = tokens[2:]

    if len(tokens) < 3:
        parsed["error"] = "Insufficient tokens for Cisco ACL rule"
        return parsed

    parsed["action"] = tokens[0].lower()
    parsed["protocol"] = tokens[1].lower()

    def read_endpoint(start: int) -> tuple[str, int]:
        if start >= len(tokens):
            return "", start

        t = tokens[start].lower()
        if t == "any":
            return "any", start + 1
        if t == "host" and start + 1 < len(tokens):
            return tokens[start + 1], start + 2
        if start + 1 < len(tokens):
            # network + wildcard mask
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", tokens[start]) and re.match(
                r"^\d{1,3}(?:\.\d{1,3}){3}$", tokens[start + 1]
            ):
                return f"{tokens[start]} {tokens[start + 1]}", start + 2
        return tokens[start], start + 1

    idx = 2
    src, idx = read_endpoint(idx)
    dst, idx = read_endpoint(idx)
    parsed["source"] = src
    parsed["destination"] = dst

    # Optional destination operator/port section
    if idx < len(tokens) and tokens[idx].lower() in {"eq", "neq", "lt", "gt", "range"}:
        op = tokens[idx].lower()
        if op == "range" and idx + 2 < len(tokens):
            parsed["port"] = f"{tokens[idx + 1]}-{tokens[idx + 2]}"
        elif idx + 1 < len(tokens):
            parsed["port"] = tokens[idx + 1]

    return parsed


def detect_vendor(rule_line: str) -> Optional[str]:
    line = rule_line.strip().lower()
    if not line:
        return None
    if "rulebase security rules" in line or " app=" in f" {line}" or " src=" in f" {line}":
        return "palo_alto"
    if line.startswith("access-list") or re.match(r"^\d+\s+(permit|deny)\s+", line):
        return "cisco"
    return None


def parse_rule(rule_line: str, vendor: Optional[str] = None) -> Dict[str, Any]:
    chosen_vendor = (vendor or detect_vendor(rule_line) or "unknown").lower()

    if chosen_vendor in {"palo", "paloalto", "palo_alto", "pan"}:
        result = parse_palo_alto_rule(rule_line)
    elif chosen_vendor in {"cisco", "asa", "ios"}:
        result = parse_cisco_rule(rule_line)
    else:
        result = {
            "vendor": "unknown",
            "raw": rule_line,
            "error": "Could not determine vendor. Pass vendor='palo_alto' or vendor='cisco'.",
        }

    # Attach extracted network objects (IPs, ports, protocols) to every result
    result["extracted"] = extract_network_objects(rule_line)
    return result


def parse_rules(rule_lines: Iterable[str], vendor: Optional[str] = None) -> List[Dict[str, Any]]:
    return [parse_rule(line, vendor=vendor) for line in rule_lines if line is not None]
