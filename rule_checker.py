"""
rule_checker.py

Detects "dead rules" in firewall configurations:
- Unreferenced rules (not used by other rules)
- Redundant rules (duplicate or shadowed by others)
- Incomplete rules (missing critical fields)
- Ineffective rules (e.g., rules with "any" source/dest that don't match patterns)
- Shadowed rules in ACL (rules that will never be reached)
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from parser import parse_rules


class DeadRuleDetector:
    """Analyzes parsed firewall rules to identify dead/ineffective rules."""

    def __init__(self, parsed_rules: List[Dict[str, Any]]):
        """Initialize with a list of parsed firewall rules."""
        self.rules = parsed_rules
        self.dead_rules: List[Dict[str, Any]] = []
        self._seen_findings: Set[Tuple[int, str]] = set()
        self.rule_references: Dict[str, Set[str]] = defaultdict(set)
        self.redundant_groups: List[List[int]] = []
        self.analysis_results: Dict[str, Any] = {}

    def _add_dead_rule(self, entry: Dict[str, Any]) -> None:
        """Add a dead-rule finding once per (index, reason) pair."""
        key = (entry.get("index", -1), entry.get("reason", ""))
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        self.dead_rules.append(entry)

    def run_analysis(self) -> Dict[str, Any]:
        """Run comprehensive dead rule detection."""
        self._identify_incomplete_rules()
        self._identify_redundant_rules()
        self._identify_shadowed_rules()
        self._identify_unreferenced_rules()
        self._identify_ineffective_rules()

        self.analysis_results = {
            "total_rules": len(self.rules),
            "dead_rules_count": len(self.dead_rules),
            "dead_rules": self.dead_rules,
            "redundant_groups": self.redundant_groups,
            "rule_references": dict(self.rule_references),
        }
        return self.analysis_results

    def _identify_incomplete_rules(self) -> None:
        """Identify rules missing critical fields."""
        for idx, rule in enumerate(self.rules):
            if rule.get("error"):
                self._add_dead_rule({
                    "index": idx,
                    "reason": "Parse error",
                    "error": rule.get("error"),
                    "rule": rule.get("raw", ""),
                })
                continue

            vendor = rule.get("vendor")
            critical_fields = {"action", "source", "destination", "protocol"}
            if vendor == "palo_alto":
                # Palo Alto rules are often app/service-centric and may omit protocol.
                critical_fields = {"action", "source", "destination"}

            missing_fields = []
            for field in critical_fields:
                if not rule.get(field):
                    missing_fields.append(field)

            if vendor == "palo_alto" and not any(
                rule.get(field) for field in ("protocol", "service", "application")
            ):
                missing_fields.append("protocol_or_service")

            if missing_fields and rule.get("vendor") != "unknown":
                self._add_dead_rule({
                    "index": idx,
                    "reason": "Incomplete rule",
                    "missing_fields": missing_fields,
                    "rule_name": rule.get("rule_name") or rule.get("acl_name"),
                    "rule": rule.get("raw", ""),
                })

    def _identify_redundant_rules(self) -> None:
        """Identify duplicate or functionally equivalent rules."""
        rule_signatures: Dict[str, List[int]] = defaultdict(list)

        for idx, rule in enumerate(self.rules):
            if rule.get("error") or rule.get("vendor") == "unknown":
                continue

            # Create a signature for the rule
            vendor = rule.get("vendor")
            action = rule.get("action", "")
            source = rule.get("source", "") or rule.get("src", "")
            destination = rule.get("destination", "") or rule.get("dst", "")
            protocol = rule.get("protocol", "")
            port = rule.get("port", "") or rule.get("service", "")
            application = rule.get("application", "")

            signature = f"{vendor}:{action}:{source}:{destination}:{protocol}:{port}:{application}"
            rule_signatures[signature].append(idx)

        # Group rules with identical signatures
        for signature, indices in rule_signatures.items():
            if len(indices) > 1:
                self.redundant_groups.append(indices)
                # Mark all but the first as redundant
                for idx in indices[1:]:
                    self._add_dead_rule({
                        "index": idx,
                        "reason": "Redundant rule",
                        "duplicate_of": indices[0],
                        "rule_name": self.rules[idx].get("rule_name") or self.rules[idx].get("acl_name"),
                        "rule": self.rules[idx].get("raw", ""),
                    })

    def _identify_shadowed_rules(self) -> None:
        """
        Identify Cisco ACL rules that are shadowed (unreachable) due to
        prior rules with broader match criteria.
        """
        for vendor_type in ["cisco", "palo_alto"]:
            vendor_indices = [
                i for i, rule in enumerate(self.rules)
                if rule.get("vendor") == vendor_type and not rule.get("error")
            ]

            if vendor_type == "cisco":
                self._detect_shadowed_acl_rules(vendor_indices)

    def _detect_shadowed_acl_rules(self, acl_indices: List[int]) -> None:
        """Detect shadowed rules in Cisco ACL order."""
        for i in range(len(acl_indices)):
            current_rule = self.rules[acl_indices[i]]

            if self._is_any_rule(current_rule):
                # Any rule shadows all subsequent rules in the same ACL
                acl_name = current_rule.get("acl_name")
                for j in range(i + 1, len(acl_indices)):
                    next_rule = self.rules[acl_indices[j]]
                    if (next_rule.get("acl_name") == acl_name
                            and self._rules_overlap(current_rule, next_rule)):
                        self._add_dead_rule({
                            "index": acl_indices[j],
                            "reason": "Shadowed by earlier rule",
                            "shadowed_by": acl_indices[i],
                            "rule_name": next_rule.get("acl_name"),
                            "rule": next_rule.get("raw", ""),
                        })

    def _identify_unreferenced_rules(self) -> None:
        """
        Identify rules that are never referenced by other rules or policies.
        (In a simple analysis, we look for rules with specific naming patterns
        that suggest they should be referenced elsewhere.)
        """
        rule_names: Set[str] = set()
        referenced_names: Set[str] = set()

        # Collect all rule names
        for rule in self.rules:
            rule_name = rule.get("rule_name") or rule.get("acl_name")
            if rule_name:
                rule_names.add(rule_name)

        # Collect all references (in raw text, service names, etc.)
        for rule in self.rules:
            raw = rule.get("raw", "").lower()
            rule_name = rule.get("rule_name") or rule.get("acl_name") or ""
            for name in rule_names:
                if name and name.lower() != rule_name.lower():
                    if name.lower() in raw:
                        referenced_names.add(name)

        # Identify unreferenced rules with naming conventions suggesting they should be referenced
        unreferenced = rule_names - referenced_names
        for idx, rule in enumerate(self.rules):
            rule_name = rule.get("rule_name") or rule.get("acl_name")
            if rule_name in unreferenced:
                # Only flag if it looks like it should be referenced (e.g., has underscore, starts with certain patterns)
                if self._looks_like_referenced_rule(rule_name):
                    self._add_dead_rule({
                        "index": idx,
                        "reason": "Potentially unreferenced rule",
                        "rule_name": rule_name,
                        "note": "Rule may not be called by any policy",
                        "rule": rule.get("raw", ""),
                    })

    def _identify_ineffective_rules(self) -> None:
        """Identify rules that have very broad match criteria and may be ineffective."""
        for idx, rule in enumerate(self.rules):
            if rule.get("error"):
                continue

            # Rule matching any source AND any destination AND any protocol is suspicious
            if (self._is_match_any(rule.get("source"))
                    and self._is_match_any(rule.get("destination"))
                    and self._is_protocol_any(rule.get("protocol"))
                    and not any(rule.get(field) for field in ("port", "service", "application"))):
                # This is a catch-all rule; flag it as potentially ineffective
                # unless it has a specific action
                action = rule.get("action", "").lower()
                if action in {"allow", "permit"}:
                    self._add_dead_rule({
                        "index": idx,
                        "reason": "Ineffective catch-all rule",
                        "note": "Rule permits all traffic; may indicate incomplete configuration",
                        "rule_name": rule.get("rule_name") or rule.get("acl_name"),
                        "rule": rule.get("raw", ""),
                    })

    def _is_match_any(self, value: Optional[str]) -> bool:
        """Check if a value represents 'any' in firewall terms."""
        if not value:
            return False
        return value.lower() in {"any", "*", "0.0.0.0/0", "::/0"}

    def _is_protocol_any(self, value: Optional[str]) -> bool:
        """Treat missing protocol, 'any', and Cisco 'ip' as match-any protocol."""
        if not value:
            return True
        return value.lower() in {"any", "ip"}

    def _is_any_rule(self, rule: Dict[str, Any]) -> bool:
        """Check if a rule matches any source/destination/protocol."""
        return (self._is_match_any(rule.get("source")) and
                self._is_match_any(rule.get("destination")))

    def _rules_overlap(self, rule1: Dict[str, Any], rule2: Dict[str, Any]) -> bool:
        """Check if two rules have overlapping match criteria."""
        # Simplified overlap check
        src1 = rule1.get("source", "").lower()
        src2 = rule2.get("source", "").lower()
        dst1 = rule1.get("destination", "").lower()
        dst2 = rule2.get("destination", "").lower()
        proto1 = (rule1.get("protocol") or "").lower()
        proto2 = (rule2.get("protocol") or "").lower()
        port1 = (rule1.get("port") or rule1.get("service") or "").lower()
        port2 = (rule2.get("port") or rule2.get("service") or "").lower()

        # An earlier rule only shadows protocol-specific traffic when protocol scopes overlap.
        if not self._is_protocol_any(proto1) and proto1 != proto2:
            return False

        # If earlier rule is port-scoped, it can only shadow overlapping ports.
        if not self._ports_overlap(port1, port2):
            return False

        # If both are "any" or identical, they overlap
        if src1 == src2 and dst1 == dst2:
            return True
        # If rule1 is "any", it overlaps with rule2
        if self._is_match_any(src1) and self._is_match_any(dst1):
            return True
        return False

    def _ports_overlap(self, port1: str, port2: str) -> bool:
        """Return True when earlier-rule port scope can match the later rule port scope."""
        if not port1:
            return True
        if not port2:
            return False
        if port1 == port2:
            return True

        def parse_port_range(value: str) -> Optional[Tuple[int, int]]:
            if "-" in value:
                parts = value.split("-", 1)
                if parts[0].isdigit() and parts[1].isdigit():
                    low, high = int(parts[0]), int(parts[1])
                    return (low, high) if low <= high else None
                return None
            if value.isdigit():
                num = int(value)
                return num, num
            return None

        r1 = parse_port_range(port1)
        r2 = parse_port_range(port2)
        if not r1 or not r2:
            return False
        return r1[0] <= r2[0] and r1[1] >= r2[1]

    def _looks_like_referenced_rule(self, name: str) -> bool:
        """Heuristic to determine if a rule name suggests it should be referenced."""
        patterns = ["policy_", "policy-", "_policy", "-policy", "ref_", "temp_"]
        return any(pattern in name.lower() for pattern in patterns)


def detect_dead_rules(rules: List[str], vendor: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to parse rules and detect dead rules in one call.

    Args:
        rules: List of firewall rule strings
        vendor: Optional vendor name ('palo_alto', 'cisco', etc.)

    Returns:
        Dictionary with analysis results
    """
    parsed_rules = parse_rules(rules, vendor=vendor)
    detector = DeadRuleDetector(parsed_rules)
    return detector.run_analysis()


def print_dead_rules_report(analysis_results: Dict[str, Any]) -> None:
    """Pretty-print the dead rules analysis report."""
    print("\n" + "=" * 80)
    print("DEAD RULES ANALYSIS REPORT")
    print("=" * 80)

    print(f"\nTotal Rules Analyzed: {analysis_results['total_rules']}")
    print(f"Dead Rules Found: {analysis_results['dead_rules_count']}")

    if analysis_results["dead_rules"]:
        print("\n" + "-" * 80)
        print("DEAD RULES:")
        print("-" * 80)
        for dead_rule in analysis_results["dead_rules"]:
            idx = dead_rule["index"]
            reason = dead_rule["reason"]
            rule_name = dead_rule.get("rule_name", "N/A")
            raw = dead_rule.get("rule", "")[:60] + ("..." if len(dead_rule.get("rule", "")) > 60 else "")

            print(f"\n[{idx}] {reason}")
            print(f"    Name: {rule_name}")
            print(f"    Rule: {raw}")

            if "error" in dead_rule:
                print(f"    Error: {dead_rule['error']}")
            if "missing_fields" in dead_rule:
                print(f"    Missing: {', '.join(dead_rule['missing_fields'])}")
            if "duplicate_of" in dead_rule:
                print(f"    Duplicate of rule index: {dead_rule['duplicate_of']}")
            if "shadowed_by" in dead_rule:
                print(f"    Shadowed by rule index: {dead_rule['shadowed_by']}")
            if "note" in dead_rule:
                print(f"    Note: {dead_rule['note']}")

    if analysis_results["redundant_groups"]:
        print("\n" + "-" * 80)
        print("REDUNDANT RULE GROUPS:")
        print("-" * 80)
        for group in analysis_results["redundant_groups"]:
            print(f"  Duplicate rules at indices: {group}")

    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    # Example usage
    example_rules = [
        "access-list OUTSIDE-IN extended permit tcp any host 10.0.0.10 eq 443",
        "access-list OUTSIDE-IN extended permit tcp any host 10.0.0.10 eq 443",  # Duplicate
        "access-list OUTSIDE-IN extended permit tcp any any eq 80",  # Catch-all
        "rule=AllowWeb src=any dst=any action=allow service=http",
        "rule=DenyAll src=any dst=any action=deny",  # Shadows previous if any
        "",  # Empty
        "set rulebase security rules Allow-Web from trust to untrust source any",  # Incomplete
    ]

    results = detect_dead_rules(example_rules)
    print_dead_rules_report(results)
