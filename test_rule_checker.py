"""
test_rule_checker.py - Test script for dead rule detection

Run this script to test the dead rule checker functionality.
"""

from rule_checker import detect_dead_rules, print_dead_rules_report, DeadRuleDetector
from parser import parse_rules


def test_dead_rule_detection():
    """Test various types of dead rules."""
    
    # Create diverse test cases
    test_cases = {
        "Cisco ACL Tests": [
            "access-list OUTSIDE-IN extended permit tcp any host 10.0.0.10 eq 443",
            "access-list OUTSIDE-IN extended permit tcp any host 10.0.0.10 eq 443",  # Duplicate
            "access-list OUTSIDE-IN extended permit tcp any any",  # Catch-all
            "access-list OUTSIDE-IN extended deny tcp any host 10.0.0.10 eq 443",  # Shadowed by catch-all
        ],
        "Palo Alto Tests": [
            "rule=AllowWeb src=192.168.1.0 dst=10.0.0.0 action=allow service=http",
            "rule=AllowWeb src=192.168.1.0 dst=10.0.0.0 action=allow service=http",  # Duplicate
            "rule=AllowSSH src=any dst=any action=allow service=ssh",  # Incomplete (no protocol)
            "rule=DenyAll src=any dst=any action=deny",  # Catch-all deny
        ],
        "Mixed/Error Cases": [
            "",  # Empty
            "invalid rule format",  # Parse error
            "rule=Incomplete src=192.168.1.0 dst=10.0.0.0",  # Missing action
        ]
    }

    for test_name, rules in test_cases.items():
        print(f"\n{'='*80}")
        print(f"Testing: {test_name}")
        print(f"{'='*80}")
        
        results = detect_dead_rules(rules)
        
        print(f"Total rules: {results['total_rules']}")
        print(f"Dead rules found: {results['dead_rules_count']}")
        
        if results['dead_rules']:
            print("\nDead Rules Details:")
            for dead_rule in results['dead_rules']:
                print(f"  [{dead_rule['index']}] {dead_rule['reason']}")
                if 'missing_fields' in dead_rule:
                    print(f"      Missing: {', '.join(dead_rule['missing_fields'])}")
                if 'duplicate_of' in dead_rule:
                    print(f"      Duplicate of rule index: {dead_rule['duplicate_of']}")


def test_api_response_format():
    """Test the API response format for check-dead-rules endpoint."""
    print(f"\n{'='*80}")
    print("Testing API Response Format")
    print(f"{'='*80}\n")
    
    # Simulate API request
    rules = [
        "access-list ACL1 extended permit tcp any any",
        "access-list ACL1 extended permit tcp any any",  # Duplicate
        "access-list ACL1 extended permit tcp 192.168.1.0 host 10.0.0.10 eq 443",  # Shadowed
    ]
    
    results = detect_dead_rules(rules, vendor="cisco")
    
    # Format as API would return it
    api_response = {
        "status": "success",
        "data": {
            "requested_vendor": "cisco",
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
    
    # Pretty print
    import json
    print("API Response Preview:")
    print(json.dumps(api_response, indent=2, default=str))


def test_edge_cases():
    """Test edge cases and boundary conditions."""
    print(f"\n{'='*80}")
    print("Testing Edge Cases")
    print(f"{'='*80}\n")
    
    edge_cases = [
        ([], "Empty rule list"),
        ([""] * 5, "Multiple empty rules"),
        (["rule=" + str(i) for i in range(100)], "Large number of incomplete rules"),
    ]
    
    for rules, description in edge_cases:
        print(f"Test: {description}")
        results = detect_dead_rules(rules)
        print(f"  Result: {results['dead_rules_count']} dead rules found\n")


if __name__ == "__main__":
    print("=" * 80)
    print("DEAD RULE DETECTION - TEST SUITE")
    print("=" * 80)
    
    test_dead_rule_detection()
    test_api_response_format()
    test_edge_cases()
    
    print(f"\n{'='*80}")
    print("All tests completed!")
    print(f"{'='*80}\n")
