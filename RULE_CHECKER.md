# Rule Checker Documentation

## Overview
The `rule_checker.py` module provides comprehensive detection of "dead rules" in firewall configurations. Dead rules are rules that are ineffective, unreachable, redundant, or incomplete.

## Types of Dead Rules Detected

### 1. Parse Errors
**Description:** Rules that fail to parse correctly.
**Example:** Invalid syntax or unrecognized vendor format.
**Impact:** High - Rule is not functional.

### 2. Incomplete Rules
**Description:** Rules missing critical fields required for evaluation.
**Critical fields:** `action`, `source`, `destination`, `protocol`
**Example:** Palo Alto rule without `destination` field.
**Impact:** Medium - Rule may not behave as expected.

### 3. Redundant Rules
**Description:** Exact duplicate rules with identical match criteria and actions.
**Detection Method:** Signature-based comparison across all rule attributes.
**Example:**
```
Rule A: permit tcp any host 10.0.0.10 eq 443
Rule B: permit tcp any host 10.0.0.10 eq 443  # Duplicate
```
**Impact:** Low - Wastes resources but doesn't cause failures.

### 4. Shadowed Rules (Cisco ACL)
**Description:** Rules that can never be reached due to earlier rules with broader match criteria.
**Detection Logic:** Rules following "any" rules with matching ACL name.
**Example:**
```
10 permit tcp any any                    # Catches all TCP
20 permit tcp any host 10.0.0.10 eq 443  # Unreachable - shadowed by line 10
```
**Impact:** High - Rule has no effect.

### 5. Unreferenced Rules
**Description:** Rules with naming conventions suggesting they should be referenced but aren't called by any policy.
**Detection Pattern:** Names containing `policy_`, `policy-`, `_policy`, `ref_`, `temp_`.
**Impact:** Medium - May indicate incomplete configuration or cleanup needed.

### 6. Ineffective Rules
**Description:** Catch-all rules matching any source/destination/protocol that may indicate incomplete configuration.
**Example:**
```
src=any dst=any action=allow  # Permits all traffic - suspicious
```
**Impact:** Medium - May be a placeholder or security risk.

## Usage

### Basic Usage
```python
from rule_checker import detect_dead_rules, print_dead_rules_report

rules = [
    "access-list ACL1 extended permit tcp any host 10.0.0.10 eq 443",
    "access-list ACL1 extended permit tcp any host 10.0.0.10 eq 443",  # Duplicate
]

results = detect_dead_rules(rules)
print_dead_rules_report(results)
```

### Advanced Usage - Custom Analysis
```python
from rule_checker import DeadRuleDetector
from parser import parse_rules

rules_text = ["rule line 1", "rule line 2"]
parsed = parse_rules(rules_text, vendor="cisco")
detector = DeadRuleDetector(parsed)
results = detector.run_analysis()

# Access specific analysis results
print(f"Found {results['dead_rules_count']} dead rules")
for dead_rule in results['dead_rules']:
    print(f"Index {dead_rule['index']}: {dead_rule['reason']}")
```

## Output Format

### Analysis Results Dictionary
```python
{
    "total_rules": 10,
    "dead_rules_count": 3,
    "dead_rules": [
        {
            "index": 1,
            "reason": "Redundant rule",
            "duplicate_of": 0,
            "rule_name": "ACL1",
            "rule": "access-list ACL1 extended permit tcp..."
        },
        {
            "index": 5,
            "reason": "Incomplete rule",
            "missing_fields": ["protocol"],
            "rule_name": "AllowWeb",
            "rule": "rule=AllowWeb src=any dst=any action=allow"
        },
        {
            "index": 8,
            "reason": "Shadowed by earlier rule",
            "shadowed_by": 7,
            "rule_name": "ACL1",
            "rule": "20 permit tcp any host 10.0.0.10 eq 443"
        }
    ],
    "redundant_groups": [[0, 1], [5, 6]],
    "rule_references": {"AllowWeb": set(), "DenyAll": set()}
}
```

## Integration with Audit API

To integrate with the existing `/audit` endpoint, you can:

### Option 1: Separate Endpoint
```python
# In audit.py
@router.post("/audit/check-dead-rules")
async def check_dead_rules(payload: AuditRequest) -> Dict[str, Any]:
    from rule_checker import detect_dead_rules
    results = detect_dead_rules(payload.rules, vendor=payload.vendor)
    return {
        "status": "success",
        "data": results
    }
```

### Option 2: Integrated Analysis
```python
# Extend existing audit summary
def _build_summary(parsed_rules):
    # ... existing code ...
    
    # Add dead rule detection
    from rule_checker import DeadRuleDetector
    detector = DeadRuleDetector(parsed_rules)
    dead_rules = detector.run_analysis()
    
    return {
        # ... existing fields ...
        "dead_rules_analysis": dead_rules
    }
```

## Limitations & Future Improvements

### Current Limitations:
1. Unreferenced detection is heuristic-based (naming patterns)
2. Shadowed rule detection only supports Cisco ACL currently
3. No policy-to-rule reference graph analysis
4. No temporal analysis (rules modified/last used)

### Future Enhancements:
1. Parse policy definitions to detect actual rule references
2. Implement firewall state machine for more accurate shadowing detection
3. Add protocol-specific range overlap detection
4. Support for more vendors (FortiGate, etc.)
5. Statistical analysis (rule hit counts, traffic analysis)
6. Automatic rule consolidation suggestions
7. Historical tracking of dead rules over time

## Performance Considerations

- **Time Complexity:** O(n²) for redundancy detection (signature comparison)
- **Space Complexity:** O(n) for rule storage and analysis results
- **Scalability:** Handles 1000+ rules efficiently

For very large rulesets (10,000+ rules):
- Consider batch processing
- Use incremental analysis
- Cache signatures for repeated runs

## API Examples

### cURL Example
```bash
curl -X POST http://localhost:8000/api/v1/audit/check-dead-rules \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [
      "access-list ACL1 extended permit tcp any any",
      "access-list ACL1 extended permit tcp any any"
    ],
    "vendor": "cisco"
  }'
```

### Python Requests Example
```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/audit/check-dead-rules",
    json={
        "rules": [
            "rule=AllowWeb src=any dst=any action=allow",
            "rule=AllowWeb src=any dst=any action=allow"
        ],
        "vendor": "palo_alto"
    }
)
print(response.json())
```

## Testing

Run the built-in test:
```bash
python rule_checker.py
```

This will analyze the example rules in the `__main__` block and print a formatted report.

## References

- [Firewall Audit Backend](README.md)
- [Parser Module](parser.py)
- [Audit API](audit.py)
