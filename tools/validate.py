#!/usr/bin/env python3
from daclib import ValidationError, validate_project

try:
    rules = validate_project()
except ValidationError as exc:
    print("VALIDATION FAILED")
    print(exc)
    raise SystemExit(1)

print(f"VALIDATION PASSED: {len(rules)} Sigma rule(s)")
for rule in rules:
    print(f"  OK  {rule.id}  {rule.path.relative_to(rule.path.parents[3])}")
