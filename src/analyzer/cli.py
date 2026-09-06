"""Run the heuristic scanner against a local IAM policy JSON file.

Usage:
    python -m analyzer.cli sandbox_fixtures/bad_role.json
"""
from __future__ import annotations

import json
import sys

from analyzer.heuristics import scan_policy_document


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 1

    with open(argv[0]) as f:
        document = json.load(f)

    findings = scan_policy_document(document)
    if not findings:
        print(f"{argv[0]}: no findings.")
        return 0

    print(f"{argv[0]}: {len(findings)} finding(s)")
    for finding in findings:
        print(f"  [{finding.severity:>6}] statement[{finding.statement_index}] "
              f"{finding.rule_id}: {finding.message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
