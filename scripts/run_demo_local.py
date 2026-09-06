"""Scan the local sandbox_fixtures policy JSON files with the heuristic
rules, then draft a least-privilege replacement for each flagged statement
via Amazon Bedrock. No IAM read/write needed -- everything operates on
local JSON files, so this runs even in IAM-locked-down sandboxes.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from analyzer.heuristics import scan_policy_document  # noqa: E402

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "sandbox_fixtures")

bedrock = boto3.client("bedrock-runtime")

_INSTRUCTIONS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "lambdas", "analyze_and_draft", "instructions.md",
)
with open(_INSTRUCTIONS_PATH) as f:
    SYSTEM_INSTRUCTIONS = f.read()

_FENCE_RE = re.compile(r"^```(?:json)?\s*|```\s*$", re.MULTILINE)


def _parse_model_json(raw_text):
    cleaned = _FENCE_RE.sub("", raw_text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {"insufficient_context": True, "reason": f"model returned non-JSON: {raw_text[:200]!r}"}


def draft_fix(role_name, statement, rule_ids):
    user_message = json.dumps({
        "role_name": role_name,
        "policy_name": "demo-policy",
        "trust_policy": None,
        "flagged_statement": statement,
        "heuristic_rule_ids": rule_ids,
    })
    response = bedrock.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "system": SYSTEM_INSTRUCTIONS,
            "messages": [{"role": "user", "content": user_message}],
        }),
    )
    body = json.loads(response["body"].read())
    raw_text = body["content"][0]["text"]
    return _parse_model_json(raw_text)


def main():
    for path in sorted(glob.glob(os.path.join(FIXTURES_DIR, "*.json"))):
        role_name = os.path.splitext(os.path.basename(path))[0]
        with open(path) as f:
            document = json.load(f)

        findings = scan_policy_document(document)
        print(f"\n########## {role_name} ##########")
        if not findings:
            print("No findings -- policy already looks least-privilege.")
            continue

        statements = document["Statement"]
        if isinstance(statements, dict):
            statements = [statements]

        by_statement = {}
        for finding in findings:
            by_statement.setdefault(finding.statement_index, []).append(finding.rule_id)

        for index, rule_ids in by_statement.items():
            statement = statements[index]
            print(f"\n=== statement[{index}] ===")
            print("Heuristic flags:", ", ".join(rule_ids))
            print("Original statement:")
            print(json.dumps(statement, indent=2))

            proposed = draft_fix(role_name, statement, rule_ids)
            print("Bedrock-proposed least-privilege replacement:")
            print(json.dumps(proposed, indent=2))


if __name__ == "__main__":
    main()
