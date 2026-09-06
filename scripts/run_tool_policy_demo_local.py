"""Scan the local agent tool policy fixtures with the heuristic rules, then
draft a tightened policy for each flagged tool via Amazon Bedrock. No IAM
or other AWS permissions needed beyond bedrock:InvokeModel.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from tool_policy.heuristics import scan_tool_policy  # noqa: E402

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "sandbox_fixtures", "tool_policies")

bedrock = boto3.client("bedrock-runtime")

_INSTRUCTIONS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "tool_policy", "instructions.md",
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


def draft_fix(policy, rule_ids):
    user_message = json.dumps({
        "tool_policy": policy,
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
        with open(path) as f:
            policy = json.load(f)

        findings = scan_tool_policy(policy)
        print(f"\n########## {os.path.basename(path)} ##########")
        print("Tool policy:")
        print(json.dumps(policy, indent=2))

        if not findings:
            print("No findings -- policy already looks least-privilege.")
            continue

        rule_ids = [f.rule_id for f in findings]
        print("Heuristic flags:", ", ".join(rule_ids))
        for f in findings:
            print(f"  [{f.severity:>6}] {f.rule_id}: {f.message}")

        proposed = draft_fix(policy, rule_ids)
        print("Bedrock-proposed tightened policy:")
        print(json.dumps(proposed, indent=2))


if __name__ == "__main__":
    main()
