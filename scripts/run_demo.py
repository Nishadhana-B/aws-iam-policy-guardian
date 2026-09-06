"""The hands-on demo: scan the roles from setup_demo_roles.py, flag risky
statements with the deterministic heuristics, draft a least-privilege
replacement via Amazon Bedrock, show the before/after, and apply it to the
real IAM role ONLY if you type 'y'.

Requires: Bedrock model access in this account/region (the Bedrock sandbox
grants this already). Set BEDROCK_MODEL_ID if you're not using Claude 3.5
Sonnet.

    python scripts/run_demo.py
"""
from __future__ import annotations

import json
import os
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from analyzer.heuristics import scan_policy_document  # noqa: E402

DEMO_ROLE_PREFIX = "policy-guardian-demo-"
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")

iam = boto3.client("iam")
bedrock = boto3.client("bedrock-runtime")

_INSTRUCTIONS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "lambdas", "analyze_and_draft", "instructions.md",
)
with open(_INSTRUCTIONS_PATH) as f:
    SYSTEM_INSTRUCTIONS = f.read()


def draft_fix(role_name: str, policy_name: str, statement: dict, rule_ids: list[str], trust_policy) -> dict:
    user_message = json.dumps({
        "role_name": role_name,
        "policy_name": policy_name,
        "trust_policy": trust_policy,
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

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return {"insufficient_context": True, "reason": f"model returned non-JSON: {raw_text[:200]!r}"}


def iter_demo_roles():
    for role in iam.list_roles()["Roles"]:
        if role["RoleName"].startswith(DEMO_ROLE_PREFIX):
            yield role


def main():
    found_any = False

    for role in iter_demo_roles():
        role_name = role["RoleName"]
        trust_policy = role.get("AssumeRolePolicyDocument")

        for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
            findings = scan_policy_document(document)
            if not findings:
                continue
            found_any = True

            statements = document["Statement"]
            if isinstance(statements, dict):
                statements = [statements]

            by_statement: dict[int, list[str]] = {}
            for finding in findings:
                by_statement.setdefault(finding.statement_index, []).append(finding.rule_id)

            for index, rule_ids in by_statement.items():
                statement = statements[index]
                print(f"\n=== {role_name} / {policy_name} statement[{index}] ===")
                print("Heuristic flags:", ", ".join(rule_ids))
                print("Original statement:")
                print(json.dumps(statement, indent=2))

                proposed = draft_fix(role_name, policy_name, statement, rule_ids, trust_policy)
                print("Bedrock-proposed replacement:")
                print(json.dumps(proposed, indent=2))

                if proposed.get("insufficient_context"):
                    print("Skipping apply -- model didn't have enough context to propose a safe fix.")
                    continue

                answer = input(f"Apply this fix to {role_name}/{policy_name}? [y/N] ").strip().lower()
                if answer == "y":
                    new_statements = list(statements)
                    new_statements[index] = proposed
                    new_document = {**document, "Statement": new_statements}
                    iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(new_document),
                    )
                    print(f"Applied. {role_name}/{policy_name} updated in IAM.")
                else:
                    print("Skipped -- no change made.")

    if not found_any:
        print("No demo roles with findings were found. Did you run scripts/setup_demo_roles.py first?")


if __name__ == "__main__":
    main()
