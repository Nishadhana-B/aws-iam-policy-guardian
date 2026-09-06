"""analyze_and_draft: draft a least-privilege replacement via Bedrock.

Execution role: bedrock:InvokeModel + dynamodb:PutItem only. Deliberately
holds NO iam:* permissions at all — this function can reason about IAM
policy JSON handed to it, but has no ability to read or write real IAM
state itself.
"""
from __future__ import annotations

import json
import os
import uuid

import boto3

from lambdas.common.models import FlaggedStatement

bedrock = boto3.client("bedrock-runtime")
dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ["FINDINGS_TABLE_NAME"]
MODEL_ID = os.environ["BEDROCK_MODEL_ID"]
PROMPT_VERSION = "v1"

with open(os.path.join(os.path.dirname(__file__), "instructions.md")) as f:
    _SYSTEM_INSTRUCTIONS = f.read()


def _draft_replacement(flagged: FlaggedStatement) -> dict:
    user_message = json.dumps({
        "role_name": flagged.role_name,
        "policy_name": flagged.policy_name,
        "trust_policy": flagged.trust_policy,
        "flagged_statement": flagged.statement,
        "heuristic_rule_ids": flagged.heuristic_rule_ids,
    })

    response = bedrock.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "system": _SYSTEM_INSTRUCTIONS,
            "messages": [{"role": "user", "content": user_message}],
        }),
    )
    body = json.loads(response["body"].read())
    raw_text = body["content"][0]["text"]

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return {"insufficient_context": True, "reason": f"model returned non-JSON output: {raw_text[:200]!r}"}


def handler(event, _context):
    flagged = FlaggedStatement.from_payload(event)
    proposed = _draft_replacement(flagged)

    finding_id = str(uuid.uuid4())
    item = {
        "finding_id": finding_id,
        "scan_id": event.get("scan_id", "manual"),
        "role_name": flagged.role_name,
        "policy_name": flagged.policy_name,
        "heuristic_flags": flagged.heuristic_rule_ids,
        "original_statement": json.dumps(flagged.statement),
        "proposed_statement": json.dumps(proposed),
        "model_id": MODEL_ID,
        "prompt_version": PROMPT_VERSION,
        "status": "pending",
    }
    dynamodb.Table(TABLE_NAME).put_item(Item=item)

    return {"finding_id": finding_id, **item}
