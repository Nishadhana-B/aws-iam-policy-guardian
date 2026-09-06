"""list_policies: read-only IAM enumeration + heuristic scan.

Execution role: read-only IAM (iam:List*, iam:Get* for roles/policies) plus
lambda:InvokeFunction scoped to the analyze_and_draft function ARN. No
DynamoDB or Bedrock permissions — this function never writes findings or
calls the model itself, it only decides what's worth analyzing and hands
each flagged statement to analyze_and_draft.

Packaging note: this Lambda's deployment bundle must include the
`analyzer` package (src/analyzer) alongside this handler and
`lambdas/common` — see infra/iam_policy_guardian/stack.py for how the
bundle is assembled.
"""
from __future__ import annotations

import json
import os

import boto3

from analyzer.heuristics import scan_policy_document
from lambdas.common.models import FlaggedStatement

iam = boto3.client("iam")
lambda_client = boto3.client("lambda")

ANALYZE_AND_DRAFT_FUNCTION_NAME = os.environ["ANALYZE_AND_DRAFT_FUNCTION_NAME"]


def _iter_inline_policy_documents(role_name: str):
    for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
        yield policy_name, doc


def _iter_attached_policy_documents(role_name: str):
    attached_policies = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    for attached in attached_policies:
        policy_arn = attached["PolicyArn"]
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"],
        )["PolicyVersion"]
        yield attached["PolicyName"], version["Document"]


def handler(event, _context):
    scan_id = event.get("scan_id", "manual")
    dispatched = []

    for role in iam.list_roles()["Roles"]:
        role_name = role["RoleName"]
        trust_policy = role.get("AssumeRolePolicyDocument")

        for policy_name, document in list(_iter_inline_policy_documents(role_name)) + \
                list(_iter_attached_policy_documents(role_name)):
            findings = scan_policy_document(document)
            if not findings:
                continue

            by_statement: dict[int, list[str]] = {}
            for finding in findings:
                by_statement.setdefault(finding.statement_index, []).append(finding.rule_id)

            statements = document["Statement"]
            if isinstance(statements, dict):
                statements = [statements]

            for statement_index, rule_ids in by_statement.items():
                flagged = FlaggedStatement(
                    role_name=role_name,
                    policy_name=policy_name,
                    statement=statements[statement_index],
                    heuristic_rule_ids=rule_ids,
                    trust_policy=trust_policy,
                )
                response = lambda_client.invoke(
                    FunctionName=ANALYZE_AND_DRAFT_FUNCTION_NAME,
                    InvocationType="RequestResponse",
                    Payload=json.dumps({"scan_id": scan_id, **flagged.to_payload()}).encode(),
                )
                result = json.loads(response["Payload"].read())
                dispatched.append(result)

    return {"scan_id": scan_id, "findings_dispatched": len(dispatched), "results": dispatched}
