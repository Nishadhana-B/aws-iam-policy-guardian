"""M1 scope: DynamoDB findings table + list_policies + analyze_and_draft.

Deliberately does NOT yet include request_approval / apply_remediation /
Step Functions / API Gateway — those land in M2/M3 (see docs/ROADMAP.md).
Building the approval-gated write path before the read+draft path works
end-to-end would mean debugging two unfinished things at once.

Privilege separation (see docs/ARCHITECTURE.md):
  - list_policies: read-only IAM, plus invoke on analyze_and_draft only.
  - analyze_and_draft: bedrock:InvokeModel + dynamodb:PutItem only, no IAM.
"""
from __future__ import annotations

import os

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from constructs import Construct

# Source lives one level up from infra/, shared by both Lambdas so that
# `analyzer` and `lambdas.common` are importable from either handler.
SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "src")

# Override via `cdk deploy -c bedrock_model_id=...` once you've confirmed
# which model you have access to in the sandbox account/region.
DEFAULT_BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"


class IamPolicyGuardianStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        findings_table = dynamodb.Table(
            self, "PolicyFindings",
            partition_key=dynamodb.Attribute(name="finding_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            # Sandbox project: destroy with the stack rather than orphaning
            # a table. Revisit if this ever points at a non-sandbox account.
            removal_policy=RemovalPolicy.DESTROY,
        )

        bedrock_model_id = self.node.try_get_context("bedrock_model_id") or DEFAULT_BEDROCK_MODEL_ID

        analyze_and_draft_fn = lambda_.Function(
            self, "AnalyzeAndDraftFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="lambdas.analyze_and_draft.handler.handler",
            code=lambda_.Code.from_asset(SRC_DIR),
            timeout=Duration.seconds(30),
            environment={
                "FINDINGS_TABLE_NAME": findings_table.table_name,
                "BEDROCK_MODEL_ID": bedrock_model_id,
            },
        )
        findings_table.grant_write_data(analyze_and_draft_fn)
        analyze_and_draft_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel"],
            resources=[
                f"arn:aws:bedrock:{self.region}::foundation-model/{bedrock_model_id}",
            ],
        ))

        list_policies_fn = lambda_.Function(
            self, "ListPoliciesFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="lambdas.list_policies.handler.handler",
            code=lambda_.Code.from_asset(SRC_DIR),
            timeout=Duration.minutes(5),
            environment={
                "ANALYZE_AND_DRAFT_FUNCTION_NAME": analyze_and_draft_fn.function_name,
            },
        )
        analyze_and_draft_fn.grant_invoke(list_policies_fn)
        list_policies_fn.add_to_role_policy(iam.PolicyStatement(
            actions=[
                "iam:ListRoles",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
            ],
            resources=["*"],  # read-only IAM introspection has no narrower resource scope
        ))
