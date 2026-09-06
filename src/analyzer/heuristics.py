"""Deterministic (no-LLM) scan for over-permissive IAM policy statements.

Runs before any Bedrock call so that: (1) obviously-risky statements are
flagged cheaply and reproducibly, and (2) only the flagged statements are
ever sent to the model, bounding prompt size and hallucination surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str  # "high" | "medium"
    message: str
    statement_index: int


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def scan_statement(statement: dict, index: int) -> list[Finding]:
    if statement.get("Effect") != "Allow":
        return []

    findings: list[Finding] = []
    actions = [a.lower() for a in _as_list(statement.get("Action"))]
    resources = _as_list(statement.get("Resource"))
    has_condition = bool(statement.get("Condition"))

    wildcard_action = "*" in actions
    wildcard_resource = "*" in resources

    if wildcard_action and wildcard_resource:
        findings.append(Finding(
            rule_id="full_admin",
            severity="high",
            message="Statement grants Action:* on Resource:* (full admin equivalent).",
            statement_index=index,
        ))
    else:
        if wildcard_action:
            findings.append(Finding(
                rule_id="wildcard_action",
                severity="medium",
                message="Statement grants Action:* — scope to the specific actions used.",
                statement_index=index,
            ))
        if wildcard_resource:
            findings.append(Finding(
                rule_id="wildcard_resource",
                severity="medium",
                message="Statement grants access to Resource:* — scope to specific ARNs.",
                statement_index=index,
            ))

    if "iam:passrole" in actions and wildcard_resource:
        findings.append(Finding(
            rule_id="passrole_wildcard_resource",
            severity="high",
            message=(
                "iam:PassRole on Resource:* allows passing ANY role in the "
                "account to a service — a common privilege-escalation path."
            ),
            statement_index=index,
        ))

    if "sts:assumerole" in actions and not has_condition:
        findings.append(Finding(
            rule_id="assumerole_no_condition",
            severity="medium",
            message=(
                "sts:AssumeRole with no Condition (e.g. ExternalId, source "
                "identity) — consider constraining who/what can assume this."
            ),
            statement_index=index,
        ))

    return findings


def scan_policy_document(document: dict) -> list[Finding]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    findings: list[Finding] = []
    for index, statement in enumerate(statements):
        findings.extend(scan_statement(statement, index))
    return findings
