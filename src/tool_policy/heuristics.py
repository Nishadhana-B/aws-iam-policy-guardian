"""Deterministic (no-LLM) scan for over-permissive agent tool policies.

Same shape as analyzer.heuristics, applied to a different domain: instead
of an IAM policy statement, the input is a tool policy document describing
what an AI agent's tool is allowed to do (paths/hosts/commands it can touch,
and whether calling it requires human approval).

Runs before any Bedrock call so that: (1) obviously-risky tool grants are
flagged cheaply and reproducibly, and (2) only flagged tools are ever sent
to the model, bounding prompt size and hallucination surface.
"""
from __future__ import annotations

from dataclasses import dataclass

DESTRUCTIVE_KEYWORDS = (
    "delete", "remove", "drop", "terminate", "revoke", "kill", "wipe", "purge", "destroy",
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str  # "high" | "medium"
    message: str


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _is_destructive(tool_name: str, description: str) -> bool:
    text = f"{tool_name} {description}".lower()
    return any(keyword in text for keyword in DESTRUCTIVE_KEYWORDS)


def scan_tool_policy(policy: dict) -> list[Finding]:
    tool_name = policy.get("tool", "")
    description = policy.get("description", "")
    requires_approval = bool(policy.get("requires_approval", False))
    destructive = _is_destructive(tool_name, description)

    allowed_paths = _as_list(policy.get("allowed_paths"))
    allowed_commands = _as_list(policy.get("allowed_commands"))
    allowed_hosts = _as_list(policy.get("allowed_hosts"))

    unscoped_paths = any(p in ("*", "/", "**") for p in allowed_paths)
    unscoped_commands = "*" in allowed_commands
    unscoped_hosts = "*" in allowed_hosts

    findings: list[Finding] = []

    if unscoped_paths:
        findings.append(Finding(
            rule_id="unscoped_paths",
            severity="high" if destructive else "medium",
            message=(
                f"allowed_paths grants access to '*' -- scope to the specific "
                f"directories '{tool_name}' actually needs."
            ),
        ))

    if unscoped_commands:
        findings.append(Finding(
            rule_id="unscoped_commands",
            severity="high",
            message=(
                "allowed_commands grants '*' -- arbitrary command execution. "
                "Scope to an explicit allow-list of commands."
            ),
        ))

    if unscoped_hosts:
        findings.append(Finding(
            rule_id="unscoped_hosts",
            severity="medium",
            message=(
                "allowed_hosts grants '*' -- this tool can reach any host, "
                "risking data exfiltration. Scope to a specific allow-list."
            ),
        ))

    if destructive and not requires_approval:
        findings.append(Finding(
            rule_id="no_approval_for_destructive",
            severity="high",
            message=(
                f"'{tool_name}' looks destructive/irreversible (matched keyword in "
                f"name/description) but requires_approval is false -- it can run "
                f"fully autonomously with no human in the loop."
            ),
        ))

    return findings
