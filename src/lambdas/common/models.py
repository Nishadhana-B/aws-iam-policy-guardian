"""Shared types passed between list_policies and analyze_and_draft.

Kept dependency-free (no boto3) so it can be unit tested without AWS.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FlaggedStatement:
    role_name: str
    policy_name: str
    statement: dict
    heuristic_rule_ids: list[str]
    trust_policy: dict | None = None

    def to_payload(self) -> dict:
        return {
            "role_name": self.role_name,
            "policy_name": self.policy_name,
            "statement": self.statement,
            "heuristic_rule_ids": self.heuristic_rule_ids,
            "trust_policy": self.trust_policy,
        }

    @classmethod
    def from_payload(cls, payload: dict) -> "FlaggedStatement":
        return cls(
            role_name=payload["role_name"],
            policy_name=payload["policy_name"],
            statement=payload["statement"],
            heuristic_rule_ids=payload["heuristic_rule_ids"],
            trust_policy=payload.get("trust_policy"),
        )
