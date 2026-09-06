# Architecture

## Problem

Over-permissive IAM policies (`"Action": "*"`, `"Resource": "*"`, unused
admin-equivalent roles) are one of the most common real-world AWS security
findings. Detecting them is well-trodden (IAM Access Analyzer, Prowler,
etc.); *drafting a correct least-privilege replacement* is the harder, more
interesting problem — it requires understanding what the role's workload
actually needs, which is exactly the kind of judgment call an LLM is well
suited to *propose* and poorly suited to be trusted to *apply* unsupervised.

## Design principle: privilege separation mirrors the IAM problem itself

The agent that recommends fixing over-privileged IAM roles must not itself
be an over-privileged IAM principal. Three execution roles, strictly scoped:

| Lambda | IAM permissions | Can be invoked by |
|---|---|---|
| `list_policies` | `iam:ListRoles`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion` (read-only) | Step Functions / agent |
| `analyze_and_draft` | none (pure compute + Bedrock `InvokeModel`) | Step Functions / agent |
| `request_approval` | none (SNS `Publish` only) | Step Functions / agent |
| `apply_remediation` | `iam:PutRolePolicy`, `iam:CreatePolicyVersion`, `iam:GetRolePolicy` (scoped via resource ARN condition to roles tagged `policy-guardian:managed=true`) | **Only** the approval-callback path (API Gateway → Lambda), never the agent |

This means: even if the LLM is prompt-injected via a malicious inline policy
document it's asked to analyze, or simply hallucinates a bad action plan,
there is no code path from "agent decides to act" to "IAM actually changes."
The only way to reach `apply_remediation` is a human clicking approve on a
specific `finding_id`, which the callback Lambda re-validates against
DynamoDB before invoking.

## Hybrid analysis: heuristics first, LLM second

`analyze_and_draft` runs a deterministic pass before calling Bedrock:

1. **Heuristic scan** (no LLM): flag `Action: "*"`, `Resource: "*"`,
   `iam:PassRole` + `Resource: "*"` combos, `sts:AssumeRole` without
   condition keys, and other pattern-matchable risks. Cheap, deterministic,
   testable without any AWS or Bedrock calls (see `tests/`).
2. **LLM drafting**: only the heuristic-flagged statements, plus role
   metadata (name, trust policy, tags), are sent to Bedrock with a prompt
   asking for a minimal least-privilege replacement statement. The model
   never sees or reasons about clean policies — this bounds prompt size,
   cost, and the surface area for the model to hallucinate a "finding" that
   isn't real.
3. Both the heuristic finding and the LLM-drafted replacement are stored
   together in DynamoDB so the blog/demo can show model output next to the
   deterministic signal that triggered it — useful for the "how do you
   evaluate whether the LLM's suggestion is actually safe" section.

## Data model — `PolicyFindings` (DynamoDB)

| field | notes |
|---|---|
| `finding_id` (PK) | uuid |
| `scan_id` | groups findings from one run |
| `role_name`, `policy_name` | |
| `heuristic_flags` | list of rule ids that fired |
| `original_statement` | JSON |
| `proposed_statement` | JSON, from Bedrock |
| `model_id`, `prompt_version` | for reproducibility |
| `status` | `pending` \| `approved` \| `rejected` \| `applied` \| `apply_failed` |
| `created_at`, `decided_at`, `applied_at` | |

## Open questions (to resolve while building, not guessed at up front)

- Approval channel: SNS email link vs. Slack interactive message — start
  with SNS email (simpler), consider Slack as a stretch goal for the
  "active in community" demo value.
- Whether to model this as a Bedrock **Agent with Action Groups** end-to-end,
  or a Step Functions state machine that calls Bedrock `InvokeModel`
  directly for the drafting step only. Starting with the Step Functions
  version (simpler to reason about and cheaper to run repeatedly while
  developing); revisit Agents/Action Groups once the core loop works, since
  that's the part worth writing about for the "Bedrock Agents" angle.
