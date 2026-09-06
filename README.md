# IAM Policy Guardian

An AI agent that scans an AWS account's IAM roles and policies, flags
over-permissive statements (wildcard actions/resources, privilege-escalation
paths), and drafts least-privilege remediation policies — with a **required
human approval step** before anything is ever applied.

Built on **Amazon Bedrock** (agent + tool-calling), Lambda, Step Functions,
and DynamoDB. This is a personal project written up as a technical blog post
covering: hybrid deterministic + LLM policy analysis, designing an agent that
is architecturally incapable of writing IAM changes without a human in the
loop, and testing LLM output against real AWS APIs.

## Why this project

Most "AI agent on AWS" demos are chatbots. This one gives the agent a
consequential, security-sensitive job (recommending IAM changes) and then
deliberately limits its blast radius — the interesting engineering problem
isn't "can the LLM read a policy," it's "how do you let an LLM participate in
a change to your account's security posture without ever letting it *make*
that change unsupervised."

## Architecture

```
                    ┌─────────────────────┐
   trigger  ──────▶ │  Step Functions      │
 (CLI / EventBridge)│  state machine       │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                            ▼
        ┌─────────────────┐          ┌──────────────────┐
        │ list_policies    │          │  DynamoDB         │
        │ (read-only IAM   │─writes──▶│  PolicyFindings   │
        │  role, IAM:Get*) │          │  table            │
        └────────┬─────────┘          └─────────┬─────────┘
                 │                               ▲
                 ▼                               │
        ┌──────────────────────┐                 │
        │ analyze_and_draft     │                 │
        │  1. heuristic scan    │─────writes──────┘
        │     (wildcard/escal.  │
        │     detection, no LLM)│
        │  2. Bedrock model call│
        │     drafts least-priv │
        │     policy JSON       │
        │  (read-only IAM role) │
        └────────┬──────────────┘
                 ▼
        ┌──────────────────────┐
        │ request_approval      │──▶ SNS email / Slack webhook
        │  (no IAM permissions  │     with approve/reject link
        │   at all)             │
        └────────┬──────────────┘
                 ▼   (human clicks approve)
        ┌──────────────────────┐
        │ apply_remediation     │  <- ONLY Lambda with
        │  (write-scoped IAM    │     iam:PutRolePolicy /
        │   role, invoked only  │     CreatePolicyVersion,
        │   post-approval)      │     backs up prior policy
        └──────────────────────┘     version to DynamoDB first
```

Key design decision: **the reasoning Lambdas (list/analyze) hold read-only
IAM permissions; only `apply_remediation` can write, and it is never invoked
by the agent itself** — only by the approval callback after a human accepts.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full writeup.

## Status

Early scaffold — see [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Prerequisites

- An AWS sandbox account (this project is being built against an AWS
  Builder Center workshop sandbox) with Bedrock model access granted in your
  target region — request this early, approval can take a day.
- Python 3.11+ (Lambda runtime target; note: local dev shell here reports
  3.14 — pin Lambda runtime explicitly in CDK, don't assume parity)
- Node.js + `npm install -g aws-cdk` for deploying infra (not yet installed
  in this environment — install before first deploy)
- `sandbox_fixtures/` — intentionally-messy example IAM policies for local
  testing of the analyzer without touching a real account

## Repo layout

```
infra/                CDK app (Python) — DynamoDB, Lambdas, Step Functions,
                       IAM roles for the agent's own execution
src/lambdas/          Lambda handler code, one dir per function (each
                       function's Bedrock prompt, if any, lives alongside it)
agent/                Reserved for M4: real Bedrock Agent + Action Group
                       config, once the Lambdas are re-expressed that way
docs/                 Architecture notes, roadmap
sandbox_fixtures/     Sample messy IAM policy JSON for local/offline testing
tests/                Unit tests for the heuristic analyzer + Lambda handlers
```

## Setup (once sandbox is live)

1. Request Bedrock model access in the sandbox account/region.
2. `pip install -r infra/requirements.txt` and `npm install -g aws-cdk`.
3. `cdk bootstrap` then `cdk deploy` from `infra/`.
4. Load `sandbox_fixtures/` policies into a couple of test IAM roles in the
   sandbox (or point the scanner at whatever the sandbox already has).
5. Trigger the state machine, watch a finding land in DynamoDB, approve it
   via the emailed link, confirm `apply_remediation` only fires after that.
