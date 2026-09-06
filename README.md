# Policy Guardian

An AI-assisted "policy least-privilege" pattern, applied to two domains:

1. **IAM Policy Guardian** — scans an AWS account's IAM roles/policies,
   flags over-permissive statements (wildcard actions/resources,
   privilege-escalation paths), and drafts least-privilege remediation
   policies via Amazon Bedrock — with a **required human approval step**
   before anything is ever applied.
2. **Agent Tool Policy Guardian** — the same pattern applied to *AI agent
   tool permissions* instead of AWS IAM: scans a tool's policy (allowed
   paths/commands/hosts, whether it requires approval), flags
   over-permissive grants, and drafts a tightened policy via Bedrock.
   Directly relevant to anyone building agents with Bedrock AgentCore,
   MCP tools, or any framework where an LLM decides what tool to call next.

Both share one architecture: deterministic heuristics flag *what's* risky
(cheap, testable, no LLM) → only flagged items go to Bedrock to draft a fix
(bounds cost and hallucination surface) → a human approves before anything
is ever applied for real.

This is a personal project written up as a technical blog post covering:
hybrid deterministic + LLM policy analysis, designing an agent that is
architecturally incapable of making a change without a human in the loop,
and what happens when you actually run this against a live, locked-down
AWS sandbox (see "What we learned" below).

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

Early scaffold — see [`docs/ROADMAP.md`](docs/ROADMAP.md). Both the IAM
and agent-tool local demos (below) are working, tested against live
Bedrock. The full CDK/Lambda/Step Functions architecture in `infra/` is
designed but not deployed — see "What we learned" below for why.

## Try it (no AWS account writes needed)

Both demos only need `bedrock:InvokeModel` — everything else runs against
local JSON fixtures, so they work even in a locked-down sandbox account.

```bash
pip install -e ".[dev]"
export AWS_DEFAULT_REGION=us-west-2   # or wherever you have Bedrock access
export BEDROCK_MODEL_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0  # or any inference-profile ID you have access to

python scripts/run_demo_local.py              # IAM policy statements
python scripts/run_tool_policy_demo_local.py  # agent tool policies
```

## What we learned running this against a real sandbox

Built and tested this against an AWS Builder Center workshop sandbox
("Building with Amazon Bedrock"). Two things worth knowing if you try the
same:

- **The sandbox is a real, full AWS account — but its default role is
  scoped to Bedrock, not IAM.** Both the code environment's own bootstrap
  role *and* the broader `WSParticipantRole` came back `AccessDenied` on
  `iam:CreateRole`. IAM read (`list-roles`, `get-role-policy`) works fine;
  IAM write does not. This is why the local-fixture demos exist — they
  prove the actual "is this AI going to suggest something safe" question
  without needing a permission grant most sandboxes won't give you.
- **Newer Claude models on Bedrock need an inference-profile ID, not a bare
  model ID.** `anthropic.claude-haiku-4-5-...` on-demand throughput isn't
  supported for some models; use `aws bedrock list-inference-profiles` to
  find the `us.anthropic....` / `global.anthropic....` ID for your model
  and pass that as `--model-id` / `BEDROCK_MODEL_ID` instead.
- **We also tried wiring this into a real Bedrock AgentCore policy engine**
  (Cedar-based tool authorization) and hit a genuine, fully-diagnosed
  permission wall — see
  [`docs/AGENTCORE_INVESTIGATION.md`](docs/AGENTCORE_INVESTIGATION.md) for
  the exact commands and errors. A real Policy Engine resource does exist
  in this sandbox; attaching an enforced policy to a real tool needs a
  Gateway, which needs `iam:PassRole` on a role this sandbox doesn't let
  us pass, and whose one passable role isn't trusted by AgentCore anyway.

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
                       IAM roles for the agent's own execution (designed,
                       not deployed -- see "What we learned")
src/lambdas/          Lambda handler code for the IAM Policy Guardian, one
                       dir per function (each function's Bedrock prompt, if
                       any, lives alongside it)
src/analyzer/         Heuristic IAM policy scanner + CLI
src/tool_policy/      Heuristic agent-tool-policy scanner + Bedrock prompt
agent/                Reserved for M4: real Bedrock Agent + Action Group
                       config, once the Lambdas are re-expressed that way
docs/                 Architecture notes, roadmap
sandbox_fixtures/     Sample messy IAM policy JSON, and sandbox_fixtures/
                      tool_policies/ for sample agent tool policies
scripts/              run_demo_local.py (IAM) and
                      run_tool_policy_demo_local.py (agent tools) -- the
                      demos that actually run against live Bedrock
tests/                Unit tests for both heuristic scanners
```

## Full deploy (designed, not yet proven against a real account)

The `infra/` CDK app + Step Functions/SNS approval flow in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) is the "real" version of the
IAM Policy Guardian -- reading live IAM roles and actually applying an
approved fix. It needs an account where you can create IAM roles for the
Lambdas (most locked-down sandboxes won't allow this -- see "What we
learned"). If you have such an account:

1. Request Bedrock model access in the account/region.
2. `pip install -r infra/requirements.txt` and `npm install -g aws-cdk`.
3. `cdk bootstrap` then `cdk deploy` from `infra/`.
4. Load `sandbox_fixtures/` policies into a couple of test IAM roles.
5. Trigger the state machine, watch a finding land in DynamoDB, approve it
   via the emailed link, confirm `apply_remediation` only fires after that.
