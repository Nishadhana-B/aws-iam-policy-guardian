# Roadmap

Scope is deliberately small — one finished, demo-able loop beats a big
half-built system. Each milestone should be independently demo-able.

## M0 — Local, no AWS needed
- [x] Heuristic analyzer (wildcard/escalation detection) as a pure function
- [x] Unit tests against `sandbox_fixtures/*.json` (mix of clean + bad policies)
- [x] CLI entry point: `python -m analyzer.cli sandbox_fixtures/bad_role.json`

## M0b — Agent Tool Policy Guardian (same pattern, different domain)
- [x] Heuristic scanner for agent tool policies (unscoped paths/commands/
      hosts, destructive tool missing an approval gate)
- [x] Unit tests against `sandbox_fixtures/tool_policies/*.json`
- [x] `scripts/run_tool_policy_demo_local.py` — same local-fixture + Bedrock
      pattern as the IAM demo, run and verified against live Bedrock

## M1 — Sandbox account online
- [x] Bedrock model access confirmed in sandbox region (`us-west-2`, via
      inference profile `us.anthropic.claude-haiku-4-5-...`)
- [ ] ~~`list_policies` Lambda: enumerate real IAM roles read-only~~ --
      blocked: the sandbox's own bootstrap role AND `WSParticipantRole`
      both got `AccessDenied` on `iam:CreateRole`; IAM read works, write
      doesn't. Pivoted to `scripts/run_demo_local.py` (and the tool-policy
      equivalent) which scan local fixture JSON instead -- same scanner and
      Bedrock-drafting logic, proven live, no IAM permission needed.
- [ ] `analyze_and_draft` Lambda deployed for real (`list_policies` Lambda
      too) -- needs an account that grants IAM write; see
      "Full deploy" in the README

## M2 — Human-in-the-loop approval
- [ ] `request_approval`: SNS email with approve/reject link (signed, single-use)
- [ ] API Gateway + callback Lambda: validates token, updates `status`
- [ ] `apply_remediation`: only reachable from the callback, only on `approved`, backs up prior policy version before writing
- [ ] End-to-end demo: scan → email → click approve → policy actually updated in sandbox

## M3 — Orchestration + polish
- [ ] Step Functions state machine tying M1+M2 together, EventBridge schedule trigger
- [ ] Rollback path: re-apply the backed-up policy version from DynamoDB
- [ ] README demo GIF / screen recording

## M4 (stretch) — Bedrock Agent + Action Groups
- [ ] Re-express `list_policies` / `analyze_and_draft` as Action Groups behind
      a real Bedrock Agent, compare against the Step Functions version —
      this comparison is likely the most interesting section of the blog
- [ ] Bedrock Guardrails constraining output to valid JSON policy documents only

## Not in scope (say so explicitly, don't silently drift into it)
- Multi-account / Organizations-wide scanning
- Anything beyond IAM roles (users, groups, resource policies) — v1 is roles only
- A web UI — DynamoDB + CLI + email is enough for the demo and the blog
