# Roadmap

Scope is deliberately small — one finished, demo-able loop beats a big
half-built system. Each milestone should be independently demo-able.

## M0 — Local, no AWS needed
- [ ] Heuristic analyzer (wildcard/escalation detection) as a pure function
- [ ] Unit tests against `sandbox_fixtures/*.json` (mix of clean + bad policies)
- [ ] CLI entry point: `python -m analyzer.cli sandbox_fixtures/bad_role.json`

## M1 — Sandbox account online
- [ ] Bedrock model access requested + confirmed in sandbox region
- [ ] `list_policies` Lambda: enumerate real IAM roles read-only, feed into M0 analyzer
- [ ] `analyze_and_draft` Lambda: heuristic hits → Bedrock `InvokeModel` → proposed statement, written to DynamoDB
- [ ] Manual demo: run once, inspect DynamoDB findings by hand (no approval flow yet)

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
