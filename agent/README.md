# agent/

Reserved for M4 (see [`docs/ROADMAP.md`](../docs/ROADMAP.md)): a real
Bedrock Agent's instructions + Action Group OpenAPI specs, once
`list_policies`/`analyze_and_draft` are re-expressed as Action Groups
instead of being invoked directly.

Until then, the model system prompt lives next to the code that actually
uses it: [`src/lambdas/analyze_and_draft/instructions.md`](../src/lambdas/analyze_and_draft/instructions.md).
