# Investigating Bedrock AgentCore in a locked-down sandbox

This documents a real permission investigation done against a live AWS
Builder Center sandbox account, not a guess. Every command below was run
for real; the exact errors are reproduced verbatim.

## What worked

- `bedrock-agentcore-control create-policy-engine` succeeded — a real
  Policy Engine resource (`PolicyGuardianEngineB`, status `ACTIVE`) exists
  in this account with a real ARN.
- IAM read access (`list-roles`, `get-role`, `list-attached-role-policies`,
  `get-policy-version`) worked throughout.
- The workshop pre-provisions a role named `DemoGatewayRole`, intended for
  AgentCore Gateway creation.

## What's blocked, and why (proven, not assumed)

**1. Creating a Gateway fails on `iam:PassRole`:**
```
AccessDeniedException: User: .../WSParticipantRole/Participant is not
authorized to perform: iam:PassRole on resource: role/DemoGatewayRole
because no identity-based policy allows the iam:PassRole action
```

**2. Reading the actual attached policy (`ws-default-policy`) shows why** —
there IS a PassRole grant, but scoped to exactly one role:
```json
{
  "Sid": "AllowIamPassRole",
  "Effect": "Allow",
  "Action": ["iam:PassRole"],
  "Resource": ["arn:aws:iam::<account>:role/WSParticipantRole"]
}
```
Not `DemoGatewayRole`.

**3. Checking whether passing `WSParticipantRole` itself would work** —
its trust policy only allows `lambda.amazonaws.com` and `ssm.amazonaws.com`
to assume it, not `bedrock-agentcore.amazonaws.com`. So even if PassRole
allowed it, AgentCore's Gateway service would be rejected trying to assume
that role.

**4. Confirmed `create-policy` isn't itself permission-blocked** — it's a
Cedar *validation* error requiring a real resource ARN:
```
ValidationException: Invalid resource ARN provided in policy's resource
scope: invalid resource 'gateway-target/...' encountered in ARN, only
gateway resources are supported
```
Retrying with a syntactically valid but nonexistent Gateway ARN proves it's
a genuine existence check, not just a format check:
```
ResourceNotFoundException: Gateway with ID policyguardiangw-ab12cd34ef
does not exist
```

## Conclusion

There is no combination of existing roles or API calls in this sandbox
account that can create a Gateway, and therefore none that can attach an
enforced Cedar policy to a real tool. This isn't a workaround we missed —
it's confirmed at three independent layers: IAM policy scope, IAM trust
policy, and AgentCore's own resource-existence check. Finishing the
Gateway + Gateway Target + enforced Cedar policy loop needs an account
where you control IAM directly (i.e. not a shared workshop sandbox).

What we did complete honestly in this sandbox: a live Policy Engine
resource, and a standalone script (`scripts/run_tool_policy_demo_local.py`)
proving the identical heuristic + Bedrock-drafted-fix decision logic,
labeled explicitly as not going through AgentCore's enforcement path.
