"""Create a few IAM roles with intentionally over-permissive policies, so
run_demo.py has something real to find. Run this first, once, at the start
of your sandbox session.

    python scripts/setup_demo_roles.py
"""
from __future__ import annotations

import json
import os

import boto3

iam = boto3.client("iam")

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "sandbox_fixtures")

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

# (role name, fixture file to attach as an inline policy)
DEMO_ROLES = [
    ("policy-guardian-demo-full-admin", "bad_role_full_admin.json"),
    ("policy-guardian-demo-passrole", "bad_role_passrole_escalation.json"),
    ("policy-guardian-demo-clean", "clean_role_scoped_s3.json"),
]


def main():
    for role_name, fixture_file in DEMO_ROLES:
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
                Description="policy-guardian demo role -- safe to delete",
            )
            print(f"Created role: {role_name}")
        except iam.exceptions.EntityAlreadyExistsException:
            print(f"Role already exists, reusing: {role_name}")

        with open(os.path.join(FIXTURES_DIR, fixture_file)) as f:
            document = json.load(f)

        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="demo-policy",
            PolicyDocument=json.dumps(document),
        )
        print(f"  attached inline policy from {fixture_file}")

    print("\nDone. Now run: python scripts/run_demo.py")


if __name__ == "__main__":
    main()
