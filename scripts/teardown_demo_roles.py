"""Delete the demo roles created by setup_demo_roles.py. Only needed if
you're running this in your own AWS account -- the Builder Center sandbox
deletes everything automatically when the 8-hour session ends.

    python scripts/teardown_demo_roles.py
"""
from __future__ import annotations

import boto3

from setup_demo_roles import DEMO_ROLES

iam = boto3.client("iam")


def main():
    for role_name, _ in DEMO_ROLES:
        try:
            for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            iam.delete_role(RoleName=role_name)
            print(f"Deleted role: {role_name}")
        except iam.exceptions.NoSuchEntityException:
            print(f"Role not found, already deleted: {role_name}")


if __name__ == "__main__":
    main()
