#!/usr/bin/env python3
import aws_cdk as cdk

from iam_policy_guardian.stack import IamPolicyGuardianStack

app = cdk.App()
IamPolicyGuardianStack(app, "IamPolicyGuardian")
app.synth()
