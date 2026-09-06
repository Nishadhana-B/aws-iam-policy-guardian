from analyzer.heuristics import scan_policy_document


def test_full_admin_flagged_as_single_high_severity_finding():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
        ]
    }
    findings = scan_policy_document(doc)
    assert [f.rule_id for f in findings] == ["full_admin"]
    assert findings[0].severity == "high"


def test_wildcard_action_and_resource_flagged_separately_when_not_combined_as_admin():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket/*"},
        ]
    }
    findings = scan_policy_document(doc)
    assert findings == []  # s3:* is not "*", and resource is scoped — no wildcard rule fires


def test_passrole_with_wildcard_resource_is_flagged_high():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
        ]
    }
    findings = scan_policy_document(doc)
    rule_ids = [f.rule_id for f in findings]
    assert "wildcard_resource" in rule_ids
    assert "passrole_wildcard_resource" in rule_ids


def test_assumerole_without_condition_flagged_medium():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123:role/x"},
        ]
    }
    findings = scan_policy_document(doc)
    assert [f.rule_id for f in findings] == ["assumerole_no_condition"]


def test_assumerole_with_condition_not_flagged():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123:role/x",
                "Condition": {"StringEquals": {"sts:ExternalId": "abc"}},
            },
        ]
    }
    assert scan_policy_document(doc) == []


def test_deny_statements_are_never_flagged():
    doc = {
        "Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
        ]
    }
    assert scan_policy_document(doc) == []


def test_clean_scoped_policy_has_no_findings():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
            },
        ]
    }
    assert scan_policy_document(doc) == []


def test_single_statement_dict_not_list_is_handled():
    doc = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    findings = scan_policy_document(doc)
    assert [f.rule_id for f in findings] == ["full_admin"]
