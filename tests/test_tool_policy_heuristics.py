from tool_policy.heuristics import scan_tool_policy


def test_unscoped_paths_on_destructive_tool_is_high_severity():
    policy = {
        "tool": "delete_file",
        "description": "Deletes a file.",
        "allowed_paths": ["*"],
        "requires_approval": False,
    }
    findings = scan_tool_policy(policy)
    rule_ids = {f.rule_id for f in findings}
    assert "unscoped_paths" in rule_ids
    assert "no_approval_for_destructive" in rule_ids
    unscoped = next(f for f in findings if f.rule_id == "unscoped_paths")
    assert unscoped.severity == "high"


def test_unscoped_paths_on_read_only_tool_is_medium_severity():
    policy = {
        "tool": "list_files",
        "description": "Lists files in a directory.",
        "allowed_paths": ["*"],
        "requires_approval": False,
    }
    findings = scan_tool_policy(policy)
    unscoped = next(f for f in findings if f.rule_id == "unscoped_paths")
    assert unscoped.severity == "medium"
    assert "no_approval_for_destructive" not in {f.rule_id for f in findings}


def test_unscoped_commands_flagged_high():
    policy = {
        "tool": "run_shell_command",
        "description": "Runs a shell command.",
        "allowed_commands": ["*"],
        "requires_approval": True,
    }
    findings = scan_tool_policy(policy)
    assert [f.rule_id for f in findings] == ["unscoped_commands"]
    assert findings[0].severity == "high"


def test_unscoped_hosts_flagged_medium():
    policy = {
        "tool": "http_fetch",
        "description": "Fetches a URL.",
        "allowed_hosts": ["*"],
        "requires_approval": True,
    }
    findings = scan_tool_policy(policy)
    assert [f.rule_id for f in findings] == ["unscoped_hosts"]


def test_destructive_tool_without_approval_flagged_even_when_scoped():
    policy = {
        "tool": "terminate_ec2_instance",
        "description": "Terminates a specific EC2 instance.",
        "allowed_instance_ids": ["i-123"],
        "requires_approval": False,
    }
    findings = scan_tool_policy(policy)
    assert [f.rule_id for f in findings] == ["no_approval_for_destructive"]


def test_destructive_tool_with_approval_not_flagged():
    policy = {
        "tool": "terminate_ec2_instance",
        "description": "Terminates a specific EC2 instance.",
        "allowed_instance_ids": ["i-123"],
        "requires_approval": True,
    }
    assert scan_tool_policy(policy) == []


def test_clean_scoped_read_only_tool_has_no_findings():
    policy = {
        "tool": "read_file",
        "description": "Reads a file from the workspace.",
        "allowed_paths": ["/workspace/**"],
        "requires_approval": False,
    }
    assert scan_tool_policy(policy) == []
