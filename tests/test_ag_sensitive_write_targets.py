# Dropped upstream widened-grant gateway test: requires MCP, Receiver and M1 runtime.
import pytest

from security_harness.agentguard.sensitive_targets import sensitive_write_target

SENSITIVE = ["case-001/.ssh/authorized_keys", "case-001/.vscode/settings.json", "case-001/.git/hooks/pre-commit", "case-001/.github/workflows/ci.yml", "case-001/.env", "case-001/.bashrc", "case-001/keys/server.pem"]
ORDINARY = ["case-001/output/report.txt", "case-001/notes/ssh_hardening.md", "case-001/env.txt"]
@pytest.mark.parametrize("path,expected", [(p, True) for p in SENSITIVE] + [(p, False) for p in ORDINARY])
def test_sensitive_name_matcher(path, expected):
    assert sensitive_write_target("/workspace/" + path) is expected
    assert sensitive_write_target(path.replace("/", "\\").upper()) is expected
