"""Non-overridable sensitive write targets (赛题能力3: fs.write 敏感路径).

A widened trusted Contract/Grant still cannot authorise writes to these names:
credentials, shell start-up files, scheduled tasks, VCS hooks/CI, and IDE agent
settings (the CVE-2025-53773 vector: an injected agent writes
``.vscode/settings.json`` to enable auto-approval). Matching is on logical path
segments, case-insensitive, after separator normalisation; it is a name policy,
not a substitute for the executor's directory-fd / O_NOFOLLOW checks.
"""

from __future__ import annotations

import re

SENSITIVE_DIRS = frozenset(
    {
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".git",
        ".vscode",
        ".idea",
        ".cursor",
        "cron.d",
        "systemd",
        "launchagents",
        "init.d",
        "sudoers.d",
    }
)
SENSITIVE_FILES = frozenset(
    {
        "authorized_keys",
        "known_hosts",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zprofile",
        "crontab",
        "sudoers",
        "passwd",
        "shadow",
        "credentials",
    }
)
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_CI_PATH = re.compile(r"(?:^|/)\.github/workflows/|(?:^|/)\.gitlab-ci\.ya?ml$")


def sensitive_write_target(resource: str) -> bool:
    path = resource.replace("\\", "/").lower()
    parts = [part for part in path.split("/") if part not in {"", "."}]
    if not parts:
        return False
    name = parts[-1]
    return bool(
        SENSITIVE_DIRS.intersection(parts[:-1])
        or name in SENSITIVE_FILES
        or name.startswith(".env.")
        or name.endswith(SENSITIVE_SUFFIXES)
        or _CI_PATH.search(path)
    )
