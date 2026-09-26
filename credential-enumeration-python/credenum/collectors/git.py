"""
git.py  --  Git credential store and token collector.

Python port of the Nim `git.nim`. Three checks:

  scan_git_credentials -- ~/.git-credentials stores full URLs *with the
                          password embedded* in plaintext (that is how the
                          'store' helper works). Count the entries; high, or
                          critical if world-readable.
  scan_git_config      -- ~/.gitconfig and ~/.config/git/config: which
                          credential helper is configured. 'store' is flagged
                          medium because it persists plaintext.
  scan_token_patterns  -- look for GitHub PAT prefixes (ghp_, gho_, ...) and
                          GitLab (glpat-) accidentally committed into config,
                          reporting a redacted preview.
"""

from __future__ import annotations

import time

from .. import config as C
from ..base import (
    expand_home,
    get_perms_string,
    is_world_readable,
    make_finding,
    make_finding_with_cred,
    new_collector_result,
    read_file_content,
    read_file_lines,
    redact_value,
    safe_file_exists,
)
from ..types import Category, CollectorResult, Credential, HarvestConfig, Severity


def _scan_git_credentials(config: HarvestConfig, result: CollectorResult) -> None:
    cred_path = expand_home(config, C.GIT_CREDENTIALS)
    if not safe_file_exists(cred_path):
        return

    cred_count = 0
    for line in read_file_lines(cred_path):
        stripped = line.strip()
        if len(stripped) > 0 and "://" in stripped:
            cred_count += 1

    if cred_count == 0:
        return

    cred = Credential(
        source=cred_path,
        cred_type="git_plaintext_credentials",
        preview=f"{cred_count} stored credentials",
        metadata={"count": str(cred_count), "permissions": get_perms_string(cred_path)},
    )
    sev = Severity.CRITICAL if is_world_readable(cred_path) else Severity.HIGH
    result.findings.append(
        make_finding_with_cred(
            cred_path,
            f"Plaintext Git credential store with {cred_count} entries",
            Category.GIT,
            sev,
            cred,
        )
    )


def _scan_git_config(config: HarvestConfig, result: CollectorResult) -> None:
    paths = [expand_home(config, C.GIT_CONFIG), expand_home(config, C.GIT_CONFIG_LOCAL)]

    for path in paths:
        if not safe_file_exists(path):
            continue
        content = read_file_content(path)
        if len(content) == 0:
            continue

        in_credential_section = False
        helper_value = ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_credential_section = stripped.lower().startswith("[credential")
            if in_credential_section and stripped.lower().startswith("helper"):
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    helper_value = parts[1].strip()

        if len(helper_value) > 0:
            sev = Severity.MEDIUM if helper_value == "store" else Severity.INFO
            result.findings.append(
                make_finding(
                    path, f"Git credential helper configured: {helper_value}", Category.GIT, sev
                )
            )


def _scan_token_patterns(config: HarvestConfig, result: CollectorResult) -> None:
    config_paths = [expand_home(config, C.GIT_CONFIG), expand_home(config, C.GIT_CONFIG_LOCAL)]

    for path in config_paths:
        if not safe_file_exists(path):
            continue
        content = read_file_content(path)
        if len(content) == 0:
            continue

        for pattern in C.GITHUB_TOKEN_PATTERNS:
            idx = content.find(pattern)
            if idx >= 0:
                token_start = content[idx:min(idx + 20, len(content))]
                cred = Credential(
                    source=path,
                    cred_type="github_token",
                    preview=redact_value(token_start, 8),
                    metadata={},
                )
                result.findings.append(
                    make_finding_with_cred(
                        path, "GitHub personal access token detected", Category.GIT, Severity.HIGH, cred
                    )
                )
                break

        for pattern in C.GITLAB_TOKEN_PATTERNS:
            idx = content.find(pattern)
            if idx >= 0:
                token_start = content[idx:min(idx + 20, len(content))]
                cred = Credential(
                    source=path,
                    cred_type="gitlab_token",
                    preview=redact_value(token_start, 8),
                    metadata={},
                )
                result.findings.append(
                    make_finding_with_cred(
                        path, "GitLab personal access token detected", Category.GIT, Severity.HIGH, cred
                    )
                )
                break


def collect(config: HarvestConfig) -> CollectorResult:
    result = new_collector_result("git", Category.GIT)
    start = time.monotonic()

    _scan_git_credentials(config, result)
    _scan_git_config(config, result)
    _scan_token_patterns(config, result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
