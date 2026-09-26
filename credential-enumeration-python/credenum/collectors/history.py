"""
history.py  --  Shell history and environment file collector.

Python port of the Nim `history.nim`. Two jobs:

  scan_history_file -- read up to 50 000 lines from each shell history file
                       (.bash_history, .zsh_history, ...) and flag two kinds
                       of leak: secret assignments (export TOKEN=..., API_KEY=)
                       capped at 20 findings, and sensitive commands
                       (curl -u, mysql -p, sshpass) capped at 10. Matched
                       values are redacted so the report never prints the
                       real secret.
  scan_env_files    -- recursively walk (max depth 5) for .env / .env.local /
                       .env.production / .env.staging, skipping hidden and
                       vendored directories.
"""

from __future__ import annotations

import os
import time

from .. import config as C
from ..base import (
    expand_home,
    is_group_readable,
    is_world_readable,
    make_finding,
    make_finding_with_cred,
    matches_exclude,
    new_collector_result,
    read_file_lines,
    redact_value,
    safe_file_exists,
)
from ..types import Category, CollectorResult, Credential, HarvestConfig, Severity

MAX_HISTORY_LINES = 50000
MAX_ENV_DEPTH = 5

# Directories we never descend into when hunting for .env files.
_SKIP_DIRS = {"node_modules", "vendor", ".git", "__pycache__", ".venv", "venv", ".cache"}
_ALLOWED_HIDDEN = {".config", ".local"}


def redact_line(line: str) -> str:
    """Turn 'export TOKEN="abcd1234"' into 'export TOKEN=abcd********'."""
    eq_idx = line.find("=")
    if eq_idx < 0:
        return line
    key = line[:eq_idx]
    val_start = eq_idx + 1
    if val_start >= len(line):
        return line
    value = line[val_start:].strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        clean_value = value[1:-1]
    else:
        clean_value = value
    return key + "=" + redact_value(clean_value, 4)


def matches_secret_pattern(line: str) -> bool:
    """True if the line looks like a secret assignment (KEY=, TOKEN=, ...)."""
    upper = line.upper()
    for pattern in C.SECRET_PATTERNS:
        if pattern in upper:
            if "export " in line.lower() or line.strip().startswith(pattern.split("=")[0]):
                return True
    return False


def matches_command_pattern(line: str) -> bool:
    """True if the line matches a sensitive-command pattern.

    Patterns use '.*' to mean 'then, later on the line'. We split on '.*' and
    require each piece to appear in order -- a tiny ordered-substring matcher,
    so no real regex engine (and no ReDoS risk) is involved.
    """
    lower = line.lower()
    for pattern in C.HISTORY_COMMAND_PATTERNS:
        parts = pattern.split(".*")
        if len(parts) >= 2:
            all_found = True
            search_from = 0
            for part in parts:
                idx = lower.find(part, search_from)
                if idx < 0:
                    all_found = False
                    break
                search_from = idx + len(part)
            if all_found:
                return True
        elif pattern in lower:
            return True
    return False


def _scan_history_file(config: HarvestConfig, file_name: str, result: CollectorResult) -> None:
    path = expand_home(config, file_name)
    if not safe_file_exists(path):
        return

    lines = read_file_lines(path, MAX_HISTORY_LINES)
    secret_count = 0
    command_count = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        if len(stripped) == 0:
            continue

        if matches_secret_pattern(stripped):
            secret_count += 1
            if secret_count <= 20:
                cred = Credential(
                    source=path,
                    cred_type="history_secret",
                    preview=redact_line(stripped),
                    metadata={"line_region": str(i + 1)},
                )
                result.findings.append(
                    make_finding_with_cred(
                        path,
                        f"Secret in shell history (line ~{i + 1})",
                        Category.HISTORY,
                        Severity.HIGH,
                        cred,
                    )
                )
        elif matches_command_pattern(stripped):
            command_count += 1
            if command_count <= 10:
                preview = stripped[:60] + "..." if len(stripped) > 60 else stripped
                result.findings.append(
                    make_finding(
                        path,
                        f"Sensitive command in history: {preview}",
                        Category.HISTORY,
                        Severity.MEDIUM,
                    )
                )

    if secret_count > 20:
        result.findings.append(
            make_finding(
                path,
                f"{secret_count} total secret patterns found (showing first 20)",
                Category.HISTORY,
                Severity.INFO,
            )
        )


def _walk_for_env(dir_path: str, depth: int, exclude_patterns, result: CollectorResult) -> None:
    if depth > MAX_ENV_DEPTH:
        return
    try:
        entries = list(os.scandir(dir_path))
    except OSError as e:
        result.errors.append(f"Error scanning for env files in {dir_path}: {e}")
        return

    for entry in entries:
        path = entry.path
        if matches_exclude(path, exclude_patterns):
            continue
        # follow_symlinks=False: symlinks are neither file nor dir here, so
        # they are skipped -- matching the Nim walkDir behaviour.
        if entry.is_file(follow_symlinks=False):
            name = os.path.basename(path)
            for env_pattern in C.ENV_FILE_PATTERNS:
                if name == env_pattern:
                    if is_world_readable(path):
                        sev = Severity.CRITICAL
                    elif is_group_readable(path):
                        sev = Severity.HIGH
                    else:
                        sev = Severity.MEDIUM
                    result.findings.append(
                        make_finding(path, f"Environment file: {name}", Category.HISTORY, sev)
                    )
                    break
        elif entry.is_dir(follow_symlinks=False):
            dir_name = os.path.basename(path)
            if dir_name.startswith(".") and dir_name not in _ALLOWED_HIDDEN:
                continue
            if dir_name in _SKIP_DIRS:
                continue
            _walk_for_env(path, depth + 1, exclude_patterns, result)


def _scan_env_files(config: HarvestConfig, result: CollectorResult) -> None:
    _walk_for_env(config.target_dir, 0, config.exclude_patterns, result)


def collect(config: HarvestConfig) -> CollectorResult:
    result = new_collector_result("history", Category.HISTORY)
    start = time.monotonic()

    for hist_file in C.HISTORY_FILES:
        _scan_history_file(config, hist_file, result)

    _scan_env_files(config, result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
