"""
base.py  --  Shared collector utilities and Finding constructors.

Python port of the Nim `base.nim`. This is the foundation layer every
collector builds on. It wraps three concerns:

  1. Permission inspection  -- read a file's mode via os.stat and answer
     "is this world-readable / group-readable?", "what are the octal perms?"
  2. Safe filesystem access -- exists/read helpers that never raise; a missing
     or unreadable file just yields "" or False, so one bad file can't crash
     a whole scan.
  3. Finding construction    -- make_finding / make_finding_with_cred stamp a
     Finding with permissions, modification time, and size automatically.

`permission_severity` is the core risk-rating rule shared across collectors:
world-readable = critical, group-readable = medium, looser-than-expected =
low, otherwise info.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional

from .config import (
    GROUP_READ_BIT,
    OWNER_ONLY_DIR_PERMS,
    OWNER_ONLY_FILE_PERMS,
    WORLD_READ_BIT,
)
from .types import (
    Category,
    CollectorResult,
    Credential,
    Finding,
    HarvestConfig,
    Severity,
)


# --- permission / stat helpers ---------------------------------------------

def get_perms_string(path: str) -> str:
    """Return octal permissions like '0600'. 'unknown' if stat fails."""
    try:
        mode = os.stat(path).st_mode & 0o777
        return "0" + format(mode, "03o")
    except OSError:
        return "unknown"


def get_modified_time(path: str) -> str:
    """Return the last-modified time as UTC ISO-8601 ('...Z'), or 'unknown'."""
    try:
        mtime = os.stat(path).st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except OSError:
        return "unknown"


def get_file_size_bytes(path: str) -> int:
    """Return file size in bytes, or -1 if it cannot be determined."""
    try:
        return os.path.getsize(path)
    except OSError:
        return -1


def get_numeric_perms(path: str) -> int:
    """Return the permission bits (mode & 0o7777), or -1 on error."""
    try:
        return os.stat(path).st_mode & 0o7777
    except OSError:
        return -1


def is_world_readable(path: str) -> bool:
    try:
        return (os.stat(path).st_mode & WORLD_READ_BIT) != 0
    except OSError:
        return False


def is_group_readable(path: str) -> bool:
    try:
        return (os.stat(path).st_mode & GROUP_READ_BIT) != 0
    except OSError:
        return False


# --- safe filesystem access -------------------------------------------------

def expand_home(config: HarvestConfig, subpath: str) -> str:
    """Join the scan target directory with a relative sub-path."""
    return os.path.join(config.target_dir, subpath)


def safe_file_exists(path: str) -> bool:
    try:
        return os.path.isfile(path)
    except OSError:
        return False


def safe_dir_exists(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except OSError:
        return False


def read_file_content(path: str) -> str:
    """Read a whole file as text. Returns '' on any error (never raises).

    Undecodable bytes are replaced rather than raising, because we only ever
    string-match against the content -- we never need it byte-perfect.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, ValueError):
        return ""


def read_file_lines(path: str, max_lines: int = -1) -> List[str]:
    """Read a file into a list of lines, optionally capped at max_lines."""
    content = read_file_content(path)
    if content == "":
        # Distinguish "unreadable" from "genuinely empty": read_file_content
        # returns "" for both, and an empty file has no lines anyway.
        if not safe_file_exists(path):
            return []
    lines = content.splitlines()
    if 0 < max_lines < len(lines):
        return lines[:max_lines]
    return lines


def matches_exclude(path: str, patterns: List[str]) -> bool:
    """True if the path's filename equals a pattern, or a /pattern/ segment
    appears anywhere in the path."""
    name = os.path.basename(path)
    for pattern in patterns:
        if pattern == name or ("/" + pattern + "/") in path:
            return True
    return False


# --- Finding construction ---------------------------------------------------

def make_finding(
    path: str, description: str, category: Category, severity: Severity
) -> Finding:
    """Build a Finding, auto-filling permissions / modified time / size."""
    return Finding(
        path=path,
        category=category,
        severity=severity,
        description=description,
        credential=None,
        permissions=get_perms_string(path),
        modified=get_modified_time(path),
        size=get_file_size_bytes(path),
    )


def make_finding_with_cred(
    path: str,
    description: str,
    category: Category,
    severity: Severity,
    cred: Credential,
) -> Finding:
    """Like make_finding, but attaches a Credential detail record."""
    return Finding(
        path=path,
        category=category,
        severity=severity,
        description=description,
        credential=cred,
        permissions=get_perms_string(path),
        modified=get_modified_time(path),
        size=get_file_size_bytes(path),
    )


def new_collector_result(name: str, category: Category) -> CollectorResult:
    return CollectorResult(name=name, category=category, findings=[], duration_ms=0, errors=[])


def permission_severity(path: str, is_dir: bool = False) -> Severity:
    """Rate a file/dir purely by how exposed its permission bits are.

    world-readable -> CRITICAL, group-readable -> MEDIUM,
    looser than the owner-only baseline -> LOW, otherwise INFO.
    """
    perms = get_numeric_perms(path)
    if perms < 0:
        return Severity.INFO
    if (perms & WORLD_READ_BIT) != 0:
        return Severity.CRITICAL
    if (perms & GROUP_READ_BIT) != 0:
        return Severity.MEDIUM
    expected = OWNER_ONLY_DIR_PERMS if is_dir else OWNER_ONLY_FILE_PERMS
    if perms > expected:
        return Severity.LOW
    return Severity.INFO


def redact_value(value: str, show_chars: int = 4) -> str:
    """Mask a secret: keep the first `show_chars` chars, star out the rest."""
    if len(value) <= show_chars:
        return "*" * len(value)
    return value[:show_chars] + "*" * (len(value) - show_chars)
