"""
keyring.py  --  Desktop keyring and password manager collector.

Python port of the Nim `keyring.nim`. Detects local vaults from five sources:

  scan_gnome_keyring -- *.keyring DBs under ~/.local/share/keyrings
  scan_kde_wallet    -- wallet files under ~/.local/share/kwalletd
  scan_keepass       -- *.kdbx databases (recursive, max depth 5)
  scan_pass_store    -- ~/.password-store, counting *.gpg entries
  scan_bitwarden     -- Bitwarden desktop / CLI local vault dirs

These stores are normally encrypted, so most findings are informational; the
severity comes from how exposed the files' permissions are.
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
    permission_severity,
    safe_dir_exists,
)
from ..types import Category, CollectorResult, Credential, HarvestConfig, Severity

_SKIP_DIRS = {"node_modules", "vendor", ".git", "__pycache__", ".venv", "venv", ".cache"}
_ALLOWED_HIDDEN = {".config", ".local", ".keepass", ".keepassxc"}


def _perm_severity(path: str) -> Severity:
    if is_world_readable(path):
        return Severity.CRITICAL
    if is_group_readable(path):
        return Severity.HIGH
    return Severity.MEDIUM


def _scan_gnome_keyring(config: HarvestConfig, result: CollectorResult) -> None:
    keyring_dir = expand_home(config, C.GNOME_KEYRING_DIR)
    if not safe_dir_exists(keyring_dir):
        return
    try:
        db_count = 0
        for entry in os.scandir(keyring_dir):
            if not entry.is_file(follow_symlinks=False):
                continue
            if entry.path.endswith(".keyring"):
                db_count += 1
                result.findings.append(
                    make_finding(entry.path, "GNOME Keyring database", Category.KEYRING, _perm_severity(entry.path))
                )
        if db_count == 0:
            result.findings.append(
                make_finding(
                    keyring_dir, "GNOME Keyring directory exists (empty)", Category.KEYRING, Severity.INFO
                )
            )
    except OSError as e:
        result.errors.append(f"Error scanning GNOME Keyring: {e}")


def _scan_kde_wallet(config: HarvestConfig, result: CollectorResult) -> None:
    wallet_dir = expand_home(config, C.KDE_WALLET_DIR)
    if not safe_dir_exists(wallet_dir):
        return
    try:
        for entry in os.scandir(wallet_dir):
            if not entry.is_file(follow_symlinks=False):
                continue
            result.findings.append(
                make_finding(entry.path, "KDE Wallet database", Category.KEYRING, _perm_severity(entry.path))
            )
    except OSError as e:
        result.errors.append(f"Error scanning KDE Wallet: {e}")


def _walk_for_kdbx(dir_path: str, depth: int, exclude_patterns, result: CollectorResult) -> None:
    if depth > 5:
        return
    try:
        entries = list(os.scandir(dir_path))
    except OSError:
        return

    for entry in entries:
        path = entry.path
        if matches_exclude(path, exclude_patterns):
            continue
        if entry.is_file(follow_symlinks=False):
            if path.endswith(C.KEEPASS_EXTENSION):
                result.findings.append(
                    make_finding(path, "KeePass database file", Category.KEYRING, _perm_severity(path))
                )
        elif entry.is_dir(follow_symlinks=False):
            dir_name = os.path.basename(path)
            if dir_name.startswith(".") and dir_name not in _ALLOWED_HIDDEN:
                continue
            if dir_name in _SKIP_DIRS:
                continue
            _walk_for_kdbx(path, depth + 1, exclude_patterns, result)


def _scan_keepass(config: HarvestConfig, result: CollectorResult) -> None:
    _walk_for_kdbx(config.target_dir, 0, config.exclude_patterns, result)


def _scan_pass_store(config: HarvestConfig, result: CollectorResult) -> None:
    pass_dir = expand_home(config, C.PASS_STORE_DIR)
    if not safe_dir_exists(pass_dir):
        return

    entry_count = 0
    try:
        for entry in os.scandir(pass_dir):
            if entry.is_file(follow_symlinks=False) and entry.path.endswith(".gpg"):
                entry_count += 1
    except OSError as e:
        result.errors.append(f"Error scanning pass store: {e}")

    cred = Credential(
        source=pass_dir,
        cred_type="pass_store",
        preview=f"{entry_count} encrypted entries",
        metadata={"entry_count": str(entry_count)},
    )
    result.findings.append(
        make_finding_with_cred(
            pass_dir,
            f"pass (password-store) with {entry_count} entries",
            Category.KEYRING,
            Severity.INFO,
            cred,
        )
    )


def _scan_bitwarden(config: HarvestConfig, result: CollectorResult) -> None:
    dirs = [expand_home(config, C.BITWARDEN_DIR), expand_home(config, C.BITWARDEN_CLI_DIR)]
    for d in dirs:
        if safe_dir_exists(d):
            sev = permission_severity(d, is_dir=True)
            result.findings.append(
                make_finding(d, "Bitwarden local vault data", Category.KEYRING, sev)
            )


def collect(config: HarvestConfig) -> CollectorResult:
    result = new_collector_result("keyring", Category.KEYRING)
    start = time.monotonic()

    _scan_gnome_keyring(config, result)
    _scan_kde_wallet(config, result)
    _scan_keepass(config, result)
    _scan_pass_store(config, result)
    _scan_bitwarden(config, result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
