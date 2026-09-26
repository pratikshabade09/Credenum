"""
ssh.py  --  SSH key and configuration collector.

Python port of the Nim `ssh.nim`. Scans the target's ~/.ssh directory across
four areas:

  scan_keys            -- walk every file, detect PEM / OpenSSH private-key
                          headers, classify each as encrypted or not, and
                          escalate severity from that plus the file's perms.
  scan_config          -- parse ssh_config for host-entry counts and weak
                          settings (PasswordAuthentication yes,
                          StrictHostKeyChecking no).
  scan_authorized_keys -- count non-comment public-key entries.
  scan_known_hosts     -- count known-host entries.

The .ssh directory itself is also checked against the expected 0700.
"""

from __future__ import annotations

import os
import time

from .. import config as C
from ..base import (
    expand_home,
    get_numeric_perms,
    get_perms_string,
    matches_exclude,
    make_finding,
    make_finding_with_cred,
    new_collector_result,
    permission_severity,
    read_file_content,
    read_file_lines,
    safe_dir_exists,
    safe_file_exists,
)
from ..types import Category, CollectorResult, Credential, HarvestConfig, Severity


def is_private_key(content: str) -> bool:
    return any(content.startswith(h) for h in C.SSH_KEY_HEADERS)


def is_encrypted(content: str) -> bool:
    return any(marker in content for marker in C.SSH_ENCRYPTED_MARKERS)


def _scan_keys(config: HarvestConfig, result: CollectorResult) -> None:
    ssh_path = expand_home(config, C.SSH_DIR)
    if not safe_dir_exists(ssh_path):
        return

    # Flag the directory itself if it is not exactly 0700.
    dir_perms = get_numeric_perms(ssh_path)
    if dir_perms >= 0 and dir_perms != C.OWNER_ONLY_DIR_PERMS:
        sev = permission_severity(ssh_path, is_dir=True)
        result.findings.append(
            make_finding(
                ssh_path,
                f"SSH directory permissions {get_perms_string(ssh_path)} "
                f"(expected {C.SSH_SAFE_DIR_PERMS})",
                Category.SSH,
                sev,
            )
        )

    try:
        for entry in os.scandir(ssh_path):
            if not entry.is_file():
                continue
            path = entry.path
            if matches_exclude(path, config.exclude_patterns):
                continue

            content = read_file_content(path)
            if len(content) == 0:
                continue
            if not is_private_key(content):
                continue

            encrypted = is_encrypted(content)
            perms = get_numeric_perms(path)

            sev = Severity.INFO if encrypted else Severity.HIGH
            if perms >= 0 and (perms & C.WORLD_READ_BIT) != 0:
                sev = Severity.CRITICAL
            elif perms >= 0 and (perms & C.GROUP_READ_BIT) != 0:
                if sev < Severity.HIGH:
                    sev = Severity.HIGH

            if content.startswith(C.SSH_KEY_HEADERS[0]):
                key_type = "OpenSSH"
            elif content.startswith(C.SSH_KEY_HEADERS[1]):
                key_type = "RSA"
            elif content.startswith(C.SSH_KEY_HEADERS[2]):
                key_type = "ECDSA"
            elif content.startswith(C.SSH_KEY_HEADERS[3]):
                key_type = "DSA"
            else:
                key_type = "Unknown"

            desc = (
                f"{key_type} private key (passphrase-protected)"
                if encrypted
                else f"{key_type} private key (no passphrase)"
            )

            cred = Credential(
                source=path,
                cred_type="ssh_private_key",
                preview=f"{key_type} key",
                metadata={
                    "encrypted": str(encrypted).lower(),
                    "permissions": get_perms_string(path),
                },
            )
            result.findings.append(
                make_finding_with_cred(path, desc, Category.SSH, sev, cred)
            )
    except OSError as e:
        result.errors.append(f"Error scanning SSH keys: {e}")


def _scan_config(config: HarvestConfig, result: CollectorResult) -> None:
    config_path = expand_home(config, os.path.join(C.SSH_DIR, C.SSH_CONFIG))
    if not safe_file_exists(config_path):
        return

    lines = read_file_lines(config_path)
    host_count = 0
    weak_settings = []

    for line in lines:
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("host ") and not low.startswith("host *"):
            host_count += 1
        if low.startswith("passwordauthentication yes"):
            weak_settings.append("PasswordAuthentication enabled")
        if low.startswith("stricthostkeychecking no"):
            weak_settings.append("StrictHostKeyChecking disabled")

    if host_count > 0:
        result.findings.append(
            make_finding(
                config_path,
                f"SSH config with {host_count} host entries",
                Category.SSH,
                Severity.INFO,
            )
        )

    for setting in weak_settings:
        result.findings.append(
            make_finding(
                config_path, f"Weak SSH setting: {setting}", Category.SSH, Severity.MEDIUM
            )
        )


def _scan_authorized_keys(config: HarvestConfig, result: CollectorResult) -> None:
    ak_path = expand_home(config, os.path.join(C.SSH_DIR, C.SSH_AUTHORIZED_KEYS))
    if not safe_file_exists(ak_path):
        return

    key_count = 0
    for line in read_file_lines(ak_path):
        s = line.strip()
        if len(s) > 0 and not s.startswith("#"):
            key_count += 1

    if key_count > 0:
        result.findings.append(
            make_finding(
                ak_path, f"{key_count} authorized public keys", Category.SSH, Severity.INFO
            )
        )


def _scan_known_hosts(config: HarvestConfig, result: CollectorResult) -> None:
    kh_path = expand_home(config, os.path.join(C.SSH_DIR, C.SSH_KNOWN_HOSTS))
    if not safe_file_exists(kh_path):
        return

    host_count = 0
    for line in read_file_lines(kh_path):
        s = line.strip()
        if len(s) > 0 and not s.startswith("#"):
            host_count += 1

    if host_count > 0:
        result.findings.append(
            make_finding(kh_path, f"{host_count} known hosts", Category.SSH, Severity.INFO)
        )


def collect(config: HarvestConfig) -> CollectorResult:
    result = new_collector_result("ssh", Category.SSH)
    start = time.monotonic()

    _scan_keys(config, result)
    _scan_config(config, result)
    _scan_authorized_keys(config, result)
    _scan_known_hosts(config, result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
