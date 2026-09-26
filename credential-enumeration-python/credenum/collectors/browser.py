"""
browser.py  --  Browser credential store collector.

Python port of the Nim `browser.nim`. Finds the SQLite/JSON databases that
Firefox and Chromium-family browsers use to store passwords, cookies and
autofill/payment data:

  scan_firefox  -- read profiles.ini to find each profile dir, then check for
                   logins.json (saved passwords), cookies.sqlite, key4.db
                   (the master-key DB that decrypts logins.json).
  scan_chromium -- for Chrome / Chromium / Brave / Vivaldi and each of their
                   'Default' / 'Profile N' dirs, check for 'Login Data',
                   'Cookies' and 'Web Data'.

The tool only reports that these databases *exist and are readable* and rates
them by permission exposure -- it never opens or decrypts them.
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
    new_collector_result,
    read_file_lines,
    safe_dir_exists,
    safe_file_exists,
)
from ..types import Category, CollectorResult, HarvestConfig, Severity


def _perm_severity(path: str) -> Severity:
    if is_world_readable(path):
        return Severity.CRITICAL
    if is_group_readable(path):
        return Severity.HIGH
    return Severity.MEDIUM


def _scan_firefox(config: HarvestConfig, result: CollectorResult) -> None:
    firefox_path = expand_home(config, C.FIREFOX_DIR)
    if not safe_dir_exists(firefox_path):
        return

    profiles_ini_path = os.path.join(firefox_path, C.FIREFOX_PROFILES_INI)
    if not safe_file_exists(profiles_ini_path):
        return

    profiles = []
    current_path = ""
    for line in read_file_lines(profiles_ini_path):
        stripped = line.strip()
        if stripped.startswith("[Profile"):
            if len(current_path) > 0:
                profiles.append(current_path)
            current_path = ""
        if stripped.lower().startswith("path="):
            current_path = stripped.split("=", 1)[1]
    if len(current_path) > 0:
        profiles.append(current_path)

    for profile in profiles:
        profile_dir = profile if profile.startswith("/") else os.path.join(firefox_path, profile)
        if not safe_dir_exists(profile_dir):
            continue

        cred_files = [
            (C.FIREFOX_LOGINS_FILE, "Firefox stored logins database"),
            (C.FIREFOX_COOKIES_DB, "Firefox cookies database"),
            (C.FIREFOX_KEY_DB, "Firefox key database"),
        ]
        for file_name, desc in cred_files:
            file_path = os.path.join(profile_dir, file_name)
            if safe_file_exists(file_path):
                result.findings.append(
                    make_finding(file_path, desc, Category.BROWSER, _perm_severity(file_path))
                )


def _scan_chromium(config: HarvestConfig, result: CollectorResult) -> None:
    for chromium_dir in C.CHROMIUM_DIRS:
        base_path = expand_home(config, chromium_dir)
        if not safe_dir_exists(base_path):
            continue

        browser_name = chromium_dir.split("/")[-1]

        default_profile = os.path.join(base_path, "Default")
        profile_dirs = []
        if safe_dir_exists(default_profile):
            profile_dirs.append(default_profile)

        try:
            for entry in os.scandir(base_path):
                if entry.is_dir(follow_symlinks=False) and os.path.basename(entry.path).startswith("Profile "):
                    profile_dirs.append(entry.path)
        except OSError as e:
            result.errors.append(f"Error walking {browser_name} profiles: {e}")

        for profile_dir in profile_dirs:
            cred_files = [
                (C.CHROMIUM_LOGIN_DATA, f"{browser_name} stored login database"),
                (C.CHROMIUM_COOKIES, f"{browser_name} cookies database"),
                (C.CHROMIUM_WEB_DATA, f"{browser_name} web data (autofill, payment methods)"),
            ]
            for file_name, desc in cred_files:
                file_path = os.path.join(profile_dir, file_name)
                if safe_file_exists(file_path):
                    result.findings.append(
                        make_finding(file_path, desc, Category.BROWSER, _perm_severity(file_path))
                    )


def collect(config: HarvestConfig) -> CollectorResult:
    result = new_collector_result("browser", Category.BROWSER)
    start = time.monotonic()

    _scan_firefox(config, result)
    _scan_chromium(config, result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
