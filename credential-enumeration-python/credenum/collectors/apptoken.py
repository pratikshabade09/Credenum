"""
apptoken.py  --  Application token and database credential collector.

Python port of the Nim `apptoken.nim`. The broadest collector: it checks
desktop-app data dirs, database credential files, package-registry configs
and infrastructure-tool tokens.

  app dirs           -- Slack / Discord / VS Code data + VS Code settings.json
  scan_db_cred_files -- .pgpass (Postgres), .my.cnf (MySQL), .rediscli_auth,
                        .mongorc.js
  scan_docker_config -- .docker/config.json registry auth tokens
  scan_netrc         -- .netrc machine entries with passwords
  scan_dev_token_files   -- .npmrc (_authToken), .pypirc, gh CLI hosts.yml
  scan_infra_token_files -- Terraform Cloud, Vault, Helm, rclone

Severity escalates for world-readable files and for files that actually
contain a plaintext password/token.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .. import config as C
from ..base import (
    expand_home,
    is_group_readable,
    is_world_readable,
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


@dataclass
class AppTarget:
    path: str
    name: str
    description: str
    is_dir: bool


def _file_severity(path: str) -> Severity:
    if is_world_readable(path):
        return Severity.CRITICAL
    if is_group_readable(path):
        return Severity.HIGH
    return Severity.MEDIUM


def _scan_app_dir(config: HarvestConfig, target: AppTarget, result: CollectorResult) -> None:
    full_path = expand_home(config, target.path)
    if target.is_dir:
        if not safe_dir_exists(full_path):
            return
        sev = permission_severity(full_path, is_dir=True)
        result.findings.append(make_finding(full_path, target.description, Category.APPTOKEN, sev))
    else:
        if not safe_file_exists(full_path):
            return
        result.findings.append(
            make_finding(full_path, target.description, Category.APPTOKEN, _file_severity(full_path))
        )


def _scan_db_cred_files(config: HarvestConfig, result: CollectorResult) -> None:
    # PostgreSQL .pgpass
    pgpass_path = expand_home(config, C.PGPASS)
    if safe_file_exists(pgpass_path):
        entry_count = 0
        for line in read_file_lines(pgpass_path):
            s = line.strip()
            if len(s) > 0 and not s.startswith("#"):
                entry_count += 1
        sev = Severity.CRITICAL if is_world_readable(pgpass_path) else Severity.HIGH
        cred = Credential(
            source=pgpass_path,
            cred_type="postgresql_credentials",
            preview=f"{entry_count} database connection entries",
            metadata={"entry_count": str(entry_count)},
        )
        result.findings.append(
            make_finding_with_cred(
                pgpass_path,
                f"PostgreSQL password file with {entry_count} entries",
                Category.APPTOKEN,
                sev,
                cred,
            )
        )

    # MySQL .my.cnf
    mycnf_path = expand_home(config, C.MY_CNF)
    if safe_file_exists(mycnf_path):
        content = read_file_content(mycnf_path)
        has_password = "password" in content.lower()
        if is_world_readable(mycnf_path):
            sev = Severity.CRITICAL
        elif has_password:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        result.findings.append(
            make_finding(
                mycnf_path,
                "MySQL configuration" + (" (contains password)" if has_password else ""),
                Category.APPTOKEN,
                sev,
            )
        )

    # Redis
    redis_path = expand_home(config, C.REDIS_CONF)
    if safe_file_exists(redis_path):
        sev = Severity.CRITICAL if is_world_readable(redis_path) else Severity.HIGH
        result.findings.append(
            make_finding(redis_path, "Redis CLI authentication file", Category.APPTOKEN, sev)
        )

    # MongoDB .mongorc.js
    mongo_path = expand_home(config, C.MONGO_RC)
    if safe_file_exists(mongo_path):
        content = read_file_content(mongo_path).lower()
        has_creds = "password" in content or "auth" in content
        if is_world_readable(mongo_path):
            sev = Severity.CRITICAL
        elif has_creds:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        result.findings.append(
            make_finding(
                mongo_path,
                "MongoDB RC file" + (" (may contain credentials)" if has_creds else ""),
                Category.APPTOKEN,
                sev,
            )
        )


def _scan_netrc(config: HarvestConfig, result: CollectorResult) -> None:
    path = expand_home(config, C.NETRC_FILE)
    if not safe_file_exists(path):
        return

    machine_count = 0
    has_password = False
    for line in read_file_content(path).splitlines():
        low = line.strip().lower()
        if low.startswith("machine "):
            machine_count += 1
        if "password " in low:
            has_password = True

    if is_world_readable(path):
        sev = Severity.CRITICAL
    elif has_password:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM

    cred = Credential(
        source=path,
        cred_type="netrc_credentials",
        preview=f"{machine_count} machine entries",
        metadata={"machines": str(machine_count), "has_password": str(has_password).lower()},
    )
    result.findings.append(
        make_finding_with_cred(
            path, f"Netrc credential file with {machine_count} entries", Category.APPTOKEN, sev, cred
        )
    )


def _scan_dev_token_files(config: HarvestConfig, result: CollectorResult) -> None:
    # npm
    npmrc_path = expand_home(config, C.NPMRC_FILE)
    if safe_file_exists(npmrc_path):
        content = read_file_content(npmrc_path)
        has_token = "_authToken" in content or "_auth" in content
        if is_world_readable(npmrc_path):
            sev = Severity.CRITICAL
        elif has_token:
            sev = Severity.HIGH
        else:
            sev = Severity.INFO
        if has_token:
            result.findings.append(
                make_finding(npmrc_path, "npm registry authentication token", Category.APPTOKEN, sev)
            )

    # PyPI
    pypirc_path = expand_home(config, C.PYPIRC_FILE)
    if safe_file_exists(pypirc_path):
        content = read_file_content(pypirc_path)
        has_password = "password" in content.lower()
        if is_world_readable(pypirc_path):
            sev = Severity.CRITICAL
        elif has_password:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        result.findings.append(
            make_finding(
                pypirc_path,
                "PyPI configuration" + (" (contains credentials)" if has_password else ""),
                Category.APPTOKEN,
                sev,
            )
        )

    # GitHub CLI
    gh_path = expand_home(config, C.GH_CLI_HOSTS)
    if safe_file_exists(gh_path):
        content = read_file_content(gh_path)
        has_oauth = "oauth_token" in content.lower()
        if is_world_readable(gh_path):
            sev = Severity.CRITICAL
        elif has_oauth:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        result.findings.append(
            make_finding(gh_path, "GitHub CLI OAuth token", Category.APPTOKEN, sev)
        )


def _scan_infra_token_files(config: HarvestConfig, result: CollectorResult) -> None:
    # Terraform Cloud
    tf_path = expand_home(config, C.TERRAFORM_CREDS)
    if safe_file_exists(tf_path):
        content = read_file_content(tf_path)
        has_token = "token" in content.lower()
        if is_world_readable(tf_path):
            sev = Severity.CRITICAL
        elif has_token:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        result.findings.append(
            make_finding(tf_path, "Terraform Cloud API token", Category.APPTOKEN, sev)
        )

    # Vault
    vault_path = expand_home(config, C.VAULT_TOKEN_FILE)
    if safe_file_exists(vault_path):
        sev = Severity.CRITICAL if is_world_readable(vault_path) else Severity.HIGH
        result.findings.append(
            make_finding(vault_path, "HashiCorp Vault token", Category.APPTOKEN, sev)
        )

    # Helm
    helm_path = expand_home(config, C.HELM_REPOS)
    if safe_file_exists(helm_path):
        content = read_file_content(helm_path)
        has_password = "password" in content.lower()
        if is_world_readable(helm_path):
            sev = Severity.CRITICAL
        elif has_password:
            sev = Severity.HIGH
        else:
            sev = Severity.INFO
        if has_password:
            result.findings.append(
                make_finding(helm_path, "Helm repository credentials", Category.APPTOKEN, sev)
            )

    # rclone
    rclone_path = expand_home(config, C.RCLONE_CONF)
    if safe_file_exists(rclone_path):
        content = read_file_content(rclone_path).lower()
        has_creds = "pass" in content or "token" in content or "key" in content
        if is_world_readable(rclone_path):
            sev = Severity.CRITICAL
        elif has_creds:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        result.findings.append(
            make_finding(
                rclone_path,
                "Rclone cloud storage configuration" + (" (contains credentials)" if has_creds else ""),
                Category.APPTOKEN,
                sev,
            )
        )


def _scan_docker_config(config: HarvestConfig, result: CollectorResult) -> None:
    docker_path = expand_home(config, C.DOCKER_CONFIG)
    if not safe_file_exists(docker_path):
        return
    content = read_file_content(docker_path)
    has_auth = '"auth"' in content or '"auths"' in content
    if is_world_readable(docker_path):
        sev = Severity.CRITICAL
    elif has_auth:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM
    cred = Credential(
        source=docker_path,
        cred_type="docker_registry_auth",
        preview="Registry authentication tokens present" if has_auth else "No auth data",
        metadata={},
    )
    result.findings.append(
        make_finding_with_cred(
            docker_path,
            "Docker configuration" + (" with registry auth tokens" if has_auth else ""),
            Category.APPTOKEN,
            sev,
            cred,
        )
    )


def collect(config: HarvestConfig) -> CollectorResult:
    result = new_collector_result("apptoken", Category.APPTOKEN)
    start = time.monotonic()

    app_targets = [
        AppTarget(C.SLACK_DIR, "Slack", "Slack desktop session data", True),
        AppTarget(C.DISCORD_DIR, "Discord", "Discord desktop session data", True),
        AppTarget(C.VSCODE_DIR, "VS Code", "VS Code configuration directory", True),
        AppTarget(C.VSCODE_USER_SETTINGS, "VS Code Settings", "VS Code user settings (may contain tokens)", False),
    ]
    for target in app_targets:
        _scan_app_dir(config, target, result)

    _scan_db_cred_files(config, result)
    _scan_docker_config(config, result)
    _scan_netrc(config, result)
    _scan_dev_token_files(config, result)
    _scan_infra_token_files(config, result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
