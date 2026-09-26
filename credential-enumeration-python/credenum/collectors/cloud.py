"""
cloud.py  --  Cloud provider configuration collector.

Python port of the Nim `cloud.nim`. Detects credential exposure across four
platforms:

  scan_aws        -- ~/.aws/credentials: count profiles, static keys (AKIA)
                     and session keys (ASIA); ~/.aws/config: SSO / MFA.
  scan_gcp        -- application default credentials (service-account vs user)
                     plus any *.json service-account keys under ~/.config/gcloud.
  scan_azure      -- access-token / MSAL token-cache files.
  scan_kubernetes -- ~/.kube/config: count contexts and users, detect token-
                     vs certificate-based auth.

Severity escalates for static keys, service accounts, token auth, and any
world-readable file.
"""

from __future__ import annotations

import os
import time

from .. import config as C
from ..base import (
    expand_home,
    is_world_readable,
    make_finding,
    make_finding_with_cred,
    new_collector_result,
    read_file_content,
    read_file_lines,
    safe_dir_exists,
    safe_file_exists,
)
from ..types import Category, CollectorResult, Credential, HarvestConfig, Severity


def _scan_aws(config: HarvestConfig, result: CollectorResult) -> None:
    cred_path = expand_home(config, C.AWS_CREDENTIALS)
    config_path = expand_home(config, C.AWS_CONFIG)

    if safe_file_exists(cred_path):
        lines = read_file_content(cred_path).splitlines()
        profile_count = 0
        static_keys = 0
        session_keys = 0

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("["):
                profile_count += 1
            if stripped.lower().startswith("aws_access_key_id"):
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    key_val = parts[1].strip()
                    if key_val.startswith(C.AWS_STATIC_KEY_PREFIX):
                        static_keys += 1
                    elif key_val.startswith(C.AWS_SESSION_KEY_PREFIX):
                        session_keys += 1

        sev = Severity.MEDIUM
        if static_keys > 0:
            sev = Severity.HIGH
        if is_world_readable(cred_path):
            sev = Severity.CRITICAL

        cred = Credential(
            source=cred_path,
            cred_type="aws_credentials",
            preview=f"{profile_count} profiles, {static_keys} static keys",
            metadata={
                "profiles": str(profile_count),
                "static_keys": str(static_keys),
                "session_keys": str(session_keys),
            },
        )
        result.findings.append(
            make_finding_with_cred(
                cred_path,
                f"AWS credentials file: {profile_count} profiles, "
                f"{static_keys} static keys, {session_keys} session keys",
                Category.CLOUD,
                sev,
                cred,
            )
        )

    if safe_file_exists(config_path):
        profile_count = 0
        has_sso = False
        has_mfa = False
        for line in read_file_lines(config_path):
            stripped = line.strip()
            low = stripped.lower()
            if stripped.startswith("["):
                profile_count += 1
            if "sso_" in low:
                has_sso = True
            if "mfa_serial" in low:
                has_mfa = True

        desc = f"AWS config: {profile_count} profiles"
        if has_sso:
            desc += ", SSO configured"
        if has_mfa:
            desc += ", MFA configured"
        result.findings.append(make_finding(config_path, desc, Category.CLOUD, Severity.INFO))


def _scan_gcp(config: HarvestConfig, result: CollectorResult) -> None:
    gcp_dir = expand_home(config, C.GCP_CONFIG_DIR)
    adc_path = expand_home(config, C.GCP_APP_DEFAULT_CREDS)

    if safe_file_exists(adc_path):
        content = read_file_content(adc_path)
        is_service_account = C.GCP_SERVICE_ACCOUNT_PATTERN in content.lower()
        sev = Severity.HIGH if is_service_account else Severity.MEDIUM
        cred_type_str = "service_account" if is_service_account else "authorized_user"

        cred = Credential(
            source=adc_path,
            cred_type="gcp_credentials",
            preview="Service account key" if is_service_account else "User credentials",
            metadata={"type": cred_type_str},
        )
        result.findings.append(
            make_finding_with_cred(
                adc_path,
                f"GCP application default credentials ({cred_type_str})",
                Category.CLOUD,
                sev,
                cred,
            )
        )

    if safe_dir_exists(gcp_dir):
        try:
            for entry in os.scandir(gcp_dir):
                if not entry.is_file():
                    continue
                path = entry.path
                if path.endswith(".json") and path != adc_path:
                    content = read_file_content(path)
                    if C.GCP_SERVICE_ACCOUNT_PATTERN in content.lower():
                        result.findings.append(
                            make_finding(
                                path, "GCP service account key file", Category.CLOUD, Severity.HIGH
                            )
                        )
        except OSError as e:
            result.errors.append(f"Error scanning GCP directory: {e}")


def _scan_azure(config: HarvestConfig, result: CollectorResult) -> None:
    az_dir = expand_home(config, C.AZURE_DIR)
    if not safe_dir_exists(az_dir):
        return

    token_paths = [
        expand_home(config, C.AZURE_ACCESS_TOKENS),
        expand_home(config, C.AZURE_MSAL_TOKEN_CACHE),
    ]
    found_tokens = False
    for path in token_paths:
        if safe_file_exists(path):
            found_tokens = True
            sev = Severity.CRITICAL if is_world_readable(path) else Severity.MEDIUM
            result.findings.append(
                make_finding(path, "Azure token cache", Category.CLOUD, sev)
            )

    if not found_tokens:
        result.findings.append(
            make_finding(
                az_dir, "Azure CLI configuration directory", Category.CLOUD, Severity.INFO
            )
        )


def _scan_kubernetes(config: HarvestConfig, result: CollectorResult) -> None:
    kube_path = expand_home(config, C.KUBE_CONFIG)
    if not safe_file_exists(kube_path):
        return

    lines = read_file_content(kube_path).splitlines()
    context_count = 0
    user_count = 0
    has_token_auth = False
    has_cert_auth = False
    in_contexts = False
    in_users = False

    for line in lines:
        stripped = line.strip()
        if stripped == C.KUBE_CONTEXT_MARKER:
            in_contexts = True
            in_users = False
        elif stripped == C.KUBE_USER_MARKER:
            in_users = True
            in_contexts = False
        elif len(stripped) > 0 and not stripped.startswith(" ") and not stripped.startswith("-"):
            in_contexts = False
            in_users = False

        if in_contexts and stripped.startswith("- context:"):
            context_count += 1
        if in_users and stripped.startswith("- name:"):
            user_count += 1
        if "token:" in stripped:
            has_token_auth = True
        if "client-certificate-data:" in stripped:
            has_cert_auth = True

    if is_world_readable(kube_path):
        sev = Severity.CRITICAL
    elif has_token_auth:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM

    cred = Credential(
        source=kube_path,
        cred_type="kubernetes_config",
        preview=f"{context_count} contexts, {user_count} users",
        metadata={
            "contexts": str(context_count),
            "users": str(user_count),
            "token_auth": str(has_token_auth).lower(),
            "cert_auth": str(has_cert_auth).lower(),
        },
    )
    result.findings.append(
        make_finding_with_cred(
            kube_path,
            f"Kubernetes config: {context_count} contexts, {user_count} users",
            Category.CLOUD,
            sev,
            cred,
        )
    )


def collect(config: HarvestConfig) -> CollectorResult:
    result = new_collector_result("cloud", Category.CLOUD)
    start = time.monotonic()

    _scan_aws(config, result)
    _scan_gcp(config, result)
    _scan_azure(config, result)
    _scan_kubernetes(config, result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
