"""
config.py  --  Application constants and default configuration.

Python port of the Nim `config.nim`. This is the single place that holds
every configurable value: which modules exist and what they scan, the
filesystem paths each collector targets, the regex/string patterns used to
spot secrets, permission constants, ANSI colour codes, box-drawing
characters, the ASCII banner, and the `default_config()` factory.

Keeping all of this data in one file (instead of scattering literals through
the collectors) is deliberate: a reviewer can audit exactly what the tool
looks for by reading one file, and adding a new target is a one-line change.
"""

from __future__ import annotations

import os
from typing import Dict, List

from .types import Category, HarvestConfig, OutputFormat, Severity

APP_VERSION = "0.1.0"
BINARY_NAME = "credenum"

# The seven modules, in the order they run.
ALL_MODULES: List[Category] = [
    Category.BROWSER,
    Category.SSH,
    Category.CLOUD,
    Category.HISTORY,
    Category.KEYRING,
    Category.GIT,
    Category.APPTOKEN,
]

MODULE_NAMES: Dict[Category, str] = {
    Category.BROWSER: "browser",
    Category.SSH: "ssh",
    Category.CLOUD: "cloud",
    Category.HISTORY: "history",
    Category.KEYRING: "keyring",
    Category.GIT: "git",
    Category.APPTOKEN: "apptoken",
}

MODULE_DESCRIPTIONS: Dict[Category, str] = {
    Category.BROWSER: "Browser credential stores",
    Category.SSH: "SSH keys and configuration",
    Category.CLOUD: "Cloud provider configurations",
    Category.HISTORY: "Shell history and environment files",
    Category.KEYRING: "Keyrings and password stores",
    Category.GIT: "Git credential stores",
    Category.APPTOKEN: "Application tokens and database configs",
}

# ----------------------------------------------------------------------------
# Browser paths
# ----------------------------------------------------------------------------
FIREFOX_DIR = ".mozilla/firefox"
FIREFOX_PROFILES_INI = "profiles.ini"
FIREFOX_LOGINS_FILE = "logins.json"
FIREFOX_COOKIES_DB = "cookies.sqlite"
FIREFOX_KEY_DB = "key4.db"

CHROMIUM_DIRS = [
    ".config/google-chrome",
    ".config/chromium",
    ".config/brave",
    ".config/vivaldi",
]
CHROMIUM_LOGIN_DATA = "Login Data"
CHROMIUM_COOKIES = "Cookies"
CHROMIUM_WEB_DATA = "Web Data"

# ----------------------------------------------------------------------------
# SSH paths / markers
# ----------------------------------------------------------------------------
SSH_DIR = ".ssh"
SSH_CONFIG = "config"
SSH_AUTHORIZED_KEYS = "authorized_keys"
SSH_KNOWN_HOSTS = "known_hosts"

SSH_KEY_HEADERS = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
]

SSH_ENCRYPTED_MARKERS = [
    "ENCRYPTED",
    "Proc-Type: 4,ENCRYPTED",
    "aes256-ctr",
    "aes128-ctr",
    "bcrypt",
]

SSH_SAFE_KEY_PERMS = "0600"
SSH_SAFE_DIR_PERMS = "0700"

# ----------------------------------------------------------------------------
# Cloud paths / markers
# ----------------------------------------------------------------------------
AWS_CREDENTIALS = ".aws/credentials"
AWS_CONFIG = ".aws/config"
AWS_STATIC_KEY_PREFIX = "AKIA"
AWS_SESSION_KEY_PREFIX = "ASIA"

GCP_CONFIG_DIR = ".config/gcloud"
GCP_APP_DEFAULT_CREDS = ".config/gcloud/application_default_credentials.json"
GCP_SERVICE_ACCOUNT_PATTERN = "service_account"

AZURE_DIR = ".azure"
AZURE_ACCESS_TOKENS = ".azure/accessTokens.json"
AZURE_MSAL_TOKEN_CACHE = ".azure/msal_token_cache.json"

KUBE_CONFIG = ".kube/config"
KUBE_CONTEXT_MARKER = "contexts:"
KUBE_USER_MARKER = "users:"

# ----------------------------------------------------------------------------
# History / env
# ----------------------------------------------------------------------------
HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    ".fish_history",
    ".sh_history",
    ".python_history",
]

SECRET_PATTERNS = [
    "KEY=",
    "SECRET=",
    "TOKEN=",
    "PASSWORD=",
    "PASSWD=",
    "API_KEY=",
    "ACCESS_KEY=",
    "PRIVATE_KEY=",
    "AUTH_TOKEN=",
    "CREDENTIALS=",
]

# Each pattern uses ".*" to mean "then, later on the same line". They are
# matched by the ordered-substring search in history.py, not by a regex engine.
HISTORY_COMMAND_PATTERNS = [
    "curl.*-h.*authoriz",
    "curl.*-u ",
    "wget.*--header.*authoriz",
    "wget.*--password",
    "mysql.*-p",
    "psql.*password",
    "sshpass",
]

ENV_FILE_NAME = ".env"
ENV_FILE_PATTERNS = [".env", ".env.local", ".env.production", ".env.staging"]

# ----------------------------------------------------------------------------
# Keyrings / password managers
# ----------------------------------------------------------------------------
GNOME_KEYRING_DIR = ".local/share/keyrings"
KDE_WALLET_DIR = ".local/share/kwalletd"
KEEPASS_EXTENSION = ".kdbx"
PASS_STORE_DIR = ".password-store"
BITWARDEN_DIR = ".config/Bitwarden"
BITWARDEN_CLI_DIR = ".config/Bitwarden CLI"

# ----------------------------------------------------------------------------
# Git
# ----------------------------------------------------------------------------
GIT_CREDENTIALS = ".git-credentials"
GIT_CONFIG = ".gitconfig"
GIT_CONFIG_LOCAL = ".config/git/config"
GIT_CREDENTIAL_HELPER_KEY = "credential"
GITHUB_TOKEN_PATTERNS = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
GITLAB_TOKEN_PATTERNS = ["glpat-"]

# ----------------------------------------------------------------------------
# Application tokens / database configs
# ----------------------------------------------------------------------------
SLACK_DIR = ".config/Slack"
DISCORD_DIR = ".config/discord"
VSCODE_DIR = ".config/Code"
VSCODE_USER_SETTINGS = ".config/Code/User/settings.json"
PGPASS = ".pgpass"
MY_CNF = ".my.cnf"
REDIS_CONF = ".rediscli_auth"
MONGO_RC = ".mongorc.js"
DOCKER_CONFIG = ".docker/config.json"

NETRC_FILE = ".netrc"
NPMRC_FILE = ".npmrc"
PYPIRC_FILE = ".pypirc"
GH_CLI_HOSTS = ".config/gh/hosts.yml"
TERRAFORM_CREDS = ".terraform.d/credentials.tfrc.json"
VAULT_TOKEN_FILE = ".vault-token"
HELM_REPOS = ".config/helm/repositories.yaml"
RCLONE_CONF = ".config/rclone/rclone.conf"

# ----------------------------------------------------------------------------
# Permission bits (octal)
# ----------------------------------------------------------------------------
OWNER_ONLY_FILE_PERMS = 0o600
OWNER_ONLY_DIR_PERMS = 0o700
GROUP_READ_BIT = 0o040
WORLD_READ_BIT = 0o004

# ----------------------------------------------------------------------------
# Terminal presentation
# ----------------------------------------------------------------------------
BANNER = r"""
   ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
  ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║██║   ██║████╗ ████║
  ██║     ██████╔╝█████╗  ██║  ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
  ██║     ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
  ╚██████╗██║  ██║███████╗██████╔╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
   ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"""

BANNER_TAGLINE = "Post-access credential exposure detection"

COLOR_RESET = "\x1b[0m"
COLOR_BOLD = "\x1b[1m"
COLOR_DIM = "\x1b[2m"
COLOR_RED = "\x1b[31m"
COLOR_GREEN = "\x1b[32m"
COLOR_YELLOW = "\x1b[33m"
COLOR_BLUE = "\x1b[34m"
COLOR_MAGENTA = "\x1b[35m"
COLOR_CYAN = "\x1b[36m"
COLOR_WHITE = "\x1b[37m"
COLOR_BOLD_RED = "\x1b[1;31m"
COLOR_BOLD_GREEN = "\x1b[1;32m"
COLOR_BOLD_YELLOW = "\x1b[1;33m"
COLOR_BOLD_MAGENTA = "\x1b[1;35m"
COLOR_BOLD_CYAN = "\x1b[1;36m"

SEVERITY_COLORS: Dict[Severity, str] = {
    Severity.INFO: COLOR_DIM,
    Severity.LOW: COLOR_CYAN,
    Severity.MEDIUM: COLOR_YELLOW,
    Severity.HIGH: COLOR_BOLD_MAGENTA,
    Severity.CRITICAL: COLOR_BOLD_RED,
}

SEVERITY_LABELS: Dict[Severity, str] = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}

BOX_TOP_LEFT = "┌"
BOX_TOP_RIGHT = "┐"
BOX_BOTTOM_LEFT = "└"
BOX_BOTTOM_RIGHT = "┘"
BOX_HORIZONTAL = "─"
BOX_VERTICAL = "│"
BOX_TEE_RIGHT = "├"
BOX_TEE_LEFT = "┤"
BOX_CROSS = "┼"
BULLET = "●"
ARROW = "▸"
CHECK_MARK = "✓"
CROSS_MARK = "✗"


def default_config() -> HarvestConfig:
    """Build the default runtime configuration (scan the current user's home).

    The home path is given a trailing separator to match the original Nim
    tool's `getHomeDir()`, which returns e.g. '/home/user/'. This keeps the
    'target' field in the report byte-identical to the Nim output. A path
    passed explicitly via --target is used verbatim, exactly as in Nim.
    """
    home = os.path.expanduser("~")
    if not home.endswith(os.sep):
        home += os.sep
    return HarvestConfig(
        target_dir=home,
        enabled_modules=list(ALL_MODULES),
        exclude_patterns=[],
        output_format=OutputFormat.TERMINAL,
        output_path="",
        dry_run=False,
        quiet=False,
        verbose=False,
    )