"""
types.py  --  Domain types for the credential enumeration tool.

Python port of the Nim `types.nim`. Defines the core type hierarchy:
Severity (info -> critical) and Category (the seven collector modules) as
enums, plus the data records that flow through the program:

    Credential      -- one discovered secret's detail (source, type, preview)
    Finding         -- one credential-exposure result (path, severity, ...)
    CollectorResult -- all findings produced by one collector module
    ReportMetadata  -- run metadata (timestamp, target, version, duration)
    Report          -- the whole run: metadata + results + severity summary
    HarvestConfig   -- CLI-parsed runtime options

In Nim these were `object` types; in Python they are dataclasses, which give
us the same "plain record with named fields" shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Callable, Dict, List, Optional


class Severity(IntEnum):
    """How dangerous a finding is.

    IntEnum (not plain Enum) so that we can compare levels directly, e.g.
    `if sev < Severity.HIGH`, exactly like the ordered Nim enum. The integer
    value is only the rank; the wire string ("info", "low", ...) used in JSON
    output comes from `.wire`.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def wire(self) -> str:
        """Lowercase name used in JSON output (matches Nim's `$severity`)."""
        return self.name.lower()


class Category(Enum):
    """Which collector module a finding belongs to."""

    BROWSER = "browser"
    SSH = "ssh"
    CLOUD = "cloud"
    HISTORY = "history"
    KEYRING = "keyring"
    GIT = "git"
    APPTOKEN = "apptoken"

    def __str__(self) -> str:  # so f"{category}" prints "browser", like Nim
        return self.value


class OutputFormat(Enum):
    TERMINAL = "terminal"
    JSON = "json"
    BOTH = "both"


@dataclass
class Credential:
    """Detail about a single discovered credential (optional on a Finding)."""

    source: str
    cred_type: str
    preview: str
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    """One credential-exposure result discovered by a collector."""

    path: str
    category: Category
    severity: Severity
    description: str
    credential: Optional[Credential] = None
    permissions: str = ""
    modified: str = ""
    size: int = 0


@dataclass
class CollectorResult:
    """All findings produced by one collector module, plus timing/errors."""

    name: str
    category: Category
    findings: List[Finding] = field(default_factory=list)
    duration_ms: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class ReportMetadata:
    timestamp: str
    target: str
    version: str
    duration_ms: int
    modules: List[str]


@dataclass
class Report:
    metadata: ReportMetadata
    results: List[CollectorResult]
    summary: Dict[Severity, int]


@dataclass
class HarvestConfig:
    """Runtime options parsed from the command line."""

    target_dir: str
    enabled_modules: List[Category]
    exclude_patterns: List[str] = field(default_factory=list)
    output_format: OutputFormat = OutputFormat.TERMINAL
    output_path: str = ""
    dry_run: bool = False
    quiet: bool = False
    verbose: bool = False


# The signature every collector's `collect(config)` function implements.
CollectorProc = Callable[[HarvestConfig], CollectorResult]
