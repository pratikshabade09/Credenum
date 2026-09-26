"""
runner.py  --  Module dispatcher and report assembler.

Python port of the Nim `runner.nim`. `_get_collector` maps each Category to
its collector's `collect` function; `run_collectors` runs every enabled
module in order, times the whole run, tallies findings by severity, and packs
everything into a Report. The metadata timestamp is left blank here for the
CLI layer to stamp with wall-clock time (kept identical to the Nim split).
"""

from __future__ import annotations

import time

from . import config as C
from .collectors import apptoken, browser, cloud, git, history, keyring, ssh
from .types import (
    Category,
    CollectorProc,
    HarvestConfig,
    Report,
    ReportMetadata,
    Severity,
)

_COLLECTORS = {
    Category.BROWSER: browser.collect,
    Category.SSH: ssh.collect,
    Category.CLOUD: cloud.collect,
    Category.HISTORY: history.collect,
    Category.KEYRING: keyring.collect,
    Category.GIT: git.collect,
    Category.APPTOKEN: apptoken.collect,
}


def _get_collector(cat: Category) -> CollectorProc:
    return _COLLECTORS[cat]


def run_collectors(config: HarvestConfig) -> Report:
    start = time.monotonic()

    results = []
    module_names = []
    for cat in config.enabled_modules:
        module_names.append(C.MODULE_NAMES[cat])
        results.append(_get_collector(cat)(config))

    duration_ms = int((time.monotonic() - start) * 1000)

    summary = {sev: 0 for sev in Severity}
    for res in results:
        for finding in res.findings:
            summary[finding.severity] += 1

    return Report(
        metadata=ReportMetadata(
            timestamp="",
            target=config.target_dir,
            version=C.APP_VERSION,
            duration_ms=duration_ms,
            modules=module_names,
        ),
        results=results,
        summary=summary,
    )
