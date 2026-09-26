"""
json_report.py  --  JSON report serializer.

Python port of the Nim `output/json.nim`. Converts the Report object tree into
a plain dict (which is trivially serialized by the stdlib `json` module) with
the same shape the Nim tool emits:

    { "metadata": {...}, "modules": [ ... ], "summary": {severity: count} }

`render_json` pretty-prints to stdout and, if an output path is given, also
writes the JSON to that file. (Named json_report, not json, so it does not
shadow the standard library module it imports.)
"""

from __future__ import annotations

import json
import sys

from ..types import CollectorResult, Credential, Finding, Report, Severity


def _credential_to_dict(cred: Credential) -> dict:
    return {
        "source": cred.source,
        "type": cred.cred_type,
        "preview": cred.preview,
        "metadata": dict(cred.metadata),
    }


def _finding_to_dict(f: Finding) -> dict:
    d = {
        "path": f.path,
        "category": str(f.category),
        "severity": f.severity.wire,
        "description": f.description,
        "permissions": f.permissions,
        "modified": f.modified,
        "size": f.size,
    }
    if f.credential is not None:
        d["credential"] = _credential_to_dict(f.credential)
    return d


def _collector_result_to_dict(res: CollectorResult) -> dict:
    return {
        "name": res.name,
        "category": str(res.category),
        "findings": [_finding_to_dict(f) for f in res.findings],
        "duration_ms": res.duration_ms,
        "errors": list(res.errors),
    }


def report_to_dict(report: Report) -> dict:
    return {
        "metadata": {
            "timestamp": report.metadata.timestamp,
            "target": report.metadata.target,
            "version": report.metadata.version,
            "duration_ms": report.metadata.duration_ms,
            "modules": list(report.metadata.modules),
        },
        "modules": [_collector_result_to_dict(res) for res in report.results],
        "summary": {sev.wire: report.summary[sev] for sev in Severity},
    }


def render_json(report: Report, output_path: str) -> None:
    pretty = json.dumps(report_to_dict(report), indent=2)

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(pretty + "\n")
        except OSError as e:
            print(f"Warning: could not write to {output_path}: {e}", file=sys.stderr)

    print(pretty)
