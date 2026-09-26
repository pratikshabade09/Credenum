"""
terminal.py  --  ANSI terminal renderer with box-drawing output.

Python port of the Nim `output/terminal.nim`. Renders the full report to the
terminal inside Unicode box-drawn sections, one per module, ending with a
severity summary.

The fiddly part is alignment: the lines contain ANSI colour codes (which take
zero display columns) and Unicode box characters, so a naive len() would
mis-count. `visual_len` measures true display width by skipping ANSI escape
sequences, and `truncate_visual` cuts a string to a column budget without
slicing through an escape sequence. Everything is laid out to a fixed
78-column box.
"""

from __future__ import annotations

import sys

from .. import config as C
from ..types import Finding, Report, Severity

BOX_WIDTH = 78
INNER_WIDTH = BOX_WIDTH - 2


def _w(s: str) -> None:
    sys.stdout.write(s)


def _wl(s: str = "") -> None:
    sys.stdout.write(s + "\n")


def visual_len(s: str) -> int:
    """Number of visible columns, ignoring ANSI escape sequences."""
    i = 0
    n = 0
    length = len(s)
    while i < length:
        if s[i] == "\x1b":
            while i < length and s[i] != "m":
                i += 1
            if i < length:
                i += 1  # skip the trailing 'm'
        else:
            n += 1
            i += 1
    return n


def truncate_visual(s: str, max_len: int) -> str:
    """Truncate to max_len visible columns, appending '...', keeping colours."""
    out = []
    v_len = 0
    i = 0
    length = len(s)
    while i < length:
        if s[i] == "\x1b":
            start = i
            while i < length and s[i] != "m":
                i += 1
            if i < length:
                i += 1
            out.append(s[start:i])
        else:
            if v_len >= max_len - 3:
                out.append("...")
                return "".join(out)
            out.append(s[i])
            v_len += 1
            i += 1
    return "".join(out)


def _write_box_line(content: str) -> None:
    """Write a content line and pad it to the right box border."""
    _w(content)
    pad = BOX_WIDTH - visual_len(content) - 1
    if pad > 0:
        _w(" " * pad)
    _wl(C.BOX_VERTICAL)


def _sev_badge(sev: Severity) -> str:
    return C.SEVERITY_COLORS[sev] + C.COLOR_BOLD + " " + C.SEVERITY_LABELS[sev] + " " + C.COLOR_RESET


def _box_line(width: int) -> str:
    return C.BOX_TOP_LEFT + C.BOX_HORIZONTAL * (width - 2) + C.BOX_TOP_RIGHT


def _box_bottom(width: int) -> str:
    return C.BOX_BOTTOM_LEFT + C.BOX_HORIZONTAL * (width - 2) + C.BOX_BOTTOM_RIGHT


def _box_mid(width: int) -> str:
    return C.BOX_TEE_RIGHT + C.BOX_HORIZONTAL * (width - 2) + C.BOX_TEE_LEFT


def render_banner(quiet: bool) -> None:
    if quiet:
        return
    _w(C.COLOR_BOLD_RED)
    _wl(C.BANNER)
    _w(C.COLOR_RESET)
    _wl("")
    _w("  ")
    _w(C.COLOR_DIM)
    _w(C.BANNER_TAGLINE)
    _w(" v")
    _w(C.APP_VERSION)
    _wl(C.COLOR_RESET)
    _wl("")


def _render_module_header(name: str, desc: str, finding_count: int, duration_ms: int) -> None:
    _wl(_box_line(BOX_WIDTH))
    label = (
        C.BOX_VERTICAL + " " + C.COLOR_BOLD + C.COLOR_CYAN + name.upper() + C.COLOR_RESET
        + C.COLOR_DIM + " " + C.ARROW + " " + desc + C.COLOR_RESET
    )
    stats = f"{finding_count} findings" + C.COLOR_DIM + f" ({duration_ms}ms)" + C.COLOR_RESET
    used_width = 2 + len(name) + 3 + len(desc)
    stats_visual = visual_len(stats)
    gap = BOX_WIDTH - used_width - stats_visual - 2
    _w(label)
    _w(" " * gap if gap > 0 else " ")
    _w(stats)
    _wl(" " + C.BOX_VERTICAL)
    _wl(_box_mid(BOX_WIDTH))


def _render_finding(f: Finding) -> None:
    desc_line = (
        C.BOX_VERTICAL + " " + _sev_badge(f.severity) + " "
        + truncate_visual(f.description, INNER_WIDTH - 14)
    )
    _write_box_line(desc_line)

    detail = C.BOX_VERTICAL + "   " + C.COLOR_DIM + f.path + "  [" + f.permissions + "]"
    if f.modified != "unknown":
        detail += "  mod:" + f.modified
    detail += C.COLOR_RESET
    _write_box_line(detail)

    if f.credential is not None and len(f.credential.preview) > 0:
        preview_line = C.BOX_VERTICAL + "   " + C.COLOR_DIM + C.ARROW + " " + f.credential.preview + C.COLOR_RESET
        _write_box_line(preview_line)


def _render_module_errors(errors) -> None:
    for err in errors:
        err_line = C.BOX_VERTICAL + " " + C.COLOR_BOLD_RED + C.CROSS_MARK + C.COLOR_RESET + " " + C.COLOR_DIM + err + C.COLOR_RESET
        _write_box_line(err_line)


def _render_summary(report: Report) -> None:
    _wl("")
    _wl(_box_line(BOX_WIDTH))
    _write_box_line(C.BOX_VERTICAL + " " + C.COLOR_BOLD + "SUMMARY" + C.COLOR_RESET)
    _wl(_box_mid(BOX_WIDTH))

    total_findings = sum(report.summary.values())
    count_line = (
        C.BOX_VERTICAL + " " + C.COLOR_BOLD + str(total_findings) + C.COLOR_RESET
        + " findings across " + C.COLOR_BOLD + str(len(report.results)) + C.COLOR_RESET
        + " modules" + C.COLOR_DIM + f" ({report.metadata.duration_ms}ms)" + C.COLOR_RESET
    )
    _write_box_line(count_line)

    badge_line = C.BOX_VERTICAL + " "
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = report.summary[sev]
        if count > 0:
            badge_line += _sev_badge(sev) + " " + str(count) + "  "
    _write_box_line(badge_line)

    _wl(_box_bottom(BOX_WIDTH))
    _wl("")


def render_terminal(report: Report, quiet: bool, verbose: bool) -> None:
    render_banner(quiet)

    if not quiet:
        _w(C.COLOR_DIM + "  Target: " + C.COLOR_RESET)
        _wl(report.metadata.target)
        _w(C.COLOR_DIM + "  Modules: " + C.COLOR_RESET)
        _wl(", ".join(report.metadata.modules))
        _wl("")

    for res in report.results:
        if len(res.findings) == 0 and len(res.errors) == 0 and not verbose:
            continue
        _render_module_header(
            res.name, C.MODULE_DESCRIPTIONS[res.category], len(res.findings), res.duration_ms
        )
        for finding in res.findings:
            _render_finding(finding)
        _render_module_errors(res.errors)
        _wl(_box_bottom(BOX_WIDTH))

    _render_summary(report)
