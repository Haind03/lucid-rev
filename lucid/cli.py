# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Command-line entry point: ``lucid analyze <file>``."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from lucid import __version__
from lucid.finding import Finding, Severity

#: Exit codes: success, error (unreadable input / unwritable report), --fail-on triggered.
EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2
FORMATS = {"md": "md", "json": "json", "sarif": "sarif"}


def _severity(value: str) -> Severity:
    try:
        return Severity[value.upper()]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"invalid severity {value!r} (choose from {', '.join(s.name for s in Severity)})"
        ) from None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lucid",
        description="Static reverse-engineering assistant (authorized research / CTF use only).",
    )
    parser.add_argument("--version", action="version", version=f"lucid {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser(
        "analyze",
        help="statically analyze a binary",
        description="Statically analyze a binary and write a report.",
        epilog=f"exit codes: {EXIT_OK} ok, {EXIT_ERROR} error, "
        f"{EXIT_FINDINGS} findings at or above --fail-on",
    )
    analyze.add_argument("file", help="path to the binary")
    analyze.add_argument("-o", "--output",
                         help="report path (default: <file>.lucid.<format>); '-' for stdout")
    analyze.add_argument("-f", "--format", choices=sorted(FORMATS), default="md",
                         help="report format (default: md)")
    analyze.add_argument("--min-severity", type=_severity, default=Severity.INFO,
                         metavar="SEV", help="hide findings below SEV (INFO, LOW, MEDIUM, HIGH)")
    analyze.add_argument("--fail-on", type=_severity, metavar="SEV",
                         help=f"exit with code {EXIT_FINDINGS} if a finding is at or above SEV")
    analyze.add_argument("-q", "--quiet", action="store_true",
                         help="do not print the report to the terminal")
    return parser


def _module_name(func: object) -> str:
    return getattr(func, "__module__", "unknown").rsplit(".", 1)[-1]


def _target_info(path: str, binary: object) -> dict:
    data = Path(path).read_bytes()
    return {
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": getattr(binary, "format", None),
        "arch": getattr(binary, "arch", None),
        "entrypoint": getattr(binary, "entrypoint", None),
    }


def analyze(
    path: str,
    output: str | None = None,
    fmt: str = "md",
    min_severity: Severity = Severity.INFO,
    fail_on: Severity | None = None,
    quiet: bool = False,
) -> int:
    """Run every registered module on ``path``, print and save the report."""
    from rich.console import Console

    from lucid.core.loader import Binary
    from lucid.core.report import render_json, render_markdown, render_sarif, render_terminal
    from lucid.modules import REGISTRY, UNAVAILABLE

    err = Console(stderr=True)
    try:
        binary = Binary(path)
    except ValueError as exc:
        err.print(f"[bold red]error:[/] {exc}")
        return EXIT_ERROR

    findings: list[Finding] = []
    status: dict[str, str] = dict(UNAVAILABLE)
    modules: list[str] = [_module_name(run) for run in REGISTRY] + list(UNAVAILABLE)
    for run in REGISTRY:
        name = _module_name(run)
        try:
            findings.extend(run(binary))
        except Exception as exc:  # noqa: BLE001 - one module must not kill the run
            status[name] = f"failed: {type(exc).__name__}: {exc}"

    shown = [f for f in findings if f.severity >= min_severity]
    target = Path(path).name
    to_stdout = output == "-"
    if not quiet and not to_stdout:
        render_terminal(shown, target, modules, status)

    renderers = {"md": render_markdown, "json": render_json, "sarif": render_sarif}
    if fmt == "md":
        report = render_markdown(shown, target, modules, status)
    else:
        report = renderers[fmt](shown, target, modules, status, _target_info(path, binary))

    if to_stdout:
        sys.stdout.write(report)
    else:
        out_path = Path(output) if output else Path(f"{path}.lucid.{FORMATS[fmt]}")
        try:
            out_path.write_text(report, encoding="utf-8")
        except OSError as exc:
            err.print(f"[bold red]error:[/] cannot write report {out_path}: {exc}")
            return EXIT_ERROR
        if not quiet:
            err.print(f"[dim]report written to {out_path}[/]")

    if fail_on is not None and any(f.severity >= fail_on for f in findings):
        if not quiet:
            worst = max(f.severity for f in findings)
            err.print(f"[bold red]fail-on {fail_on.name}:[/] highest severity is {worst.name}")
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch the subcommand. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    if args.command == "analyze":
        return analyze(args.file, args.output, args.format, args.min_severity,
                       args.fail_on, args.quiet)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
