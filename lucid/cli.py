# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Command-line entry point: ``lucid analyze <file>``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lucid import __version__
from lucid.finding import Finding


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lucid",
        description="Static reverse-engineering assistant (authorized research / CTF use only).",
    )
    parser.add_argument("--version", action="version", version=f"lucid {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="statically analyze a binary")
    analyze.add_argument("file", help="path to the binary")
    analyze.add_argument("-o", "--output", help="Markdown report path (default: <file>.lucid.md)")
    return parser


def _module_name(func: object) -> str:
    return getattr(func, "__module__", "unknown").rsplit(".", 1)[-1]


def analyze(path: str, output: str | None = None) -> int:
    """Run every registered module on ``path``, print and save the report."""
    from rich.console import Console

    from lucid.core.loader import Binary
    from lucid.core.report import render_markdown, render_terminal
    from lucid.modules import REGISTRY, UNAVAILABLE

    err = Console(stderr=True)
    try:
        binary = Binary(path)
    except ValueError as exc:
        err.print(f"[bold red]error:[/] {exc}")
        return 1

    findings: list[Finding] = []
    status: dict[str, str] = dict(UNAVAILABLE)
    modules: list[str] = [_module_name(run) for run in REGISTRY] + list(UNAVAILABLE)
    for run in REGISTRY:
        name = _module_name(run)
        try:
            findings.extend(run(binary))
        except Exception as exc:  # noqa: BLE001 - one module must not kill the run
            status[name] = f"failed: {type(exc).__name__}: {exc}"

    target = Path(path).name
    render_terminal(findings, target, modules, status)
    out_path = Path(output) if output else Path(f"{path}.lucid.md")
    try:
        out_path.write_text(render_markdown(findings, target, modules, status), encoding="utf-8")
    except OSError as exc:
        err.print(f"[bold red]error:[/] cannot write report {out_path}: {exc}")
        return 1
    err.print(f"[dim]report written to {out_path}[/]")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch the subcommand. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    if args.command == "analyze":
        return analyze(args.file, args.output)
    return 1


if __name__ == "__main__":
    sys.exit(main())
