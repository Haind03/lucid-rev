# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys

from lucid import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lucid", description="Reverse-engineering assistant.")
    parser.add_argument("--version", action="version", version=f"lucid {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="statically analyze a binary")
    analyze.add_argument("file", help="path to the binary")
    analyze.add_argument("-o", "--output", help="Markdown report path (default: <file>.lucid.md)")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch the subcommand. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    print(f"analyze: {args.file} (not implemented yet)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
