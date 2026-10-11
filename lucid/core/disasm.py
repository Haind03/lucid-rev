# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Thin Capstone wrapper shared by modules; degrades gracefully if Capstone is missing."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

try:
    import capstone

    CAPSTONE_ERROR: str | None = None
except ImportError as _exc:  # pragma: no cover - exercised only without capstone
    capstone = None  # type: ignore[assignment]
    CAPSTONE_ERROR = f"capstone not installed ({_exc})"

_MODES = {"x86_64": "CS_MODE_64", "x86": "CS_MODE_32"}


def available(arch: str) -> str | None:
    """Return None if ``arch`` can be disassembled, else a human-readable reason."""
    if CAPSTONE_ERROR:
        return CAPSTONE_ERROR
    if arch not in _MODES:
        return f"architecture {arch!r} not supported (x86/x86_64 only in M1)"
    return None


def make_cs(arch: str, detail: bool = False) -> Any:
    """Create a Capstone instance for ``arch`` (raises RuntimeError if unavailable)."""
    reason = available(arch)
    if reason:
        raise RuntimeError(reason)
    md = capstone.Cs(capstone.CS_ARCH_X86, getattr(capstone, _MODES[arch]))
    md.detail = detail
    return md


def sweep(md: Any, data: bytes, base: int) -> Iterator[Any]:
    """Linear-sweep disassembly that skips one byte past undecodable data."""
    off = 0
    while off < len(data):
        last = None
        for insn in md.disasm(data[off:], base + off):
            last = insn
            yield insn
        off = (last.address - base + last.size) if last else off + 1
        if last is not None and off < len(data):
            off += 1  # capstone stopped on an invalid byte; skip it


def listing(arch: str, data: bytes, base: int, max_lines: int = 5) -> str:
    """Disassemble up to ``max_lines`` instructions as ``addr: bytes  mnemonic op_str``."""
    reason = available(arch)
    if reason:
        return f"(disassembly unavailable: {reason})"
    md = make_cs(arch)
    lines = []
    for insn in md.disasm(data, base):
        raw = insn.bytes.hex(" ")
        lines.append(f"{insn.address:#010x}: {raw:<24} {insn.mnemonic} {insn.op_str}".rstrip())
        if len(lines) >= max_lines:
            break
    return "\n".join(lines) or "(no valid instructions decoded)"
