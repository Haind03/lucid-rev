# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Embedded payload detection: executables, GetPC stubs and NOP sleds hidden in data."""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from lucid.core import disasm
from lucid.core.loader import Binary, Section
from lucid.finding import Finding, Severity

MODULE = "shellcode"

WINDOW = 256
STEP = WINDOW // 2
HIGH_ENTROPY = 6.5
MIN_SLED = 16
_MAX_PER_KIND = 16
_SKIP_PREFIXES = (
    ".dyn", ".rela", ".rel.", ".gnu", ".note", ".eh_frame", ".got", ".plt",
    ".interp", ".init_array", ".fini_array", ".symtab", ".strtab", ".shstrtab",
    ".comment", ".debug", ".hash", ".bss", ".tbss",
)

_MZ_RE = re.compile(rb"MZ")
_ELF_RE = re.compile(rb"\x7fELF")
#: call $+5 ; pop r32/r64 (optionally REX.B) — the classic position-independent GetPC.
_CALL_POP_RE = re.compile(rb"\xe8\x00\x00\x00\x00(?:\x41)?[\x58-\x5f]")
#: fldz ; fnstenv [esp-0xc] — FPU-based GetPC used by many encoders.
_FNSTENV_RE = re.compile(rb"\xd9\xee\xd9\x74\x24\xf4")
_CALL5_RE = re.compile(rb"\xe8\x00\x00\x00\x00")
_SLED_RE = re.compile(rb"\x90{%d,}" % MIN_SLED)


_RULES = {
    ("mz", Severity.HIGH): "shellcode/embedded-pe",
    ("mz", Severity.MEDIUM): "shellcode/embedded-mz",
    ("elf", Severity.HIGH): "shellcode/embedded-elf",
    ("getpc", Severity.HIGH): "shellcode/getpc-stub",
    ("getpc", Severity.MEDIUM): "shellcode/getpc-call5",
    ("sled", Severity.HIGH): "shellcode/nop-sled",
    ("sled", Severity.MEDIUM): "shellcode/nop-sled",
}


@dataclass
class _Hit:
    kind: str
    offset: int
    length: int
    severity: Severity
    title: str
    detail: str


def _regions(bin: Binary) -> list[Section]:
    """Non-executable data sections (fall back to non-exec LOAD segments)."""
    regions = [
        s for s in bin.sections
        if s.name and s.data and not s.executable and not s.name.startswith(_SKIP_PREFIXES)
    ]
    return regions or [s for s in bin.segments if s.data and not s.executable]


def entropy_windows(bin: Binary, data: bytes) -> list[tuple[int, float]]:
    """(offset, entropy) of every 256-byte window (step 128) above the threshold."""
    out = []
    for off in range(0, max(len(data) - WINDOW, 0) + 1, STEP):
        e = bin.section_entropy(data[off : off + WINDOW])
        if e > HIGH_ENTROPY:
            out.append((off, e))
    return out


def _in_candidate(offset: int, windows: list[tuple[int, float]]) -> float | None:
    """Entropy of the high-entropy window covering ``offset``, if any."""
    for off, e in windows:
        if off <= offset < off + WINDOW:
            return e
    return None


def _e_lfanew(data: bytes, off: int) -> int | None:
    """DOS header ``e_lfanew`` at ``off`` if it is plausible (0x40..0x400, 4-aligned)."""
    if off + 0x40 > len(data):
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, off + 0x3C)
    return e_lfanew if 0x40 <= e_lfanew <= 0x400 and e_lfanew % 4 == 0 else None


def _pe_header(data: bytes, off: int) -> int | None:
    """Offset of a valid ``PE\\0\\0`` signature referenced by the DOS header at ``off``."""
    e_lfanew = _e_lfanew(data, off)
    if e_lfanew is None:
        return None
    pe = off + e_lfanew
    return pe if data[pe : pe + 4] == b"PE\0\0" else None


def _in_int_table(data: bytes, off: int) -> bool:
    """True if ``E8 00000000`` at ``off`` is just part of an array of 64-bit integers.

    Such arrays repeat a zero high dword every 8 bytes; count zero dwords in the
    same phase as the hit's own (``off + 1``) within +/-32 bytes.
    """
    zero = off + 1
    same_phase = sum(
        1 for p in range(zero - 32, zero + 33, 8)
        if p != zero and 0 <= p and data[p : p + 4] == b"\0\0\0\0"
    )
    return same_phase >= 2


def _valid_elf_ident(data: bytes, off: int) -> bool:
    ident = data[off : off + 16]
    return len(ident) == 16 and ident[4] in (1, 2) and ident[5] in (1, 2) and ident[6] == 1


def _scan(data: bytes, windows: list[tuple[int, float]]) -> Iterator[_Hit]:
    for m in _MZ_RE.finditer(data):
        pe = _pe_header(data, m.start())
        if pe is not None:
            yield _Hit("mz", m.start(), 2, Severity.HIGH, "Embedded PE image (MZ + PE header)",
                       f"DOS header whose e_lfanew points to a PE signature at +{pe - m.start():#x}: "
                       "a Windows PE image appears to be stored inside this binary.")
        elif _in_candidate(m.start(), windows) is not None and _e_lfanew(data, m.start()):
            yield _Hit("mz", m.start(), 2, Severity.MEDIUM, "Possible embedded MZ header",
                       "'MZ' magic with a plausible e_lfanew inside a high-entropy window, but "
                       "no PE signature: may be a truncated or partly encrypted executable.")
    for m in _ELF_RE.finditer(data):
        if _valid_elf_ident(data, m.start()):
            yield _Hit("elf", m.start(), 4, Severity.HIGH, "Embedded ELF image",
                       "\\x7fELF magic with a valid e_ident (class, data, version): an ELF "
                       "executable or object is stored inside this binary.")
    for rx, name in ((_CALL_POP_RE, "call $+5; pop"), (_FNSTENV_RE, "fldz; fnstenv [esp-0xc]")):
        for m in rx.finditer(data):
            if _in_int_table(data, m.start()):
                continue
            yield _Hit("getpc", m.start(), len(m.group()), Severity.HIGH, f"GetPC stub ({name})",
                       "Position-independent code reads its own address this way; it is a "
                       "hallmark of shellcode and has no reason to live in a data section.")
    for m in _CALL5_RE.finditer(data):
        if (not _CALL_POP_RE.match(data, m.start()) and _in_candidate(m.start(), windows)
                and not _in_int_table(data, m.start())):
            yield _Hit("getpc", m.start(), 5, Severity.MEDIUM, "Possible GetPC (call $+5)",
                       "E8 00 00 00 00 (call next instruction) inside a high-entropy window.")
    for m in _SLED_RE.finditer(data):
        n = len(m.group())
        near_code = any(
            rx.search(data, max(0, m.start() - 64), m.end() + 64)
            for rx in (_CALL_POP_RE, _FNSTENV_RE, _CALL5_RE)
        )
        yield _Hit("sled", m.start(), n,
                   Severity.HIGH if near_code else Severity.MEDIUM,
                   f"NOP sled ({n} x 0x90)",
                   "A long run of single-byte NOPs in data is used to make a jump into a "
                   "payload land reliably" + (", and it sits next to a GetPC stub." if near_code
                                              else "."))


def _evidence(bin: Binary, data: bytes, hit: _Hit, va: int) -> str:
    head = data[hit.offset : hit.offset + 16]
    lines = [f"hex  : {head.hex(' ')}"]
    if hit.kind == "sled":
        code_off = hit.offset + hit.length
        lines.append(f"{va:#010x}: nop  (x{hit.length})")
        lines.append(disasm.listing(bin.arch, data[code_off : code_off + 64], va + hit.length, 4))
    elif hit.kind == "getpc":
        lines.append(disasm.listing(bin.arch, data[hit.offset : hit.offset + 64], va, 5))
    else:
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data[hit.offset : hit.offset + 64])
        lines.append(f"ascii: {text}")
    return "\n".join(lines)


def run(bin: Binary) -> list[Finding]:
    """Look for executable payloads hidden in non-executable data."""
    findings: list[Finding] = []
    per_kind: dict[str, int] = {}
    for region in _regions(bin):
        data = region.data
        windows = entropy_windows(bin, data)
        for hit in _scan(data, windows):
            if per_kind.get(hit.kind, 0) >= _MAX_PER_KIND:
                continue
            per_kind[hit.kind] = per_kind.get(hit.kind, 0) + 1
            va = bin.offset_to_va(region, hit.offset)
            window_e = _in_candidate(hit.offset, windows)
            context = (f" Surrounding 256-byte window entropy: {window_e:.2f}."
                       if window_e is not None else "")
            findings.append(
                Finding(
                    module=MODULE,
                    title=hit.title,
                    rule=_RULES[(hit.kind, hit.severity)],
                    severity=hit.severity,
                    address=va if region.va else None,
                    evidence=_evidence(bin, data, hit, va),
                    detail=hit.detail + context,
                    meta={"kind": hit.kind, "section": region.name, "offset": hit.offset,
                          "length": hit.length},
                )
            )
    return findings
