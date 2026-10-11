# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Triage: first look at a binary — layout, entropy and packer indicators."""

from __future__ import annotations

from lucid.core.loader import Binary, Section
from lucid.finding import Finding, Severity

MODULE = "triage"

HIGH_ENTROPY = 7.0
#: Below this many imports the import table is considered "almost empty".
FEW_IMPORTS = 3
#: Executable code at least this large with almost no imports looks packed.
LARGE_EXEC = 16 * 1024
UPX_MAGIC = b"UPX!"
_MAX_UPX_HITS = 4


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    """Classic hexdump (address, hex bytes, ASCII) of ``data`` starting at ``base``."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hexpart:<{width * 3}} {text}")
    return "\n".join(lines)


def _regions(bin: Binary) -> list[Section]:
    """Sections with file content; fall back to LOAD segments when headers are stripped."""
    regions = [s for s in bin.sections if s.name and s.data]
    return regions or [s for s in bin.segments if s.data]


def _summary(bin: Binary) -> Finding:
    exec_regions = [s.name for s in _regions(bin) if s.executable]
    evidence = "\n".join(
        [
            f"format      : {bin.format}",
            f"arch        : {bin.arch}",
            f"entrypoint  : {bin.entrypoint:#x}",
            f"sections    : {sum(1 for s in bin.sections if s.name)}",
            f"segments    : {len(bin.segments)} (LOAD)",
            f"imports     : {len(bin.imports)}",
            f"executable  : {', '.join(exec_regions) or '-'}",
        ]
    )
    return Finding(
        module=MODULE,
        title=f"{bin.format} {bin.arch} binary",
        rule="triage/summary",
        severity=Severity.INFO,
        address=bin.entrypoint,
        evidence=evidence,
        detail="Basic layout of the binary as parsed by LIEF.",
        meta={"format": bin.format, "arch": bin.arch, "imports": len(bin.imports)},
    )


def _entropy_findings(bin: Binary) -> list[Finding]:
    findings = []
    for region in _regions(bin):
        if region.entropy <= HIGH_ENTROPY:
            continue
        findings.append(
            Finding(
                module=MODULE,
                title=f"High-entropy section {region.name} ({region.entropy:.2f})",
                rule="triage/high-entropy-section",
                severity=Severity.MEDIUM,
                address=region.va or None,
                evidence=f"entropy={region.entropy:.4f} bits/byte, size={region.size:#x}\n"
                + hexdump(region.data[:32], region.va),
                detail="Entropy above 7.0 bits/byte is typical of packed, encrypted or "
                "compressed data rather than code or plain data.",
                meta={"section": region.name, "entropy": round(region.entropy, 4)},
            )
        )
    return findings


def _sparse_imports(bin: Binary) -> Finding | None:
    exec_regions = [s for s in _regions(bin) if s.executable]
    exec_size = sum(len(s.data) for s in exec_regions)
    if len(bin.imports) > FEW_IMPORTS or exec_size < LARGE_EXEC:
        return None
    largest = max(exec_regions, key=lambda s: len(s.data))
    static_note = ""
    if bin.format == "ELF" and not any(s.name == ".interp" for s in bin.sections):
        static_note = " No .interp section: may also simply be statically linked."
    return Finding(
        module=MODULE,
        title=f"Almost no imports ({len(bin.imports)}) with {exec_size:#x} bytes of code",
        rule="triage/sparse-imports",
        severity=Severity.MEDIUM,
        address=largest.va or None,
        evidence=f"imports: {', '.join(bin.imports) or '(none)'}\n"
        + "\n".join(f"exec region {s.name}: {len(s.data):#x} bytes, entropy {s.entropy:.2f}"
                    for s in exec_regions),
        detail="Packers usually resolve APIs at runtime, leaving a tiny import table next to "
        "a large code/stub region." + static_note,
        meta={"imports": len(bin.imports), "exec_size": exec_size},
    )


def _missing_section_headers(bin: Binary) -> Finding | None:
    if bin.format != "ELF" or bin.has_section_headers:
        return None
    return Finding(
        module=MODULE,
        title="ELF has no section header table",
        rule="triage/no-section-headers",
        severity=Severity.MEDIUM,
        evidence=f"e_shnum = 0; analysis falls back to {len(bin.segments)} LOAD segment(s)",
        detail="Section headers are not needed at runtime; stripping them is a common "
        "anti-analysis step performed by packers and droppers.",
    )


def _upx_findings(bin: Binary) -> list[Finding]:
    findings = []
    for s in bin.sections:
        if "upx" in s.name.lower():
            findings.append(
                Finding(
                    module=MODULE,
                    title=f"UPX section name: {s.name}",
                    rule="triage/upx-section",
                    severity=Severity.HIGH,
                    address=s.va or None,
                    evidence=f"section {s.name!r} va={s.va:#x} size={s.size:#x} "
                    f"entropy={s.entropy:.2f}",
                    detail="Section names like UPX0/UPX1 are created by the UPX packer; "
                    "unpack with `upx -d` (on a copy) before static analysis.",
                )
            )
    start, hits = 0, 0
    while hits < _MAX_UPX_HITS and (off := bin.raw.find(UPX_MAGIC, start)) != -1:
        findings.append(
            Finding(
                module=MODULE,
                title=f"UPX magic 'UPX!' at file offset {off:#x}",
                rule="triage/upx-magic",
                severity=Severity.HIGH,
                address=bin.file_offset_to_va(off),
                evidence=hexdump(bin.raw[max(0, off - 8) : off + 24], max(0, off - 8)),
                detail="The 'UPX!' marker precedes UPX packer headers (p_info / l_info). "
                "Note: a literal 'UPX!' string in a program also matches — check the context.",
                meta={"file_offset": off},
            )
        )
        hits += 1
        start = off + 1
    return findings


def run(bin: Binary) -> list[Finding]:
    """Summarize the binary and flag entropy / packer indicators."""
    findings = [_summary(bin)]
    findings += _entropy_findings(bin)
    for extra in (_sparse_imports(bin), _missing_section_headers(bin)):
        if extra is not None:
            findings.append(extra)
    findings += _upx_findings(bin)
    return findings
