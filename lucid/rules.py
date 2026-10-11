# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Catalogue of every rule a module can emit (used by the SARIF report and tests)."""

from __future__ import annotations

from dataclasses import dataclass

from lucid.finding import Severity


@dataclass(frozen=True)
class Rule:
    """A check performed by one module."""

    id: str
    name: str
    description: str
    severity: Severity  # default / highest severity the rule reports


RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule("triage/summary", "BinarySummary",
             "Format, architecture, entrypoint and section/import counts.", Severity.INFO),
        Rule("triage/high-entropy-section", "HighEntropySection",
             "Section entropy above 7.0 bits/byte: likely packed, encrypted or compressed.",
             Severity.MEDIUM),
        Rule("triage/sparse-imports", "SparseImports",
             "Almost no imports next to a large executable region, typical of packers.",
             Severity.MEDIUM),
        Rule("triage/no-section-headers", "NoSectionHeaders",
             "ELF without a section header table.", Severity.MEDIUM),
        Rule("triage/upx-section", "UpxSectionName",
             "Section name created by the UPX packer.", Severity.HIGH),
        Rule("triage/upx-magic", "UpxMagic",
             "'UPX!' marker found in the file.", Severity.HIGH),
        Rule("deobfus/xor-string", "XorString",
             "NUL-terminated ASCII string recovered with a single-byte XOR key.",
             Severity.MEDIUM),
        Rule("deobfus/xor-noisy-region", "XorNoisyRegion",
             "Region where many unrelated XOR keys decode short text; weak candidates "
             "suppressed.", Severity.INFO),
        Rule("deobfus/stack-string", "StackString",
             "String assembled from immediate stores to consecutive stack slots.",
             Severity.LOW),
        Rule("deobfus/stack-scan-skipped", "StackScanSkipped",
             "Stack-string scan unavailable (Capstone missing or unsupported architecture).",
             Severity.INFO),
        Rule("shellcode/embedded-pe", "EmbeddedPe",
             "DOS header with a valid PE signature inside data.", Severity.HIGH),
        Rule("shellcode/embedded-mz", "EmbeddedMz",
             "'MZ' header with a plausible e_lfanew inside a high-entropy window.",
             Severity.MEDIUM),
        Rule("shellcode/embedded-elf", "EmbeddedElf",
             "ELF magic with a valid e_ident inside data.", Severity.HIGH),
        Rule("shellcode/getpc-stub", "GetPcStub",
             "GetPC sequence (call $+5; pop or fldz; fnstenv) inside data.", Severity.HIGH),
        Rule("shellcode/getpc-call5", "GetPcCall5",
             "call $+5 without a following pop inside a high-entropy window.",
             Severity.MEDIUM),
        Rule("shellcode/nop-sled", "NopSled",
             "Run of at least 16 single-byte NOPs inside data.", Severity.HIGH),
    )
}
