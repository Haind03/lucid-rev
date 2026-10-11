# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Finding: the single result type every analysis module produces."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """How much attention a finding deserves (ordered, higher = more important)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class Finding:
    """One observation about a binary, backed by concrete evidence."""

    module: str  # "triage" | "deobfus" | "shellcode"
    title: str  # short, one line
    severity: Severity
    address: int | None = None  # virtual address, rendered as 0x...
    evidence: str = ""  # bytes / disassembly / decoded string
    detail: str = ""  # why this matters, 1-3 sentences
    meta: dict = field(default_factory=dict)

    @property
    def address_str(self) -> str:
        """Address formatted as hex, or '-' when the finding has none."""
        return f"{self.address:#x}" if self.address is not None else "-"
