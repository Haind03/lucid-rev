# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Binary loader: a thin, format-agnostic view over a LIEF-parsed file."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import lief

_ARCH_NAMES = {
    "X86_64": "x86_64",
    "X86": "x86",
    "I386": "x86",
    "AMD64": "x86_64",
    "ARM": "arm",
    "ARM64": "arm64",
    "AARCH64": "arm64",
    "MIPS": "mips",
    "PPC": "ppc",
    "PPC64": "ppc64",
    "RISCV": "riscv",
}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits per byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


@dataclass
class Section:
    """A section of the binary with its raw bytes and metadata."""

    name: str
    va: int
    size: int
    offset: int
    entropy: float
    data: bytes
    executable: bool
    writable: bool


class Binary:
    """Parsed binary: format, architecture, entrypoint, sections and imports."""

    path: str
    format: str
    arch: str
    entrypoint: int
    sections: list[Section]
    imports: list[str]
    raw: bytes

    def __init__(self, path: str) -> None:
        """Parse ``path`` with LIEF; raise ValueError if it is not a supported binary."""
        self.path = str(path)
        try:
            self.raw = Path(path).read_bytes()
        except OSError as exc:
            raise ValueError(f"cannot read {path}: {exc}") from exc

        lief.logging.disable()
        parsed = lief.parse(self.path)
        if parsed is None:
            raise ValueError(f"LIEF could not parse {path} (not ELF/PE/Mach-O?)")
        self._lief = parsed

        if isinstance(parsed, lief.ELF.Binary):
            self.format = "ELF"
        elif isinstance(parsed, lief.PE.Binary):
            self.format = "PE"
        elif isinstance(parsed, lief.MachO.Binary):
            self.format = "MACHO"
        else:
            raise ValueError(f"unsupported binary format: {type(parsed).__name__}")

        self.arch = self._detect_arch(parsed)
        self.entrypoint = int(parsed.entrypoint)
        self.sections = [self._make_section(s) for s in parsed.sections]
        self.imports = self._collect_imports(parsed)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _detect_arch(parsed: lief.Binary) -> str:
        header = parsed.abstract.header
        name = str(header.architecture).rsplit(".", 1)[-1].upper()
        arch = _ARCH_NAMES.get(name, name.lower())
        if arch == "x86" and header.is_64:
            arch = "x86_64"
        return arch

    def _make_section(self, s: lief.Section) -> Section:
        data = bytes(s.content)
        executable = writable = False
        if self.format == "ELF":
            executable = s.has(lief.ELF.Section.FLAGS.EXECINSTR)
            writable = s.has(lief.ELF.Section.FLAGS.WRITE)
        elif self.format == "PE":
            executable = s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
            writable = s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE)
        va = int(s.virtual_address)
        if self.format == "PE":
            va += int(self._lief.optional_header.imagebase)
        return Section(
            name=s.name,
            va=va,
            size=int(s.size),
            offset=int(s.offset),
            entropy=self.section_entropy(data),
            data=data,
            executable=executable,
            writable=writable,
        )

    @staticmethod
    def _collect_imports(parsed: lief.Binary) -> list[str]:
        if isinstance(parsed, lief.ELF.Binary):
            names = [s.name for s in parsed.dynamic_symbols if s.name and s.imported]
        else:
            names = [f.name for f in parsed.imported_functions if f.name]
        return sorted(set(names))

    # ------------------------------------------------------------------ public
    def section_entropy(self, data: bytes) -> float:
        """Shannon entropy of ``data`` (0..8 bits/byte)."""
        return shannon_entropy(data)

    def offset_to_va(self, section: Section, offset: int) -> int:
        """Translate an offset inside ``section.data`` to a virtual address."""
        return section.va + offset

    @property
    def is_64(self) -> bool:
        """True for 64-bit targets."""
        return self.arch in ("x86_64", "arm64", "ppc64")

    def __repr__(self) -> str:
        return f"<Binary {self.path} {self.format}/{self.arch} entry={self.entrypoint:#x}>"
