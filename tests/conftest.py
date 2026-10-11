# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Fixtures: small ELF samples compiled with ``cc`` at test time."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

XOR_KEY = 0x5A
XOR_PLAINTEXT = b"/usr/share/lucid/secret.conf"
STACK_STRING = "/bin/lucid"
SLED_LEN = 32


def _c_bytes(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


def _fake_payload() -> bytes:
    """MZ/PE header stub + NOP sled + call $+5; pop rbx; ... (never executed)."""
    header = bytearray(0x48)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x40).to_bytes(4, "little")  # e_lfanew
    header[0x40:0x44] = b"PE\0\0"
    code = b"\xe8\x00\x00\x00\x00\x5b\x48\x83\xc3\x10\xff\xe3\xcc\xcc"
    return bytes(header) + b"\x90" * SLED_LEN + code


FAKE_PAYLOAD = _fake_payload()

SOURCE = f"""
#include <stdio.h>

/* XOR(key=0x{XOR_KEY:02x})-encoded string; the trailing key byte decodes to NUL. */
unsigned char xor_secret[] = {{ {_c_bytes(bytes(b ^ XOR_KEY for b in XOR_PLAINTEXT))}, 0x{XOR_KEY:02x} }};

/* Inert byte blob that only looks like an embedded payload. */
unsigned char fake_payload[] = {{ {_c_bytes(FAKE_PAYLOAD)} }};

__attribute__((noinline)) void stack_string(void) {{
    volatile char s[16];
{"".join(f"    s[{i}] = '{c}';{chr(10)}" for i, c in enumerate(STACK_STRING))}    s[{len(STACK_STRING)}] = 0;
    puts((const char *)s);
}}

int main(void) {{
    stack_string();
    return xor_secret[0] + fake_payload[0];
}}
"""

UPX_SOURCE = """
__attribute__((section("UPX0"), used)) const unsigned char upx0[64] = {1};
const char marker[] = "UPX!";
int main(void) { return marker[0]; }
"""


@dataclass
class Sample:
    path: Path
    symbols: dict[str, int]


def _compile(tmp: Path, name: str, source: str, *flags: str) -> Path:
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler (cc/gcc/clang) available")
    src = tmp / f"{name}.c"
    out = tmp / name
    src.write_text(source)
    subprocess.run([cc, "-O0", "-fno-stack-protector", *flags, "-o", str(out), str(src)],
                   check=True, capture_output=True)
    return out


def _symbols(path: Path) -> dict[str, int]:
    from elftools.elf.elffile import ELFFile

    with path.open("rb") as fh:
        symtab = ELFFile(fh).get_section_by_name(".symtab")
        return {s.name: s["st_value"] for s in symtab.iter_symbols()} if symtab else {}


@pytest.fixture(scope="session")
def sample_elf(tmp_path_factory: pytest.TempPathFactory) -> Sample:
    """x86-64 ELF with an XOR string, a fake payload blob and a stack string."""
    path = _compile(tmp_path_factory.mktemp("elf"), "sample", SOURCE)
    return Sample(path, _symbols(path))


@pytest.fixture(scope="session")
def upx_like_elf(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """ELF carrying UPX indicators (section name and 'UPX!' magic) without being packed."""
    return _compile(tmp_path_factory.mktemp("upx"), "upx_like", UPX_SOURCE)
