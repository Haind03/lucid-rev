# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Milestone 1 acceptance tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import FAKE_PAYLOAD, SLED_LEN, STACK_STRING, XOR_KEY, XOR_PLAINTEXT, Sample
from lucid import cli
from lucid.core import disasm
from lucid.core.loader import Binary
from lucid.core.report import render_markdown
from lucid.finding import Severity
from lucid.modules import REGISTRY, deobfus, shellcode, triage


@pytest.fixture(scope="module")
def binary(sample_elf: Sample) -> Binary:
    return Binary(str(sample_elf.path))


# 1. loader --------------------------------------------------------------------
def test_binary_parses_elf_x86_64(binary: Binary) -> None:
    assert binary.format == "ELF"
    assert binary.arch == "x86_64"
    assert binary.entrypoint > 0
    assert any(s.name == ".data" for s in binary.sections)
    assert "puts" in binary.imports
    assert all(0.0 <= s.entropy <= 8.0 for s in binary.sections)


def test_binary_rejects_non_binary(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"definitely not an executable\n" * 4)
    with pytest.raises(ValueError):
        Binary(str(junk))


def test_section_entropy_bounds(binary: Binary) -> None:
    assert binary.section_entropy(b"") == 0.0
    assert binary.section_entropy(b"A" * 100) == 0.0
    assert binary.section_entropy(bytes(range(256))) == pytest.approx(8.0)


# 2. triage --------------------------------------------------------------------
def test_triage_reports_info(binary: Binary) -> None:
    findings = triage.run(binary)
    info = [f for f in findings if f.severity == Severity.INFO]
    assert info, "triage must always emit at least one INFO finding"
    assert "x86_64" in info[0].evidence and info[0].address == binary.entrypoint


def test_triage_flags_upx_indicators(upx_like_elf: Path) -> None:
    findings = triage.run(Binary(str(upx_like_elf)))
    titles = [f.title for f in findings if f.severity == Severity.HIGH]
    assert any("UPX section name" in t for t in titles)
    assert any("UPX magic" in t for t in titles)


# 3. deobfus -------------------------------------------------------------------
def test_deobfus_recovers_xor_string(binary: Binary, sample_elf: Sample) -> None:
    hits = [f for f in deobfus.run(binary) if f.title.startswith("Possible XOR string")]
    match = [f for f in hits if f.meta["decoded"] == XOR_PLAINTEXT.decode()]
    assert match, f"XOR string not recovered; got {[f.meta['decoded'] for f in hits]}"
    finding = match[0]
    assert finding.meta["key"] == XOR_KEY
    assert finding.severity == Severity.MEDIUM
    assert finding.address == sample_elf.symbols["xor_secret"]
    assert XOR_PLAINTEXT.decode() in finding.evidence


def test_deobfus_finds_stack_string(binary: Binary, sample_elf: Sample) -> None:
    hits = [f for f in deobfus.run(binary) if f.meta.get("string") == STACK_STRING]
    assert hits and hits[0].severity == Severity.LOW
    func = sample_elf.symbols["stack_string"]
    assert func <= hits[0].address < func + 0x100
    assert "mov byte ptr" in hits[0].evidence


@pytest.mark.parametrize("key", [0x01, 0x13, 0x5A, 0x7F, 0xAA, 0xFF])
@pytest.mark.parametrize(
    "plain", [b"flag{x0r_is_not_crypto}", b"/etc/passwd", b"kernel32.dll", b"Hello, World!"]
)
def test_find_xor_strings_recall(key: int, plain: bytes) -> None:
    data = b"\0" * 16 + bytes(b ^ key for b in plain + b"\0") + b"\0" * 16
    assert any(h.key == key and h.decoded == plain for h in deobfus.find_xor_strings(data))


def test_find_xor_strings_ignores_plaintext() -> None:
    data = b"\0".join(
        [b"usage: lucid analyze <file>", b"COLORTERM", b"--help", b"No such file or directory",
         b"%s: cannot open '%s'", b"MULTIHARDLINK", b"== 1220703125"]
    ) + b"\0"
    assert deobfus.find_xor_strings(data) == []


def test_stack_scan_degrades_without_capstone(binary: Binary, monkeypatch) -> None:
    monkeypatch.setattr(disasm, "CAPSTONE_ERROR", "capstone not installed (simulated)")
    findings = deobfus._stack_findings(binary)
    assert len(findings) == 1 and findings[0].severity == Severity.INFO
    assert "simulated" in findings[0].evidence


# 4. shellcode -----------------------------------------------------------------
def test_shellcode_finds_sled_mz_and_getpc(binary: Binary, sample_elf: Sample) -> None:
    findings = shellcode.run(binary)
    base = sample_elf.symbols["fake_payload"]
    by_kind = {f.meta["kind"]: f for f in findings}

    mz = by_kind["mz"]
    assert mz.severity == Severity.HIGH and mz.address == base
    assert mz.evidence.startswith("hex  : 4d 5a")

    sled = by_kind["sled"]
    assert sled.address == base + FAKE_PAYLOAD.index(b"\x90" * SLED_LEN)
    assert sled.meta["length"] == SLED_LEN
    assert sled.severity == Severity.HIGH  # adjacent to a GetPC stub
    assert "90 90 90" in sled.evidence and "call" in sled.evidence

    getpc = by_kind["getpc"]
    assert getpc.address == base + FAKE_PAYLOAD.index(b"\xe8\x00\x00\x00\x00")
    assert "pop rbx" in getpc.evidence


def test_shellcode_skips_integer_tables() -> None:
    # 8-byte entries [lo, 00 00 00 00, hi...] as in CRC tables: one entry happens to
    # read "e8 00000000 5a" (call $+5; pop rdx) — taken from /usr/bin/cksum.
    entries = [b"\x82\0\0\0\0\xc5\x61\xaa", b"\xd9\0\0\0\0\x04\x6a\x0e",
               b"\xe8\0\0\0\0\x5a\x0f\xec", b"\xb3\0\0\0\0\xa5\xd9\xc4",
               b"\xe1\0\0\0\0\x6f\x05\x65"]
    table = b"".join(entries)
    assert shellcode._CALL_POP_RE.search(table), "fixture must contain the pattern"
    assert not [h for h in shellcode._scan(table, []) if h.kind == "getpc"]
    # the same stub outside a table is reported
    lone = b"\xcc" * 32 + b"\xe8\0\0\0\0\x5a\x0f\xec" + b"\xcc" * 32
    assert [h for h in shellcode._scan(lone, []) if h.kind == "getpc"]


# 5. report & CLI ------------------------------------------------------------
def test_render_markdown(binary: Binary) -> None:
    findings = [f for run in REGISTRY for f in run(binary)]
    md = render_markdown(findings, "sample")
    assert md.strip()
    for module in ("triage", "deobfus", "shellcode"):
        assert f"## {module}" in md
    assert "| HIGH |" in md and "### [HIGH]" in md
    assert f"`{binary.entrypoint:#x}`" in md


def test_cli_analyze_writes_report(sample_elf: Sample, tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    assert cli.main(["analyze", str(sample_elf.path), "-o", str(out)]) == 0
    text = out.read_text()
    assert "lucid report" in text and XOR_PLAINTEXT.decode() in text


def test_cli_default_report_path(sample_elf: Sample) -> None:
    assert cli.main(["analyze", str(sample_elf.path)]) == 0
    assert Path(f"{sample_elf.path}.lucid.md").is_file()


def test_cli_rejects_bad_input(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.write_text("hello")
    assert cli.main(["analyze", str(bad)]) == 1


@pytest.mark.skipif(not Path("/bin/ls").exists(), reason="/bin/ls not present")
def test_cli_on_system_ls(tmp_path: Path) -> None:
    out = tmp_path / "ls.md"
    assert cli.main(["analyze", "/bin/ls", "-o", str(out)]) == 0
    assert "## triage" in out.read_text()
