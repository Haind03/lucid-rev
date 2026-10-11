# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Milestone 2: rule ids, JSON/SARIF reports, CLI filtering and the fast XOR scan."""

from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path

import pytest

from conftest import XOR_PLAINTEXT, Sample
from lucid import __version__, cli
from lucid.core.loader import Binary
from lucid.core.report import JSON_SCHEMA, render_json, render_sarif
from lucid.finding import Finding, Severity
from lucid.modules import REGISTRY, deobfus
from lucid.rules import RULES


def _all_findings(path: Path) -> list[Finding]:
    binary = Binary(str(path))
    return [f for run in REGISTRY for f in run(binary)]


@pytest.fixture(scope="module")
def findings(sample_elf: Sample) -> list[Finding]:
    return _all_findings(sample_elf.path)


# rules -----------------------------------------------------------------------
def test_every_emitted_rule_is_catalogued(findings: list[Finding], upx_like_elf: Path) -> None:
    emitted = {f.rule for f in findings + _all_findings(upx_like_elf)}
    assert "" not in emitted, "a finding was created without a rule id"
    assert emitted <= set(RULES), emitted - set(RULES)


def test_rule_ids_are_namespaced_by_module(findings: list[Finding]) -> None:
    for rule in RULES.values():
        assert rule.id.split("/")[0] in {"triage", "deobfus", "shellcode"}
    for f in findings:
        assert f.rule.startswith(f.module + "/")


# JSON ------------------------------------------------------------------------
def test_json_report(findings: list[Finding], sample_elf: Sample) -> None:
    info = {"path": str(sample_elf.path), "sha256": "ab" * 32}
    doc = json.loads(render_json(findings, "sample", status={"shellcode": "failed: X"},
                                 info=info))
    assert doc["schema"] == JSON_SCHEMA
    assert doc["tool"] == {"name": "lucid", "version": __version__}
    assert doc["target"]["sha256"] == "ab" * 32
    assert doc["summary"]["total"] == len(findings) == len(doc["findings"])
    assert doc["summary"]["HIGH"] == sum(f.severity == Severity.HIGH for f in findings)
    assert doc["modules"] == {"triage": "ok", "deobfus": "ok", "shellcode": "failed: X"}
    xor = next(f for f in doc["findings"] if f["rule"] == "deobfus/xor-string")
    assert xor["address"] == sample_elf.symbols["xor_secret"]
    assert xor["address_hex"] == hex(sample_elf.symbols["xor_secret"])
    assert xor["meta"]["decoded"] == XOR_PLAINTEXT.decode()


# SARIF -----------------------------------------------------------------------
def test_sarif_report(findings: list[Finding], sample_elf: Sample) -> None:
    log = json.loads(render_sarif(findings, "sample", info={"path": "bin/sample"}))
    assert log["version"] == "2.1.0" and "sarif-2.1.0" in log["$schema"]
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["tool"]["driver"]["version"] == __version__
    assert {r["id"] for r in rules} >= {f.rule for f in findings}
    assert len(run["results"]) == len(findings)
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bin/sample"
    pe = next(r for r in run["results"] if r["ruleId"] == "shellcode/embedded-pe")
    assert pe["level"] == "error"
    assert pe["locations"][0]["physicalLocation"]["address"]["absoluteAddress"] == \
        sample_elf.symbols["fake_payload"]
    assert pe["properties"]["evidence"].startswith("hex  : 4d 5a")
    assert run["invocations"][0]["executionSuccessful"] is True


def test_sarif_reports_module_failures(findings: list[Finding]) -> None:
    log = json.loads(render_sarif(findings, "sample", status={"deobfus": "failed: boom"}))
    invocation = log["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert "boom" in invocation["toolExecutionNotifications"][0]["message"]["text"]


# CLI -------------------------------------------------------------------------
def test_cli_json_default_path_and_hash(sample_elf: Sample) -> None:
    assert cli.main(["analyze", str(sample_elf.path), "-f", "json", "-q"]) == cli.EXIT_OK
    doc = json.loads(Path(f"{sample_elf.path}.lucid.json").read_text())
    assert doc["target"]["sha256"] == hashlib.sha256(sample_elf.path.read_bytes()).hexdigest()
    assert doc["target"]["arch"] == "x86_64"


def test_cli_stdout_output(sample_elf: Sample, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["analyze", str(sample_elf.path), "-f", "sarif", "-o", "-"]) == 0
    log = json.loads(capsys.readouterr().out)  # nothing else may reach stdout
    assert log["runs"][0]["results"]


def test_cli_min_severity(sample_elf: Sample, tmp_path: Path) -> None:
    out = tmp_path / "high.json"
    cli.main(["analyze", str(sample_elf.path), "-f", "json", "-o", str(out), "-q",
              "--min-severity", "high"])
    doc = json.loads(out.read_text())
    assert doc["findings"] and {f["severity"] for f in doc["findings"]} == {"HIGH"}


@pytest.mark.parametrize(("fail_on", "expected"), [("high", 2), ("MEDIUM", 2), ("info", 2)])
def test_cli_fail_on_triggers(sample_elf: Sample, tmp_path: Path, fail_on: str,
                              expected: int) -> None:
    argv = ["analyze", str(sample_elf.path), "-o", str(tmp_path / "r.md"), "-q",
            "--fail-on", fail_on]
    assert cli.main(argv) == expected


def test_cli_fail_on_ignores_display_filter(sample_elf: Sample, tmp_path: Path) -> None:
    # the gate sees every finding even when the report hides them
    argv = ["analyze", str(sample_elf.path), "-o", str(tmp_path / "r.md"), "-q",
            "--min-severity", "high", "--fail-on", "low"]
    assert cli.main(argv) == cli.EXIT_FINDINGS


def test_cli_exit_code_only_changes_with_fail_on(upx_like_elf: Path, tmp_path: Path) -> None:
    # the UPX fixture has HIGH findings: they only fail the run when asked to
    argv = ["analyze", str(upx_like_elf), "-o", str(tmp_path / "r.md"), "-q"]
    assert cli.main(argv + ["--fail-on", "high"]) == cli.EXIT_FINDINGS
    assert cli.main(argv) == cli.EXIT_OK


def test_cli_rejects_unknown_severity(sample_elf: Sample) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["analyze", str(sample_elf.path), "--min-severity", "critical"])
    assert exc.value.code == 2


# fast XOR scan ---------------------------------------------------------------
def _naive_candidates(data: bytes) -> set[tuple[int, int, int]]:
    """Reference implementation: regex over the fully decoded buffer."""
    out = set()
    run = re.compile(rb"[\x20-\x7e]{%d,}\x00" % deobfus.MIN_LEN)
    for key in deobfus._XOR_KEYS:
        decoded = bytes(0x01 if b == 0 else b ^ key for b in data)
        for m in run.finditer(decoded):
            out.add((key, m.start(), m.end() - 1))
    return out


@pytest.mark.parametrize("seed", range(5))
def test_xor_candidates_match_reference(seed: int) -> None:
    rng = random.Random(seed)
    chunks = []
    for _ in range(40):
        kind = rng.randrange(4)
        if kind == 0:
            chunks.append(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64))))
        elif kind == 1:
            key = rng.randrange(1, 256)
            text = bytes(rng.randrange(0x20, 0x7F) for _ in range(rng.randrange(3, 40)))
            chunks.append(bytes(b ^ key for b in text) + bytes([key]))
        elif kind == 2:
            chunks.append(b"\0" * rng.randrange(1, 16))
        else:
            chunks.append(bytes(rng.randrange(0x20, 0x7F) for _ in range(rng.randrange(1, 80))))
    data = b"".join(chunks)
    assert set(deobfus.xor_candidates(data)) == _naive_candidates(data)
