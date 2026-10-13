# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Milestone 3: YARA scanning with bundled and user-supplied rules."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

from conftest import XOR_KEY, XOR_PLAINTEXT, Sample  # noqa: E402
from lucid import cli  # noqa: E402
from lucid.core.loader import Binary  # noqa: E402
from lucid.finding import Severity  # noqa: E402
from lucid.modules import yarascan  # noqa: E402

XOR_RULE = f"""
rule lucid_test_xor_secret {{
    meta:
        description = "XOR-encoded test string from the lucid fixture"
        author = "lucid tests"
        score = 80
    strings:
        $enc = {{ {" ".join(f"{b ^ XOR_KEY:02x}" for b in XOR_PLAINTEXT[:12])} }}
    condition:
        $enc
}}
"""


@pytest.fixture(autouse=True)
def _reset_yara() -> Iterator[None]:
    yarascan.configure()  # bundled rules only, like a plain `lucid analyze`
    yield
    yarascan.configure()


def _yara_findings(path: Path):
    return [f for f in yarascan.run(Binary(str(path)))]


# bundled rules ----------------------------------------------------------------
def test_bundled_sources_are_licensed_and_compile() -> None:
    manifest = json.loads((yarascan.BUNDLED_DIR / "SOURCES.json").read_text())
    assert {s["name"] for s in manifest} == {"findcrypt", "reversinglabs", "bartblaze"}
    for source in manifest:
        assert source["license"] in {"MIT", "BSD-3-Clause"}
        assert len(source["commit"]) == 40
        assert (yarascan.BUNDLED_DIR / source["name"] / "LICENSE").is_file()
    assert yarascan.configure() == sum(s["files"] for s in manifest)


def test_findcrypt_noisy_rules_removed() -> None:
    text = (yarascan.BUNDLED_DIR / "findcrypt" / "findcrypt3.yar").read_text()
    assert "rule Big_Numbers" not in text
    assert text.startswith("// Modified for lucid")


def test_bundled_rule_finds_sha256_constants(crypto_elf: Sample) -> None:
    hits = [f for f in _yara_findings(crypto_elf.path)
            if f.rule == "yara/findcrypt/SHA256_Constants"]
    assert len(hits) == 1
    hit = hits[0]
    assert hit.severity == Severity.INFO  # capability, not a verdict
    assert hit.address == crypto_elf.symbols["sha256_init"]
    assert "67 e6 09 6a" in hit.evidence
    assert hit.meta["namespace"] == "findcrypt/findcrypt3.yar"


@pytest.mark.skipif(not Path("/bin/ls").exists(), reason="/bin/ls not present")
def test_bundled_rules_quiet_on_clean_binary() -> None:
    assert not [f for f in _yara_findings(Path("/bin/ls")) if f.severity > Severity.INFO]


# user rules -------------------------------------------------------------------
def test_user_rule_file(sample_elf: Sample, tmp_path: Path) -> None:
    rule = tmp_path / "xor.yar"
    rule.write_text(XOR_RULE)
    yarascan.configure([str(rule)])
    hit = next(f for f in _yara_findings(sample_elf.path)
               if f.rule == "yara/user/lucid_test_xor_secret")
    assert hit.severity == Severity.HIGH  # score 80
    assert hit.address == sample_elf.symbols["xor_secret"]
    assert "User rule file: xor.yar" in hit.detail


def test_user_rule_directory_and_no_bundled(crypto_elf: Sample, tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "xor.yara").write_text(XOR_RULE)
    (tmp_path / "ignored.txt").write_text("not a rule")
    assert yarascan.configure([str(tmp_path)], bundled=False) == 1
    assert _yara_findings(crypto_elf.path) == []  # findcrypt not loaded


def test_rules_using_externals_compile(tmp_path: Path) -> None:
    rule = tmp_path / "ext.yar"
    rule.write_text('rule uses_filename { condition: filename matches /x/ or true }')
    assert yarascan.configure([str(rule)], bundled=False) == 1


@pytest.mark.parametrize(
    ("meta", "source", "expected"),
    [
        ({"score": 90}, "user", Severity.HIGH),
        ({"score": 60}, "user", Severity.MEDIUM),
        ({"score": 30}, "user", Severity.LOW),
        ({"score": 5}, "user", Severity.INFO),
        ({"severity": "low"}, "user", Severity.LOW),
        ({"category": "MALWARE"}, "bartblaze", Severity.HIGH),
        ({"category": "INFO"}, "bartblaze", Severity.INFO),
        ({}, "findcrypt", Severity.INFO),
        ({}, "reversinglabs", Severity.HIGH),
    ],
)
def test_severity_mapping(meta: dict, source: str, expected: Severity) -> None:
    yarascan.configure()
    assert yarascan._severity(meta, source) == expected


# CLI ----------------------------------------------------------------------------
def test_cli_yara_flag_end_to_end(sample_elf: Sample, tmp_path: Path) -> None:
    rule = tmp_path / "xor.yar"
    rule.write_text(XOR_RULE)
    out = tmp_path / "r.json"
    code = cli.main(["analyze", str(sample_elf.path), "--yara", str(rule), "-f", "json",
                     "-o", str(out), "-q"])
    assert code == 0
    rules = {f["rule"] for f in json.loads(out.read_text())["findings"]}
    assert "yara/user/lucid_test_xor_secret" in rules


def test_cli_rejects_missing_rule_path(sample_elf: Sample, tmp_path: Path) -> None:
    assert cli.main(["analyze", str(sample_elf.path), "--yara", str(tmp_path / "nope"),
                     "-o", str(tmp_path / "r.md"), "-q"]) == cli.EXIT_ERROR


def test_cli_rejects_broken_rule(sample_elf: Sample, tmp_path: Path,
                                 capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "broken.yar"
    bad.write_text("rule broken { condition: }")
    assert cli.main(["analyze", str(sample_elf.path), "--yara", str(bad),
                     "-o", str(tmp_path / "r.md"), "-q"]) == cli.EXIT_ERROR
    assert "broken.yar" in capsys.readouterr().err


def test_cli_yara_without_yara_python(sample_elf: Sample, tmp_path: Path, monkeypatch,
                                      capsys: pytest.CaptureFixture[str]) -> None:
    import lucid.modules as modules

    monkeypatch.setitem(modules.UNAVAILABLE, "yarascan", "unavailable: no module named 'yara'")
    assert cli.main(["analyze", str(sample_elf.path), "--yara", str(tmp_path),
                     "-o", str(tmp_path / "r.md"), "-q"]) == cli.EXIT_ERROR
    assert "yara-python" in capsys.readouterr().err
