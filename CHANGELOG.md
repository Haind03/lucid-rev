# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-10-13

Milestone 3: YARA rules.

### Added
- `yarascan` module (optional extra `lucid-rev[yara]`): YARA matches become
  findings with rule id `yara/<source>/<rule>`, clustered hit address, matched
  bytes and rule metadata; severity derived from rule `score` / `severity` /
  `category`.
- Bundled rule sets with pinned commits and upstream licences: findcrypt-yara
  (BSD-3-Clause, `Big_Numbers0-5` removed), reversinglabs-yara-rules (MIT,
  without the PE certificate blocklist) and bartblaze/Yara-rules (MIT);
  `NOTICE` and `scripts/sync_yara_rules.py` to rebuild them.
- `--yara PATH` (repeatable, files or directories) and `--no-bundled-yara`;
  common externals are defined so community sets such as signature-base compile.

## [0.2.0] - 2026-10-11

Milestone 2: reporting and integration.

### Added
- `--format json` (schema `lucid-report/1`, with target SHA-256, size and
  architecture) and `--format sarif` (SARIF 2.1.0, validated against the
  OASIS schema); `-o -` writes the report to stdout.
- `--min-severity` to hide lower findings, `--fail-on` to exit with code 2
  when a finding reaches a severity, `-q` for no terminal output.
- Stable rule ids on every finding (e.g. `deobfus/xor-string`) and a rule
  catalogue in `lucid/rules.py`.

### Changed
- XOR string scan is about 7x faster (484 system binaries: 3m55s to 33s) with
  byte-for-byte identical findings.
- Default report path is `<file>.lucid.<format>`.

## [0.1.0] - 2026-10-11

Milestone 1.

### Added
- `lucid analyze <file>` CLI with a Markdown report (`<file>.lucid.md`, or `-o`)
  and a coloured terminal report; modules that fail or miss an optional
  dependency are reported instead of aborting the run.
- LIEF-backed `Binary` loader: format, architecture, entrypoint, sections and
  PT_LOAD segments with Shannon entropy, imported symbols, offset-to-VA mapping.
- `triage`: binary summary, sections with entropy > 7.0, near-empty import
  table next to large code, missing ELF section header table, UPX indicators.
- `deobfus`: single-byte XOR string recovery with false-positive filters
  measured on a system `/usr/bin`; stack strings from immediate stack stores.
- `shellcode`: embedded PE/ELF images, GetPC stubs, NOP sleds, with
  entropy-window context and Capstone listings as evidence.
- Test suite compiling ELF fixtures with `cc`; GitHub Actions CI on
  Python 3.11–3.13.
- Release workflow (tag push or manual run): wheel/sdist attached to the GitHub
  Release and a container image published to `ghcr.io/haind03/lucid-rev`.

[Unreleased]: https://github.com/Haind03/lucid-rev/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Haind03/lucid-rev/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Haind03/lucid-rev/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Haind03/lucid-rev/releases/tag/v0.1.0
