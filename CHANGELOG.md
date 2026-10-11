# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Release workflow: wheel/sdist attached to the GitHub Release and a container
  image published to `ghcr.io/haind03/lucid-rev`.

[Unreleased]: https://github.com/Haind03/lucid-rev/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Haind03/lucid-rev/releases/tag/v0.1.0
