# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - Milestone 1

### Added
- `lucid analyze <file>` CLI with Markdown (`<file>.lucid.md`) and coloured terminal reports.
- LIEF-backed `Binary` loader (sections, imports, architecture, Shannon entropy).
- `triage` module: binary summary, high-entropy sections, packer hints, UPX detection.
- `deobfus` module: single-byte XOR string recovery, stack-string detection.
- `shellcode` module: embedded MZ/ELF headers, GetPC `call $+5`, NOP sleds in high-entropy windows.
