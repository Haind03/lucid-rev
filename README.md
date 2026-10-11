<h1 align="center">lucid</h1>

<p align="center">
  <b>Static reverse-engineering assistant — triage, auto-deobfuscation hints and embedded-payload detection for binaries.</b>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status" src="https://img.shields.io/badge/status-alpha%20(M1)-orange">
  <img alt="Platform" src="https://img.shields.io/badge/target-ELF%20x86--64-lightgrey">
</p>

---

`lucid` statically inspects an **existing** binary and reports the things that
make it hard to read — packing, encoded strings, embedded payloads — so an
analyst can get to the interesting code faster. Every finding carries concrete
evidence (raw bytes, disassembly or the decoded string): heuristics are hints
for a human analyst, never verdicts.

## Features (Milestone 1)

| Module      | What it reports | Severity |
|-------------|-----------------|----------|
| `triage`    | format / arch / entrypoint / section & import counts | INFO |
|             | sections with Shannon entropy > 7.0 (packed / encrypted / compressed) | MEDIUM |
|             | near-empty import table next to a large executable section | MEDIUM |
|             | UPX section names or `UPX!` magic | HIGH |
| `deobfus`   | single-byte XOR-encoded, NUL-terminated ASCII strings in data sections | MEDIUM |
|             | stack strings assembled with consecutive `mov byte [rbp/rsp+x], imm8` | LOW |
| `shellcode` | high-entropy 256-byte windows containing embedded `MZ` / `\x7fELF` headers, GetPC (`call $+5`), NOP sleds ≥ 16 bytes | MEDIUM / HIGH |

**Out of scope for M1:** patching, emulation, dynamic execution, PE / Mach-O
deep analysis.

## Installation

Requires Python ≥ 3.11.

```bash
git clone https://github.com/haind03/lucid-rev.git
cd lucid-rev
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'          # or: pip install -r requirements.txt
```

## Usage

```bash
lucid analyze /path/to/sample.elf            # report -> sample.elf.lucid.md
lucid analyze sample.elf -o report.md        # custom report path
```

The report is printed to the terminal (coloured by severity with `rich`) and
written as Markdown to `<file>.lucid.md`. Exit code is `0` on success, `1` if
the file cannot be parsed.

## Architecture

```
lucid/
├── cli.py            # argparse entry point: `lucid analyze <file>`
├── finding.py        # Finding dataclass + Severity enum (shared contract)
├── core/
│   ├── loader.py     # Binary: LIEF-backed view (sections, imports, arch, entropy)
│   └── report.py     # Markdown + rich terminal renderers
└── modules/          # each module: run(bin: Binary) -> list[Finding]
    ├── triage.py
    ├── deobfus.py
    └── shellcode.py
```

Adding a module = write `run(bin) -> list[Finding]` and append it to
`lucid.modules.REGISTRY`. A module that fails or misses an optional dependency
is reported as *unavailable* instead of crashing the run.

## Testing

```bash
pytest -q
```

The suite compiles a small ELF fixture with `cc` at runtime (XOR-encoded string
+ fake shellcode blob in `.data`), so a C compiler is required.

## Scope of use

`lucid` is intended **only** for authorized security research, CTF challenges,
coursework / academic work and responsible-disclosure (bug bounty / CVE)
analysis of binaries you are permitted to examine. It reads binaries to help a
human understand them; it does **not** generate, modify, or conceal malicious
code. Users are responsible for complying with applicable laws and the terms of
any program they test under.

## Author

**HaiND** — Posts and Telecommunications Institute of Technology (PTIT), Vietnam.

## Citation

If you use `lucid` in academic work, please cite:

```bibtex
@software{haind_lucid_2026,
  author       = {HaiND},
  title        = {lucid: A Static Reverse-Engineering Assistant for Deobfuscation and Payload Triage},
  year         = {2026},
  institution  = {Posts and Telecommunications Institute of Technology},
  url          = {https://github.com/haind03/lucid-rev},
  version      = {0.1.0}
}
```

## License

Released under the [MIT License](LICENSE).
Copyright © 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT).
