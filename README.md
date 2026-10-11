<h1 align="center">lucid</h1>

<p align="center">
  <b>Static reverse-engineering assistant — triage, auto-deobfuscation hints and embedded-payload detection for binaries.</b>
</p>

<p align="center">
  <a href="https://github.com/haind03/lucid-rev/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/haind03/lucid-rev/actions/workflows/ci.yml/badge.svg"></a>
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
|             | ELF without a section header table | MEDIUM |
| `deobfus`   | single-byte XOR-encoded, NUL-terminated ASCII strings in data sections | MEDIUM |
|             | stack strings built from `mov [rbp/rsp+x], imm` (byte…qword) and `movabs`+`mov qword` | LOW |
| `shellcode` | embedded PE (`MZ` + valid `PE\0\0`) or ELF (`\x7fELF` + valid `e_ident`) images | HIGH |
|             | GetPC stubs (`call $+5; pop r`, `fldz; fnstenv [esp-0xc]`) | HIGH |
|             | NOP sleds ≥ 16 bytes (HIGH next to a GetPC stub) | MEDIUM / HIGH |
|             | bare `MZ` / `call $+5` inside 256-byte windows with entropy > 6.5 | MEDIUM |

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

## Example

```console
$ lucid analyze sample            # test fixture from tests/conftest.py
```

```markdown
### [MEDIUM] Possible XOR string (key=0x5a)
- **Address:** `0x4020`
decoded : '/usr/share/lucid/secret.conf'
encoded : 75 2f 29 28 75 29 32 3b 28 3f 75 36 2f 39 33 3e ...

### [HIGH] NOP sled (32 x 0x90)
- **Address:** `0x4088`
hex  : 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
0x00004088: nop  (x32)
0x000040a8: e8 00 00 00 00           call 0x40ad
0x000040ad: 5b                       pop rbx
0x000040ae: 48 83 c3 10              add rbx, 0x10
```

On an ordinary binary such as `/bin/ls` the report contains only the
triage `INFO` summary — which is the correct result.

## Detection notes and limitations

Heuristics are tuned against false positives measured on the 484 ELF files of
an Ubuntu 24.04 `/usr/bin`, and against synthetic positives.

- **XOR strings.** All keys except `0x20` are tried (`0x20` only flips letter
  case, so every plain string would match). Candidates must read clearly
  better than the raw bytes under a small English letter/bigram model, contain
  no raw NUL, not be periodic tables, and not be substrings of longer
  plaintext. Measured: ~0.2 findings per system binary; recall ≈ 87 % on a
  set of typical strings (paths, DLL/API names, URLs, flags) across 8 keys.
  Strings containing the key character itself and very short strings are
  missed. Regions that light up under many unrelated keys (lookup tables,
  varints — common in Go binaries) are collapsed into one `INFO` finding that
  keeps a sample as evidence.
- **Stack strings.** Found at `-O0`-style code generation; optimizing
  compilers usually turn them into `movabs`/SSE stores or `.rodata` copies,
  and only the `movabs`+`mov qword` form is followed.
- **Shellcode.** Signatures are searched in all non-executable data, not
  only in high-entropy windows, because a NOP sled has near-zero entropy by
  construction; window entropy gates the weak signatures and is reported as
  context. Legitimate NOP-padding tables (e.g. in JIT engines and linkers) are
  reported as `MEDIUM` sleds. Executable sections are not scanned in M1.
- **Formats.** The loader accepts ELF, PE and Mach-O through LIEF, but the
  modules are only validated on ELF x86-64 in M1.

## Architecture

```
lucid/
├── cli.py            # argparse entry point: `lucid analyze <file>`
├── finding.py        # Finding dataclass + Severity enum (shared contract)
├── core/
│   ├── loader.py     # Binary: LIEF-backed view (sections, segments, imports, entropy)
│   ├── disasm.py     # Capstone helpers (optional dependency, degrades gracefully)
│   └── report.py     # Markdown + rich terminal renderers
└── modules/          # each module: run(bin: Binary) -> list[Finding]
    ├── triage.py
    ├── deobfus.py
    └── shellcode.py
```

Adding a module = write `run(bin) -> list[Finding]` and list its name in
`lucid/modules/__init__.py`. A module that fails or misses an optional dependency
is reported as *unavailable* instead of crashing the run.

## Testing

```bash
pytest -q
```

The suite compiles small ELF fixtures with `cc` at runtime (XOR-encoded
string, an inert MZ/PE + NOP sled + `call $+5` blob, a stack string, UPX
markers) and checks every finding's address against the real symbol address.
A C compiler is required; tests are skipped if none is found.

## Scope of use

`lucid` is intended **only** for authorized security research, CTF challenges,
coursework / academic work and responsible-disclosure (bug bounty / CVE)
analysis of binaries you are permitted to examine. It reads binaries to help a
human understand them; it does **not** generate, modify, or conceal malicious
code. Users are responsible for complying with applicable laws and the terms of
any program they test under.

## Author

**HaiND** — Posts and Telecommunications Institute of Technology (PTIT), Vietnam
· <haind@ptit.edu.vn>

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
