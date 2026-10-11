<h1 align="center">lucid</h1>

<p align="center">
  <b>Static reverse-engineering assistant — triage, auto-deobfuscation hints and embedded-payload detection for binaries.</b>
</p>

<p align="center">
  <a href="https://github.com/haind03/lucid-rev/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/haind03/lucid-rev/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange">
  <img alt="Platform" src="https://img.shields.io/badge/target-ELF%20x86--64-lightgrey">
</p>

---

`lucid` statically inspects an **existing** binary and reports the things that
make it hard to read — packing, encoded strings, embedded payloads — so an
analyst can get to the interesting code faster. Every finding carries concrete
evidence (raw bytes, disassembly or the decoded string): heuristics are hints
for a human analyst, never verdicts.

## Features

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

**Out of scope:** patching, emulation, dynamic execution, PE / Mach-O deep
analysis.

## Installation

Requires Python ≥ 3.11.

```bash
git clone https://github.com/haind03/lucid-rev.git
cd lucid-rev
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'          # or: pip install -r requirements.txt
```

### From a release

```bash
pip install https://github.com/Haind03/lucid-rev/releases/download/v0.2.0/lucid_rev-0.2.0-py3-none-any.whl
```

### Docker

```bash
docker pull ghcr.io/haind03/lucid-rev:0.2.0
docker run --rm -v "$PWD:/work" ghcr.io/haind03/lucid-rev:0.2.0 analyze /work/sample.elf
```

The container runs as an unprivileged user; the report is written next to the
input inside the mounted directory.

## Usage

```bash
lucid analyze sample.elf                       # Markdown -> sample.elf.lucid.md
lucid analyze sample.elf -f json               # JSON     -> sample.elf.lucid.json
lucid analyze sample.elf -f sarif -o out.sarif # SARIF 2.1.0
lucid analyze sample.elf -f json -o - -q       # JSON on stdout, nothing else
lucid analyze sample.elf --min-severity medium # hide INFO/LOW findings
lucid analyze sample.elf --fail-on high        # exit 2 if any HIGH finding
```

| Option | Meaning |
|---|---|
| `-f, --format md\|json\|sarif` | report format (default `md`) |
| `-o, --output PATH` | report path (default `<file>.lucid.<format>`); `-` = stdout |
| `--min-severity SEV` | drop findings below `SEV` from the report and terminal |
| `--fail-on SEV` | exit `2` when any finding is at or above `SEV` — evaluated on **all** findings, independent of `--min-severity` |
| `-q, --quiet` | no terminal output |

Exit codes: `0` success, `1` error (unparsable input, unwritable report),
`2` `--fail-on` triggered.

### Report formats

- **Markdown** — human-readable summary plus one section per module.
- **JSON** (`"schema": "lucid-report/1"`) — target path, size, SHA-256, format
  and architecture; per-module status; every finding with `rule`, `severity`,
  `address` (int and hex), `detail`, `evidence` and `meta`.
- **SARIF 2.1.0** — validated against the OASIS schema; one result per
  finding with the binary location as `physicalLocation.address.absoluteAddress`
  and evidence in `properties`. Opens in SARIF viewers such as the VS Code
  SARIF Viewer. GitHub code scanning expects source line regions, so binary-only
  results may not display there.

### Rules

Every finding carries a stable rule id (also used as the SARIF `ruleId`):

| Rule | Max severity | Meaning |
|---|---|---|
| `triage/summary` | INFO | Format, architecture, entrypoint and section/import counts. |
| `triage/high-entropy-section` | MEDIUM | Section entropy above 7.0 bits/byte: likely packed, encrypted or compressed. |
| `triage/sparse-imports` | MEDIUM | Almost no imports next to a large executable region, typical of packers. |
| `triage/no-section-headers` | MEDIUM | ELF without a section header table. |
| `triage/upx-section` | HIGH | Section name created by the UPX packer. |
| `triage/upx-magic` | HIGH | 'UPX!' marker found in the file. |
| `deobfus/xor-string` | MEDIUM | NUL-terminated ASCII string recovered with a single-byte XOR key. |
| `deobfus/xor-noisy-region` | INFO | Region where many unrelated XOR keys decode short text; weak candidates suppressed. |
| `deobfus/stack-string` | LOW | String assembled from immediate stores to consecutive stack slots. |
| `deobfus/stack-scan-skipped` | INFO | Stack-string scan unavailable (Capstone missing or unsupported architecture). |
| `shellcode/embedded-pe` | HIGH | DOS header with a valid PE signature inside data. |
| `shellcode/embedded-mz` | MEDIUM | 'MZ' header with a plausible e_lfanew inside a high-entropy window. |
| `shellcode/embedded-elf` | HIGH | ELF magic with a valid e_ident inside data. |
| `shellcode/getpc-stub` | HIGH | GetPC sequence (call $+5; pop or fldz; fnstenv) inside data. |
| `shellcode/getpc-call5` | MEDIUM | call $+5 without a following pop inside a high-entropy window. |
| `shellcode/nop-sled` | HIGH | Run of at least 16 single-byte NOPs inside data. |

### In CI

```yaml
- run: pip install https://github.com/Haind03/lucid-rev/releases/download/v0.2.0/lucid_rev-0.2.0-py3-none-any.whl
- run: lucid analyze build/app -f json -o lucid.json --fail-on high
```

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
  plaintext. The scan classifies bytes per key with a translate table and
  locates terminated runs with `bytes.find`, so all 484 binaries are scanned in
  about 30 s. Measured: ~0.2 findings per system binary; recall ≈ 87 % on a
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
├── rules.py          # catalogue of rule ids emitted by the modules
├── core/
│   ├── loader.py     # Binary: LIEF-backed view (sections, segments, imports, entropy)
│   ├── disasm.py     # Capstone helpers (optional dependency, degrades gracefully)
│   └── report.py     # Markdown / JSON / SARIF + rich terminal renderers
└── modules/          # each module: run(bin: Binary) -> list[Finding]
    ├── triage.py
    ├── deobfus.py
    └── shellcode.py
```

Adding a module = write `run(bin) -> list[Finding]`, list its name in
`lucid/modules/__init__.py` and register its rule ids in `lucid/rules.py`
(a test fails if a finding uses an uncatalogued rule). A module that fails or misses an optional dependency
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
  version      = {0.2.0}
}
```

## License

Released under the [MIT License](LICENSE).
Copyright © 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT).
