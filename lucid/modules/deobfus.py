# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Deobfuscation hints: single-byte XOR strings and stack-built strings."""

from __future__ import annotations

import re
from dataclasses import dataclass

from lucid.core import disasm
from lucid.core.loader import Binary, Section
from lucid.finding import Finding, Severity

MODULE = "deobfus"

MIN_LEN = 6
#: Linker/loader metadata sections that never hold program strings.
_SKIP_PREFIXES = (
    ".dyn", ".rela", ".rel.", ".gnu", ".note", ".eh_frame", ".got", ".plt",
    ".interp", ".init_array", ".fini_array", ".symtab", ".strtab", ".shstrtab",
    ".comment", ".debug", ".hash", ".bss", ".tbss",
)
_MAX_XOR_FINDINGS = 64
NOISY_HITS = 16
NOISY_KEYS = 8
_MAX_STACK_FINDINGS = 64
_TEXT_RE = re.compile(rb"[\x20-\x7e]{%d,}\x00" % MIN_LEN)
#: Key 0x20 only flips the case of letters: indistinguishable from plain strings.
_XOR_KEYS = [k for k in range(1, 256) if k != 0x20]
#: Raw 0x00 maps to 0x01 (neither printable nor NUL) so zero padding and NULs never
#: join a candidate run: plain strings never contain the key byte's ciphertext 0.
_XOR_TABLES = {k: bytes([0x01]) + bytes(b ^ k for b in range(1, 256)) for k in _XOR_KEYS}
_TEXT_PUNCT = frozenset(b" 0123456789./:-_,!?'@=%")
_IDENT_RE = re.compile(rb"[A-Za-z0-9_]+")
#: CTF-style flag: PREFIX{body}; body needs a separator or digit (leetspeak).
_FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,15}\{(?=[^}]*[_0-9])[\x21-\x7c\x7e]{6,}\}")

_VOWELS = frozenset(b"aeiouAEIOU")
#: The 13 most frequent English letters cover ~80% of English text but only
#: half of uniformly random letters — a cheap language model for short strings.
_COMMON = frozenset(b"etaoinsrhldcuETAOINSRHLDCU")
COMMON_RATIO = 0.6
_BIGRAMS = frozenset(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as "
    "ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ex ec na "
    "ta ia la el ss tr pa us mo ad ow di ot sh wo".split()
)


def _bigram_ratio(text: bytes) -> float:
    """Fraction of in-word letter pairs that are common English bigrams."""
    pairs = [
        w[i : i + 2].decode()
        for w in re.findall(rb"[a-z]{2,}", text.lower())
        for i in range(len(w) - 1)
    ]
    return sum(1 for p in pairs if p in _BIGRAMS) / max(len(pairs), 1)


def _is_alpha(b: int) -> bool:
    return 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def _letters(s: bytes) -> float:
    """Fraction of ASCII letters and spaces in ``s``."""
    return sum(1 for b in s if _is_alpha(b) or b == 0x20) / max(len(s), 1)


def _periodic(s: bytes) -> bool:
    """True for table-like data where bytes repeat at a short stride (2..8)."""
    if len(s) < 6:
        return False
    for stride in range(2, min(8, len(s) - 3) + 1):  # at least 3 comparisons
        same = sum(1 for i in range(len(s) - stride) if s[i] == s[i + stride])
        if same >= 0.6 * (len(s) - stride):
            return True
    return False



def language_score(s: bytes) -> float:
    """English-likeness of ``s`` (0..2): letter share x (common-letter + bigram ratio)."""
    letters = bytes(b for b in s if _is_alpha(b))
    if len(letters) < 2:
        return 0.0
    common = sum(1 for b in letters if b in _COMMON) / len(letters)
    return len(letters) / len(s) * (common + _bigram_ratio(s))


def looks_like_text(decoded: bytes) -> bool:
    """Heuristic: does ``decoded`` read like a word, sentence, path or flag?"""
    if _FLAG_RE.fullmatch(decoded):
        return True
    letters = [b for b in decoded if _is_alpha(b)]
    if len(set(decoded)) < 4 or len(letters) < 0.4 * len(decoded):
        return False
    texty = sum(1 for b in decoded if _is_alpha(b) or b in _TEXT_PUNCT)
    if texty < 0.85 * len(decoded):
        return False
    if max(decoded.count(c) for c in set(decoded)) > 0.4 * len(decoded):
        return False  # "pppppp" / "CCCCCC" padding artefacts
    if len(letters) < 4 or sum(1 for b in letters if b in _VOWELS) < 0.15 * len(letters):
        return False
    if sum(1 for b in letters if b in _COMMON) < COMMON_RATIO * len(letters):
        return False
    # case must be consistent: "lower", "UPPER" or "Capitalized words", not "mcH?*I"
    upper = sum(1 for b in letters if b < 0x61)
    if upper > 0.3 * len(letters) and upper < 0.9 * len(letters):
        return False
    bigrams = _bigram_ratio(decoded)
    if upper >= 0.9 * len(letters) and bigrams < 0.3:
        return False  # all-caps gibberish is common in byte tables XOR 0x40
    if len(letters) >= 8 and bigrams < 0.15:
        return False
    return not _periodic(decoded)


def _printable(b: int) -> bool:
    return 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D)


def _inside_plain_string(data: bytes, start: int, end: int) -> bool:
    """True if data[start:end] sits inside a longer run of printable plaintext.

    Catches substrings of C strings and of Go-style string blobs (no NULs). One
    extra byte is expected after the run: the encoded terminator (== key) may
    itself be printable.
    """
    a = start
    while a > 0 and _printable(data[a - 1]):
        a -= 1
    b = end
    while b < len(data) and _printable(data[b]):
        b += 1
    extra = (start - a) + (b - end) - 1
    terminated = b < len(data) and data[b] == 0
    return extra > 0 if terminated else extra >= 4


def _data_regions(bin: Binary) -> list[Section]:
    regions = [
        s for s in bin.sections
        if s.name and s.data and not s.executable and not s.name.startswith(_SKIP_PREFIXES)
    ]
    return regions or [s for s in bin.segments if s.data and not s.executable]


# --------------------------------------------------------------------------- XOR
@dataclass
class _XorHit:
    offset: int
    key: int
    decoded: bytes
    encoded: bytes
    score: float


def find_xor_strings(data: bytes) -> list[_XorHit]:
    """Find NUL-terminated printable strings hidden under a single-byte XOR key.

    A candidate is kept only if the decoded bytes read like text clearly better
    than the raw bytes do, the raw bytes contain no NUL and are not a periodic
    table (offsets, struct arrays), and printable raw bytes are not part of a
    longer plaintext string.
    Known limitations: strings containing the key character itself (which
    encodes to NUL) are split or missed, and key 0x20 is not tried because it
    only flips letter case (plain strings would all match).
    """
    best: dict[int, _XorHit] = {}
    for key, table in _XOR_TABLES.items():
        decoded_all = data.translate(table)
        for m in _TEXT_RE.finditer(decoded_all):
            start, end = m.start(), m.end() - 1  # end excludes the terminator
            decoded = decoded_all[start:end]
            encoded = data[start:end]
            if _periodic(encoded) or not looks_like_text(decoded):
                continue
            controls = sum(1 for b in encoded if b < 0x20)
            if (controls >= 0.7 * len(encoded) and len(decoded) < 10
                    and not _FLAG_RE.fullmatch(decoded) and _bigram_ratio(decoded) < 0.4):
                continue  # small-integer tables (varints, offsets) XOR 0x40..0x7f
            if not _FLAG_RE.fullmatch(decoded) and (
                language_score(decoded) < language_score(encoded) + 0.3
            ):
                continue  # raw bytes read about as well as the "decoded" ones
            if all(_printable(b) for b in encoded):
                # ciphertext that is itself printable is ambiguous with plain strings:
                # demand mostly-lowercase output and no enclosing plaintext C-string
                letters = [b for b in decoded if _is_alpha(b)]
                lower = sum(1 for b in letters if b >= 0x61)
                upper = len(letters) - lower
                cased = lower >= 0.6 * len(letters) or upper >= 0.9 * len(letters)
                if not cased or _IDENT_RE.fullmatch(encoded) or _inside_plain_string(data, start, end):
                    continue
            score = _letters(decoded) + 0.01 * sum(1 for b in decoded if 0x61 <= b <= 0x7A)
            prev = best.get(start)
            if prev is None or score > prev.score:
                best[start] = _XorHit(start, key, decoded, encoded, score)
    # drop hits that are suffixes of a longer hit with the same key
    hits = sorted(best.values(), key=lambda h: h.offset)
    kept: list[_XorHit] = []
    for h in hits:
        if kept and kept[-1].key == h.key and h.offset < kept[-1].offset + len(kept[-1].encoded):
            continue
        kept.append(h)
    return kept


def is_noisy(hits: list[_XorHit]) -> bool:
    """A region lighting up under many unrelated keys is a lookup table, not text."""
    return len(hits) > NOISY_HITS and len({h.key for h in hits}) > NOISY_KEYS


def is_strong(hit: _XorHit) -> bool:
    """Candidate that survives even in a noisy region: a CTF-style flag.

    Short letter strings decoded from tables score as well as real words under
    a unigram/bigram model, so nothing weaker is trusted there.
    """
    return bool(_FLAG_RE.fullmatch(hit.decoded))


def _xor_findings(bin: Binary) -> list[Finding]:
    findings: list[Finding] = []
    for region in _data_regions(bin):
        hits = find_xor_strings(region.data)
        if is_noisy(hits):
            strong = [h for h in hits if is_strong(h)]
            sample = "\n".join(
                f"{bin.offset_to_va(region, h.offset):#x} key={h.key:#04x} {h.decoded[:32]!r}"
                for h in hits[:5]
            )
            findings.append(
                Finding(
                    module=MODULE,
                    title=f"{len(hits) - len(strong)} weak XOR candidates suppressed in {region.name}",
                    rule="deobfus/xor-noisy-region",
                    severity=Severity.INFO,
                    address=region.va or None,
                    evidence=f"{len(hits)} candidates under {len({h.key for h in hits})} "
                    f"different keys; first ones:\n{sample}",
                    detail="Many unrelated keys decode short text-like runs here, which is "
                    "typical of lookup tables or varint data; only strong candidates are kept.",
                    meta={"suppressed": len(hits) - len(strong), "section": region.name},
                )
            )
            hits = strong
        for hit in hits:
            if len(findings) >= _MAX_XOR_FINDINGS:
                return findings
            text = hit.decoded.decode("ascii")
            findings.append(
                Finding(
                    module=MODULE,
                    title=f"Possible XOR string (key={hit.key:#04x})",
                    rule="deobfus/xor-string",
                    severity=Severity.MEDIUM,
                    address=bin.offset_to_va(region, hit.offset) if region.va else None,
                    evidence=f"decoded : {text!r}\n"
                    f"encoded : {hit.encoded[:48].hex(' ')}"
                    f"{' ...' if len(hit.encoded) > 48 else ''}\n"
                    f"section : {region.name} + {hit.offset:#x}",
                    detail=f"{len(hit.decoded)} bytes XOR {hit.key:#04x} decode to printable "
                    "ASCII terminated by the key byte (NUL after decoding); typical of "
                    "lightweight string obfuscation.",
                    meta={"key": hit.key, "decoded": text, "section": region.name},
                )
            )
    return findings


# --------------------------------------------------------------- stack strings
#: Byte-level prefilter for x86 stack stores, so only small windows get the slow
#: detailed disassembly: ``mov r/m, imm`` (C6/C7) or ``mov r/m, reg`` (88/89) with
#: [ebp/rbp+disp] (modrm 45/85) or [esp/rsp+disp] (modrm 44/84 + SIB 24), and
#: ``movabs reg, imm64`` (REX.W B8+r).
_STORE_RE = re.compile(
    rb"[\x40-\x4f]?[\x88\x89\xc6\xc7](?:[\x45\x85]|[\x44\x84]\x24)|[\x48\x49][\xb8-\xbf]"
)
_CLUSTER_GAP = 24  # max bytes between two stores of the same string
_MAX_INSN = 15


def _store_clusters(data: bytes) -> list[tuple[int, int]]:
    """(start, end) windows of ``data`` holding >= 2 nearby candidate stores."""
    clusters: list[tuple[int, int]] = []
    first = last = -1
    count = 0
    for m in _STORE_RE.finditer(data):
        if last >= 0 and m.start() - last <= _CLUSTER_GAP:
            last, count = m.start(), count + 1
            continue
        if count >= 2:
            clusters.append((first, min(len(data), last + _MAX_INSN)))
        first = last = m.start()
        count = 1
    if count >= 2:
        clusters.append((first, min(len(data), last + _MAX_INSN)))
    return clusters


class _StackScanner:
    """Collect immediates stored to consecutive stack slots and emit printable strings."""

    def __init__(self) -> None:
        from capstone import x86

        self.x86 = x86
        self.stack_regs = {x86.X86_REG_RBP, x86.X86_REG_RSP, x86.X86_REG_EBP, x86.X86_REG_ESP}
        self.results: list[tuple[object, bytes, list]] = []
        self._reset()

    def _reset(self) -> None:
        self.run: list = []
        self.slots: dict[int, int] = {}
        self.regs: dict[int, bytes] = {}  # register -> immediate loaded by movabs
        self.base: int | None = None

    def _store(self, insn: object) -> bytes | None:
        """Bytes written by ``mov [stack+disp], imm/reg-with-known-imm``, else None."""
        x86 = self.x86
        if insn.id != x86.X86_INS_MOV:  # type: ignore[attr-defined]
            return None
        dst, src = (insn.operands + [None, None])[:2]  # type: ignore[attr-defined]
        if dst is None or src is None or dst.type != x86.X86_OP_MEM:
            return None
        mem = dst.mem
        if mem.index != 0 or mem.base not in self.stack_regs:
            return None
        if self.base is not None and mem.base != self.base:
            return None
        if src.type == x86.X86_OP_IMM:
            value = (src.imm & ((1 << (8 * dst.size)) - 1)).to_bytes(dst.size, "little")
        elif src.type == x86.X86_OP_REG and src.reg in self.regs and dst.size == 8:
            value = self.regs[src.reg]
        else:
            return None
        self.base = mem.base
        for i, b in enumerate(value):
            self.slots[mem.disp + i] = b
        return value

    def feed(self, insn: object) -> None:
        """Process one instruction; a non-store ends the current run."""
        x86 = self.x86
        if self._store(insn) is not None:
            self.run.append(insn)
            return
        ops = insn.operands  # type: ignore[attr-defined]
        if (insn.id == x86.X86_INS_MOVABS and len(ops) == 2  # type: ignore[attr-defined]
                and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_IMM):
            self.regs[ops[0].reg] = (ops[1].imm & (2**64 - 1)).to_bytes(8, "little")
            self.run.append(insn)
            return
        self.flush()

    def flush(self) -> None:
        """Turn the collected slots into strings (contiguous printable runs)."""
        if self.slots:
            lo, hi = min(self.slots), max(self.slots)
            buf = bytes(self.slots.get(i, 0) for i in range(lo, hi + 1))
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % MIN_LEN, buf):
                if _letters(m.group()) >= 0.5:
                    self.results.append((self.run[0], m.group(), list(self.run)))
        self._reset()


def find_stack_strings(bin: Binary) -> list[tuple[object, bytes, list]]:
    """Return (first_insn, string, insns) for strings assembled by consecutive stack stores."""
    md = disasm.make_cs(bin.arch, detail=True)
    scanner = _StackScanner()
    for sec in (s for s in bin.sections if s.executable and s.data and s.name):
        for start, end in _store_clusters(sec.data):
            for insn in disasm.sweep(md, sec.data[start:end], sec.va + start):
                scanner.feed(insn)
            scanner.flush()
    return scanner.results


def _stack_findings(bin: Binary) -> list[Finding]:
    reason = disasm.available(bin.arch)
    if reason:
        return [
            Finding(
                module=MODULE,
                title="Stack-string scan skipped",
                rule="deobfus/stack-scan-skipped",
                severity=Severity.INFO,
                evidence=reason,
                detail="Stack-string detection needs Capstone and an x86/x86_64 target.",
            )
        ]
    findings = []
    for first, text, insns in find_stack_strings(bin)[:_MAX_STACK_FINDINGS]:
        listing = "\n".join(
            f"{i.address:#010x}: {i.mnemonic} {i.op_str}" for i in insns[:8]
        ) + (f"\n... ({len(insns) - 8} more)" if len(insns) > 8 else "")
        findings.append(
            Finding(
                module=MODULE,
                title=f"Stack string {text.decode('ascii')!r}",
                rule="deobfus/stack-string",
                severity=Severity.LOW,
                address=first.address,  # type: ignore[attr-defined]
                evidence=listing,
                detail=f"{len(insns)} consecutive stack stores of immediates spell a printable "
                "string; building strings on the stack hides them from `strings`.",
                meta={"string": text.decode("ascii")},
            )
        )
    return findings


def run(bin: Binary) -> list[Finding]:
    """Recover XOR-encoded strings in data sections and stack-built strings in code."""
    return _xor_findings(bin) + _stack_findings(bin)
