# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""YARA scanning with bundled permissive rule sets and optional user rules.

Bundled sets live in ``lucid/yara_rules/<source>/`` (see SOURCES.json for the
pinned upstream commits and licenses). Extra rules are added with
``configure(paths=[...])``, which the CLI maps to ``--yara PATH``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yara  # optional dependency: an ImportError marks the module unavailable

from lucid.core.loader import Binary
from lucid.finding import Finding, Severity

MODULE = "yarascan"
BUNDLED_DIR = Path(__file__).resolve().parent.parent / "yara_rules"
RULE_SUFFIXES = (".yar", ".yara", ".rules")
SCAN_TIMEOUT = 60  # seconds per binary
_MAX_STRINGS = 8

#: Externals used by popular community sets (e.g. signature-base) so they compile.
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}

_CATEGORY_SEVERITY = {
    "MALWARE": Severity.HIGH,
    "EXPLOIT": Severity.HIGH,
    "TOOL": Severity.MEDIUM,
    "HACKTOOL": Severity.MEDIUM,
    "PUA": Severity.LOW,
    "INFO": Severity.INFO,
}


class YaraConfigError(ValueError):
    """A user-supplied rule path does not exist or does not compile."""


@dataclass
class _Config:
    bundled: bool = True
    paths: list[str] = field(default_factory=list)
    _rules: object | None = None
    _defaults: dict[str, Severity] = field(default_factory=dict)


_config = _Config()
#: Compiled rules keyed by (bundled, ((path, mtime), ...)): compiling the bundled
#: sets takes ~0.4 s, so repeated configure() calls reuse the result.
_cache: dict[tuple, object] = {}


def _rule_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.suffix.lower() in RULE_SUFFIXES)


def _bundled_sources() -> dict[str, Severity]:
    manifest = BUNDLED_DIR / "SOURCES.json"
    if not manifest.is_file():
        return {}
    return {s["name"]: Severity[s["default_severity"]] for s in json.loads(manifest.read_text())}


def configure(paths: list[str] | None = None, bundled: bool = True) -> int:
    """Select rule sources and compile them now; returns the number of rule files.

    Raises YaraConfigError for a missing path or a rule file that fails to compile,
    naming the file, so a typo in --yara never silently disables scanning.
    """
    filepaths: dict[str, str] = {}
    defaults: dict[str, Severity] = {}
    if bundled:
        for source, severity in _bundled_sources().items():
            for f in _rule_files(BUNDLED_DIR / source):
                filepaths[f"{source}/{f.relative_to(BUNDLED_DIR / source).as_posix()}"] = str(f)
            defaults[source] = severity
    for raw in paths or []:
        root = Path(raw)
        if not root.exists():
            raise YaraConfigError(f"YARA rule path not found: {raw}")
        files = _rule_files(root)
        if not files:
            raise YaraConfigError(f"no {'/'.join(RULE_SUFFIXES)} files under {raw}")
        for f in files:
            try:
                yara.compile(filepath=str(f), externals=EXTERNALS)
            except yara.Error as exc:
                raise YaraConfigError(f"{f}: {exc}") from None
            key = f"user/{f.relative_to(root).as_posix() if root.is_dir() else f.name}"
            filepaths[key] = str(f)
        defaults["user"] = Severity.MEDIUM
    _config.bundled, _config.paths, _config._defaults = bundled, list(paths or []), defaults
    key = (bundled, tuple(sorted((k, Path(v).stat().st_mtime_ns) for k, v in filepaths.items())))
    if filepaths and key not in _cache:
        _cache[key] = yara.compile(filepaths=filepaths, externals=EXTERNALS)
    _config._rules = _cache.get(key)
    return len(filepaths)


def _severity(meta: dict, source: str) -> Severity:
    """Map rule metadata to a lucid severity (score > severity > category > source)."""
    score = meta.get("score")
    if isinstance(score, int):
        return (Severity.HIGH if score >= 75 else Severity.MEDIUM if score >= 50
                else Severity.LOW if score >= 25 else Severity.INFO)
    named = str(meta.get("severity", "")).upper()
    if named in Severity.__members__:
        return Severity[named]
    category = str(meta.get("category", "")).upper()
    if category in _CATEGORY_SEVERITY:
        return _CATEGORY_SEVERITY[category]
    return _config._defaults.get(source, Severity.MEDIUM)


_CLUSTER = 64  # bytes: hits this close are treated as one piece of evidence


def _evidence(bin: Binary, match: object) -> tuple[str, int | None]:
    """Evidence lines and the address where the rule's hits concentrate.

    The anchor is the hit with the most other hits within +/-64 bytes (ties: lowest
    offset). A table of constants therefore wins over one stray immediate in code.
    """
    hits = sorted(
        (inst.offset, string.identifier, inst)
        for string in match.strings  # type: ignore[attr-defined]
        for inst in string.instances
    )
    if not hits:
        return "(condition matched without string hits)", None
    offsets = [h[0] for h in hits]
    anchor = max(
        offsets,
        key=lambda o: (sum(1 for x in offsets if abs(x - o) <= _CLUSTER), -o),
    )
    shown = sorted(sorted(hits, key=lambda h: (abs(h[0] - anchor), h[0]))[:_MAX_STRINGS])
    lines = []
    for offset, identifier, inst in shown:
        va = bin.file_offset_to_va(offset)
        where = f"{va:#x}" if va is not None else "unmapped"
        data = inst.matched_data[:16].hex(" ")
        more = " ..." if inst.matched_length > 16 else ""
        lines.append(f"{identifier:<10} @ {where} (file {offset:#x}): {data}{more}")
    if len(hits) > _MAX_STRINGS:
        lines.append(f"... {len(hits) - _MAX_STRINGS} more string matches")
    return "\n".join(lines), bin.file_offset_to_va(anchor)


def run(bin: Binary) -> list[Finding]:
    """Scan the raw file with the configured YARA rules."""
    if _config._rules is None and _config.bundled and not _config.paths:
        configure()
    if _config._rules is None:
        return []
    try:
        matches = _config._rules.match(data=bin.raw, timeout=SCAN_TIMEOUT)  # type: ignore[attr-defined]
    except yara.TimeoutError:
        return [Finding(
            module=MODULE, title="YARA scan timed out", severity=Severity.INFO,
            evidence=f"timeout after {SCAN_TIMEOUT}s on {len(bin.raw)} bytes",
            detail="Some rules were too slow for this file; results are incomplete.",
            rule="yarascan/timeout",
        )]
    findings = []
    for m in matches:
        source = m.namespace.split("/", 1)[0]
        meta = dict(m.meta)
        evidence, address = _evidence(bin, m)
        description = meta.get("description") or meta.get("desc") or ""
        author = meta.get("author", "")
        detail = " ".join(
            part for part in (
                description.rstrip(".") + "." if description else "",
                f"Rule by {author}." if author else "",
                f"Source: {source} ({m.namespace})." if source != "user" else
                f"User rule file: {m.namespace.removeprefix('user/')}.",
            ) if part
        )
        findings.append(Finding(
            module=MODULE,
            title=f"YARA {source}: {m.rule}",
            severity=_severity(meta, source),
            address=address,
            evidence=evidence,
            detail=detail,
            meta={"yara_rule": m.rule, "namespace": m.namespace, "tags": list(m.tags),
                  **{k: v for k, v in meta.items() if k in (
                      "description", "author", "reference", "category", "score",
                      "license", "malware", "tc_detection_name", "tc_detection_type")}},
            rule=f"yara/{source}/{m.rule}",
        ))
    return findings
