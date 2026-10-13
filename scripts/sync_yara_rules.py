#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Re-create lucid/yara_rules from pinned upstream commits.

Only permissively licensed rule sets are bundled. Each source is cloned at a
fixed commit, its LICENSE is copied next to the rules, and every exclusion or
modification is recorded in SOURCES.json. Run from the repository root:

    python scripts/sync_yara_rules.py            # uses the pinned commits
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEST = Path(__file__).resolve().parent.parent / "lucid" / "yara_rules"

SOURCES = [
    {
        "name": "findcrypt",
        "url": "https://github.com/polymorf/findcrypt-yara",
        "commit": "044644b",
        "license": "BSD-3-Clause",
        "include": ["findcrypt3.rules"],
        "rename": {"findcrypt3.rules": "findcrypt3.yar"},
        "drop_rules": r"Big_Numbers\d",
        "notes": "Rules Big_Numbers0-5 removed: they match any 20-64 character hex string "
                 "(build ids, hashes), cost ~98% of scan time and carry no crypto signal.",
        "default_severity": "INFO",
    },
    {
        "name": "reversinglabs",
        "url": "https://github.com/reversinglabs/reversinglabs-yara-rules",
        "commit": "e0a0be5",
        "license": "MIT",
        "include": ["yara/**/*.yara"],
        "strip_prefix": "yara/",
        "exclude": ["yara/certificate/**"],
        "notes": "yara/certificate excluded: code-signing certificate blocklist for PE files only.",
        "default_severity": "HIGH",
    },
    {
        "name": "bartblaze",
        "url": "https://github.com/bartblaze/Yara-rules",
        "commit": "5cc871d",
        "license": "MIT",
        "include": ["rules/**/*.yar"],
        "strip_prefix": "rules/",
        "notes": "TLP:CLEAR; rule meta retained as requested by the author.",
        "default_severity": "HIGH",
    },
]


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout.strip()


def _checkout(url: str, commit: str, into: Path) -> str:
    _git("clone", "--quiet", "--filter=blob:none", url, str(into))
    _git("checkout", "--quiet", commit, cwd=into)
    return _git("rev-parse", "HEAD", cwd=into)


def _drop_rules(text: str, pattern: str) -> tuple[str, list[str]]:
    dropped = re.findall(rf"(?m)^rule ({pattern})\b", text)
    text = re.sub(rf"(?ms)^rule (?:{pattern})\b.*?^}}\s*", "", text)
    return text, dropped


def sync() -> int:
    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)
    manifest = []
    with tempfile.TemporaryDirectory() as tmp:
        for src in SOURCES:
            repo = Path(tmp) / src["name"]
            full_commit = _checkout(src["url"], src["commit"], repo)
            out = DEST / src["name"]
            files = sorted({p for g in src["include"] for p in repo.glob(g)})
            excluded = {p for g in src.get("exclude", []) for p in repo.glob(g)}
            count = 0
            for f in files:
                if f in excluded:
                    continue
                rel = f.relative_to(repo).as_posix().removeprefix(src.get("strip_prefix", ""))
                rel = src.get("rename", {}).get(rel, rel)
                text = f.read_text(encoding="utf-8", errors="replace")
                dropped: list[str] = []
                if src.get("drop_rules"):
                    text, dropped = _drop_rules(text, src["drop_rules"])
                    note = (f"// Modified for lucid from {src['url']} @ {full_commit[:12]}:\n"
                            f"// removed rules {', '.join(dropped)} (see SOURCES.json).\n")
                    text = note + text
                target = out / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
                count += 1
            shutil.copy(repo / "LICENSE", out / "LICENSE")
            manifest.append({
                "name": src["name"], "url": src["url"], "commit": full_commit,
                "license": src["license"], "files": count,
                "excluded": src.get("exclude", []), "notes": src["notes"],
                "default_severity": src["default_severity"],
            })
            print(f"{src['name']}: {count} files @ {full_commit[:12]}")
    (DEST / "SOURCES.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(sync())
