# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Analysis modules. Each exposes ``run(bin: Binary) -> list[Finding]``.

A module whose import fails (e.g. an optional dependency is missing) is left out
of ``REGISTRY`` and listed in ``UNAVAILABLE`` so the CLI can report it instead of
crashing.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable

from lucid.finding import Finding

_MODULES: tuple[str, ...] = ("triage", "deobfus")

REGISTRY: list[Callable[..., list[Finding]]] = []
UNAVAILABLE: dict[str, str] = {}

for _name in _MODULES:
    try:
        REGISTRY.append(importlib.import_module(f"{__name__}.{_name}").run)
    except ImportError as _exc:
        UNAVAILABLE[_name] = f"unavailable: {_exc}"
