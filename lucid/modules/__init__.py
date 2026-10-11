# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
"""Analysis modules. Each exposes ``run(bin: Binary) -> list[Finding]``."""

from collections.abc import Callable

REGISTRY: list[Callable] = []
