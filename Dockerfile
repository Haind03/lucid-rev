# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HaiND, Posts and Telecommunications Institute of Technology (PTIT)
#
# Usage:
#   docker run --rm -v "$PWD:/work" ghcr.io/haind03/lucid-rev analyze /work/sample.elf
FROM python:3.12-slim

LABEL org.opencontainers.image.title="lucid" \
      org.opencontainers.image.description="Static reverse-engineering assistant: triage, deobfuscation hints and embedded payload detection for ELF binaries." \
      org.opencontainers.image.authors="HaiND <haind@ptit.edu.vn>" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Haind03/lucid-rev"

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY lucid ./lucid
RUN pip install --no-cache-dir ".[yara]" && rm -rf /src

RUN useradd --create-home --uid 1000 analyst
USER analyst
WORKDIR /work

ENTRYPOINT ["lucid"]
CMD ["--help"]
