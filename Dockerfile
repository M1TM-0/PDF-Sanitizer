# syntax=docker/dockerfile:1
#
# Two-stage build. The runtime stage never contains a compiler, pip's
# cache, or source code beyond what's installed into the venv -- only the
# venv itself and the application's non-root user.
#
# Single deployment mode: a local/batch CLI worker, meant to be run with
# `--network none` for full network isolation while parsing untrusted
# PDFs (the default ENTRYPOINT). There is no HTTP server or listening
# port anywhere in this image -- see README.md "Docker".

# ---- Builder ------------------------------------------------------------------
FROM python:3.12-slim AS builder

# build-essential is only needed transiently in case some dependency lacks
# a prebuilt wheel for this exact platform/Python combination; it is never
# present in the runtime image below. pikepdf/pypdfium2/img2pdf/Pillow all
# ship manylinux wheels for common platforms as of this writing, so this
# stage is normally a no-compile, wheel-only install.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# ---- Runtime --------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="pdf-sanitizer" \
      org.opencontainers.image.description="Defense-in-depth sanitization of untrusted PDF files via render-and-reconstruct." \
      org.opencontainers.image.licenses="MIT"

# Fixed, predictable, non-root uid/gid with no login shell -- matches the
# tmpfs/volume uid/gid used in docker-compose.yml and the `docker run`
# examples in README.md.
RUN groupadd --gid 10001 sanitizer \
    && useradd --uid 10001 --gid sanitizer --create-home --shell /usr/sbin/nologin sanitizer

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PDF_SANITIZER_TEMP_DIR=/tmp/pdf_sanitizer \
    PDF_SANITIZER_LOG_JSON=true

# Created here so the directory exists and is owned correctly even when
# no tmpfs is mounted at runtime (e.g. quick local testing without the
# full hardening flags); production runs should still mount this path as
# a tmpfs -- see README.
RUN mkdir -p /tmp/pdf_sanitizer && chown -R sanitizer:sanitizer /tmp/pdf_sanitizer

WORKDIR /home/sanitizer
USER sanitizer

# No EXPOSE here: this image never listens on any port -- there is no
# HTTP server anywhere in this project.
ENTRYPOINT ["pdf-sanitizer"]
CMD ["--help"]
