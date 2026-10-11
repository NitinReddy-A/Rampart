# syntax=docker/dockerfile:1

# Base images are pinned by digest (the multi-arch index, so linux/amd64 and linux/arm64 both
# resolve); Dependabot's docker ecosystem keeps the digest current.

# ---- Stage 1: build a wheel from the source ----
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build
WORKDIR /src
# Build tooling is hash-pinned, and the build runs without isolation so the pinned setuptools is
# the backend actually used (an isolated build would fetch an unpinned one).
COPY requirements/build.txt /tmp/build.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/build.txt
COPY . .
RUN python -m build --wheel --no-isolation --outdir /dist

# ---- Stage 2: tiny runtime image ----
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS runtime

# Rampart's core has ZERO runtime dependencies (stdlib only), so the image
# stays small. Install only the built wheel — --no-deps, so nothing is fetched from an index.
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir --no-deps /tmp/*.whl && rm -f /tmp/*.whl

# External scanners (nuclei / semgrep / nmap / trivy / testssl.sh) are OPTIONAL
# and are NOT bundled — the built-in oracles run with no external tools. To use
# the `--scanners` adapters, layer them into your own derived image, e.g.:
#   RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
#   COPY --from=projectdiscovery/nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

# Run as a non-root user.
RUN useradd --create-home --uid 10001 rampart
USER rampart
WORKDIR /work

ENTRYPOINT ["python", "-m", "rampart"]
CMD ["--help"]
