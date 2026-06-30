#!/usr/bin/env bash
# =============================================================================
# run-sca-scan.sh - Software Composition Analysis scan for wolfBoot firmware
# -----------------------------------------------------------------------------
# Black Duck analogue:
#   This script is the equivalent of the Black Duck Detect (detect.jar) step.
#   Black Duck Detect would do signature + binary + snippet scanning against the
#   Black Duck KnowledgeBase. Here we use OWASP Dependency-Check (free), which
#   does dependency / file analysis only.
#
# *** IMPORTANT LIMITATION FOR C / C++ FIRMWARE (read this in the interview) ***
#   wolfBoot is C with no package manager. Dependency-Check has NO manifest to
#   read for a C project - its native C/C++ support is weak and relies on
#   filename/archive heuristics and CPE guesses, NOT the signature matching that
#   Black Duck's KnowledgeBase performs. Therefore the *authoritative* component
#   list for the vendored crypto libraries (wolfSSL/wolfCrypt, wolfTPM, etc.) is
#   maintained by hand in scripts/components.csv and turned into a CycloneDX SBOM
#   by scripts/generate-sbom.py. Treat Dependency-Check's CVE output here as
#   best-effort enrichment, not a complete C/C++ SCA result.
#
# RUN MODES:
#   - CI    : `dependency-check` is already on PATH (installed by the workflow).
#   - Local : no local Java required - falls back to the owasp/dependency-check
#             Docker image. (Docker must be installed and running.)
#
# NVD API KEY:
#   Set the NVD_API_KEY environment variable. Without it the NVD data update is
#   rate-limited (~10 requests/min) and can take 30-60 minutes. The CLI flag is
#   `--nvdApiKey` (confirmed from `dependency-check --help`).
#
# USAGE:
#   NVD_API_KEY=xxxx ./scripts/run-sca-scan.sh [scan_path]
#   (scan_path defaults to the repo root ".")
# =============================================================================
set -euo pipefail

SCAN_PATH="${1:-.}"
OUT_DIR="${OUT_DIR:-reports}"
PROJECT="wolfBoot-firmware"

# Formats confirmed valid in the Dependency-Check Format enum:
#   HTML, XML, CSV, JSON, SARIF, JUNIT, JENKINS, GITLAB, ALL
# (CYCLONEDX is intentionally NOT here - it is not a Dependency-Check format;
#  the SBOM is generated separately by generate-sbom.py.)
FORMATS=(--format HTML --format JSON --format SARIF)

# Skip non-firmware paths: scan output, git metadata, the dashboard viewer.
EXCLUDES=(--exclude "**/.git/**" --exclude "**/reports/**" --exclude "**/dashboard/**")

mkdir -p "$OUT_DIR"

# Pass the NVD API key only if it is set, so the script also runs offline-ish.
NVD_ARG=()
if [[ -n "${NVD_API_KEY:-}" ]]; then
  NVD_ARG=(--nvdApiKey "$NVD_API_KEY")
else
  echo "WARN: NVD_API_KEY is not set - NVD update will be slow / rate-limited." >&2
fi

echo "=============================================================="
echo " SCA scan: $PROJECT"
echo " scan path : $SCAN_PATH"
echo " output    : $OUT_DIR/ (HTML, JSON, SARIF)"
echo "=============================================================="

if command -v dependency-check >/dev/null 2>&1; then
  # ----- CI / local-with-CLI mode -----
  echo "Using Dependency-Check CLI on PATH."
  dependency-check \
    --project "$PROJECT" \
    --scan "$SCAN_PATH" \
    --out "$OUT_DIR" \
    "${FORMATS[@]}" \
    "${EXCLUDES[@]}" \
    "${NVD_ARG[@]}"
else
  # ----- Local Docker fallback (no local Java needed) -----
  echo "Dependency-Check CLI not found - falling back to Docker image."
  # Named volume 'dc-data' persists the NVD database between local runs.
  docker run --rm \
    -v "$(pwd):/src:ro" \
    -v "$(pwd)/$OUT_DIR:/report" \
    -v "dc-data:/usr/share/dependency-check/data" \
    owasp/dependency-check:latest \
    --project "$PROJECT" \
    --scan /src \
    --out /report \
    "${FORMATS[@]}" \
    --exclude "**/.git/**" --exclude "**/reports/**" --exclude "**/dashboard/**" \
    "${NVD_ARG[@]}"
fi

echo "Scan complete. Reports written to: $OUT_DIR/"
echo "  - dependency-check-report.html  (human-readable)"
echo "  - dependency-check-report.json  (machine-readable, drives the dashboard + gate)"
echo "  - dependency-check-report.sarif (GitHub code-scanning format)"
