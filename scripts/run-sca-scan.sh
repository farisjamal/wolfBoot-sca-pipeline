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

# Disable analyzers that are IRRELEVANT to a C bootloader and that make blocking
# network calls (Maven Central, Sonatype OSS Index, RetireJS feed, npm/yarn
# audit). Those calls can hang for a very long time on a CI runner and add zero
# value for C firmware. We keep ONLY the NVD CVE feed (the part that matters).
# This is also why the scan is fast + deterministic.
DISABLE_ANALYZERS=(
  --disableOssIndex            # Sonatype OSS Index (network)
  --disableCentral             # Maven Central (network)
  --disableCentralCache
  --disableRetireJs            # RetireJS signature download (network)
  --disableNodeAudit           # npm audit (network)
  --disableNodeJS
  --disableYarnAudit
  --disablePnpmAudit
  --disableBundleAudit
  --disableAssembly            # .NET
  --disableMSBuild
  --disableNuspec
  --disableNugetconf
)

# NVD update resilience: a small delay + retries ride out transient NVD 503s.
NVD_TUNING=(--nvdApiDelay 2000 --nvdMaxRetryCount 10)

mkdir -p "$OUT_DIR"

# --- SCAN_MODE -------------------------------------------------------------
# baseline : emit a clearly-labeled empty report (NVD mirror not yet seeded) so
#            the whole pipeline runs green end-to-end without inventing data.
# demo     : emit a report from a labeled DEMO FIXTURE of known-vulnerable
#            components (real CVEs) to prove the policy gate blocks CRITICAL/HIGH.
# full     : run a real Dependency-Check scan (requires a seeded NVD DB).
SCAN_MODE="${SCAN_MODE:-full}"
if [[ "$SCAN_MODE" == "baseline" ]]; then
  echo "SCAN_MODE=baseline - emitting labeled baseline report (no NVD enrichment)."
  PY="$(command -v python3 || command -v python)"
  "$PY" "$(dirname "$0")/baseline-report.py" "$OUT_DIR"
  echo "Baseline report ready in $OUT_DIR/"
  exit 0
fi
if [[ "$SCAN_MODE" == "demo" ]]; then
  echo "SCAN_MODE=demo - emitting DEMO FIXTURE report (known-vulnerable components, real CVEs)."
  PY="$(command -v python3 || command -v python)"
  "$PY" "$(dirname "$0")/demo-report.py" "$(dirname "$0")/demo-findings.json" "$OUT_DIR"
  echo "Demo report ready in $OUT_DIR/ (expect the policy gate to FAIL the build)."
  exit 0
fi

# --- NVD database strategy -------------------------------------------------
# NIST throttles GitHub-hosted runner IPs *very* heavily, so a live full NVD
# sync inside CI is unreliable (observed ~11 min per 10k of 361k records = hours).
# The professional answer is the same one enterprises use: don't hit NIST from
# CI - mirror the database. We build the NVD DB once on an un-throttled host and
# pre-seed it into CI, then run with --noupdate.
#
#   DISABLE_NVD_UPDATE=true  -> use the pre-seeded DB, no NIST calls (CI default)
#   (unset) + NVD_API_KEY    -> live update (fine on a normal/residential IP)
NVD_ARG=()
if [[ "${DISABLE_NVD_UPDATE:-}" == "true" ]]; then
  echo "NVD live update DISABLED - using pre-seeded NVD database (--noupdate)."
  NVD_ARG=(--noupdate)
elif [[ -n "${NVD_API_KEY:-}" ]]; then
  echo "NVD live update ENABLED with API key."
  NVD_ARG=(--nvdApiKey "$NVD_API_KEY" "${NVD_TUNING[@]}")
else
  echo "WARN: NVD_API_KEY not set and update enabled - NVD sync will be slow." >&2
  NVD_ARG=("${NVD_TUNING[@]}")
fi

# Optional explicit NVD data directory (where the pre-seeded DB lives).
DATA_ARG=()
if [[ -n "${DC_DATA_DIR:-}" ]]; then
  DATA_ARG=(--data "$DC_DATA_DIR")
fi

echo "=============================================================="
echo " SCA scan: $PROJECT"
echo " scan path : $SCAN_PATH"
echo " output    : $OUT_DIR/ (HTML, JSON, SARIF)"
echo " data dir  : ${DC_DATA_DIR:-<default>}"
echo "=============================================================="

# The Linux launcher in the release zip is 'dependency-check.sh' (NOT
# 'dependency-check') - detect both so CI uses the cached-data CLI instead of
# silently falling back to Docker.
DC_BIN="$(command -v dependency-check 2>/dev/null || command -v dependency-check.sh 2>/dev/null || true)"

if [[ -n "$DC_BIN" ]]; then
  # ----- CI / local-with-CLI mode -----
  echo "Using Dependency-Check CLI: $DC_BIN"
  "$DC_BIN" \
    --project "$PROJECT" \
    --scan "$SCAN_PATH" \
    --out "$OUT_DIR" \
    "${FORMATS[@]}" \
    "${EXCLUDES[@]}" \
    "${DISABLE_ANALYZERS[@]}" \
    "${DATA_ARG[@]}" \
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
    "${DISABLE_ANALYZERS[@]}" \
    "${NVD_ARG[@]}"
fi

echo "Scan complete. Reports written to: $OUT_DIR/"
echo "  - dependency-check-report.html  (human-readable)"
echo "  - dependency-check-report.json  (machine-readable, drives the dashboard + gate)"
echo "  - dependency-check-report.sarif (GitHub code-scanning format)"
