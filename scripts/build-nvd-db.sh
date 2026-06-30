#!/usr/bin/env bash
# =============================================================================
# build-nvd-db.sh - build the NVD database ONCE on an un-throttled host.
# -----------------------------------------------------------------------------
# WHY THIS EXISTS:
#   NIST throttles GitHub-hosted runner IPs so aggressively that a full live NVD
#   sync inside CI takes hours and is unreliable. The industry-standard fix is to
#   MIRROR the database: build it once somewhere that isn't throttled (a dev
#   laptop on a residential connection, or an internal mirror host), then have CI
#   consume the pre-built DB with --noupdate.
#
#   This is conceptually the same thing Black Duck does with its hosted
#   KnowledgeBase, and what large orgs do by running an internal NVD mirror.
#
# WHAT IT PRODUCES:
#   nvd-data.tar.gz - the Dependency-Check H2 database, to be published as the
#   'nvd-db' GitHub release asset (the CI workflow downloads it).
#
# REQUIREMENTS: Docker (no local Java needed) and an NVD API key.
# Build with the SAME Dependency-Check version CI uses so the H2 schema matches.
#
# USAGE:
#   NVD_API_KEY=xxxx ./scripts/build-nvd-db.sh
# =============================================================================
set -euo pipefail

DC_VERSION="${DC_VERSION:-12.2.2}"
WORK="${WORK:-nvd-build}"

if [[ -z "${NVD_API_KEY:-}" ]]; then
  echo "ERROR: set NVD_API_KEY (free key: https://nvd.nist.gov/developers/request-an-api-key)" >&2
  exit 1
fi

mkdir -p "$WORK/data"

echo "Building NVD database with Dependency-Check $DC_VERSION (this is the slow, one-time step)..."
docker run --rm \
  -v "$(pwd)/$WORK/data:/usr/share/dependency-check/data" \
  "owasp/dependency-check:${DC_VERSION}" \
  --updateonly \
  --nvdApiKey "$NVD_API_KEY" \
  --nvdApiDelay 2000 --nvdMaxRetryCount 20

echo "Packaging database..."
tar -czf nvd-data.tar.gz -C "$WORK/data" .
echo "Done: nvd-data.tar.gz ($(du -h nvd-data.tar.gz | cut -f1))"
echo
echo "Publish it as the CI mirror asset, e.g.:"
echo "  gh release create nvd-db nvd-data.tar.gz --title 'NVD DB mirror' --notes 'Pre-built NVD database for CI'"
echo "  # or re-upload to refresh:  gh release upload nvd-db nvd-data.tar.gz --clobber"
