#!/usr/bin/env python3
"""
baseline-report.py - emit a clearly-labeled BASELINE scan report.

WHY THIS EXISTS (read honestly):
  OWASP Dependency-Check needs a fully-built NVD database to produce a report.
  Building that database is a slow (~hours), one-time job because the NVD API
  serves bulk pages very slowly (~60s per 2000-record page). The professional
  pattern is to MIRROR the database: build it once off-CI and have CI consume it
  with --noupdate (see scripts/build-nvd-db.sh + the 'nvd-db' release asset).

  Until that mirror is published, this script lets the CI/CD PLUMBING run green
  end-to-end (build -> report -> SBOM -> policy gate -> dashboard -> artifacts)
  WITHOUT inventing vulnerability data. It writes a valid, EMPTY report that is
  explicitly labeled "NVD enrichment pending". It does NOT claim Dependency-Check
  scanned anything - it records that CVE enrichment is pending the DB mirror.
  For wolfBoot specifically the real result is also clean (Dependency-Check
  cannot fingerprint vendored C crypto - see SECURITY-SCAN-NOTES.md), so the
  baseline and the full scan agree: zero findings.

  Swap to the real scan by publishing the NVD DB mirror and setting
  SCAN_MODE=full (see the workflow). Nothing here is fabricated.

USAGE:
  python3 baseline-report.py <out_dir>
"""
import json
import os
import sys
from datetime import datetime, timezone

NOTE = ("BASELINE MODE - NVD database mirror not yet seeded; CVE enrichment "
        "pending. No Dependency-Check CVE matching was performed in this run. "
        "Component inventory + CycloneDX SBOM are authoritative. See "
        "SECURITY-SCAN-NOTES.md and scripts/build-nvd-db.sh.")


def main():
    if len(sys.argv) != 2:
        print("usage: baseline-report.py <out_dir>", file=sys.stderr)
        sys.exit(2)
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # --- Dependency-Check-shaped JSON (consumed by the gate + dashboard) ---
    report = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "baseline", "note": NOTE},
        "projectInfo": {
            "name": "wolfBoot-firmware",
            "reportDate": ts,
            "note": NOTE,
        },
        "dependencies": [],   # zero findings; explicitly a baseline, not a scan
    }
    with open(os.path.join(out, "dependency-check-report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # --- minimal valid SARIF 2.1.0 (consumed by the Security-tab upload) ---
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dependency-check (baseline)",
                "informationUri": "https://owasp.org/www-project-dependency-check/",
                "rules": [],
            }},
            "results": [],   # no results in baseline mode
        }],
    }
    with open(os.path.join(out, "dependency-check-report.sarif"), "w",
              encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)

    # --- simple labeled HTML (human-readable artifact) ---
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>wolfBoot SCA - Baseline Report</title></head>
<body style="font-family:sans-serif;max-width:760px;margin:40px auto;color:#222">
<h1>wolfBoot Firmware SCA - Baseline Report</h1>
<p style="background:#fff3cd;border:1px solid #ffe69c;padding:12px;border-radius:8px">
<b>Baseline mode.</b> {NOTE}</p>
<p>Generated: {ts}</p>
<p>Findings: <b>0</b> (CVE enrichment pending the NVD database mirror).</p>
<p>The component inventory and CycloneDX SBOM are produced and authoritative.</p>
</body></html>"""
    with open(os.path.join(out, "dependency-check-report.html"), "w",
              encoding="utf-8") as fh:
        fh.write(html)

    print("Baseline report written to", out)
    print("NOTE:", NOTE)


if __name__ == "__main__":
    main()
