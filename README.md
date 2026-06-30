# Firmware SCA Security Pipeline — wolfBoot (Black Duck-pattern demo)

[![Firmware Security Scan (SCA)](https://github.com/farisjamal/wolfBoot-sca-pipeline/actions/workflows/firmware-security-scan.yml/badge.svg)](https://github.com/farisjamal/wolfBoot-sca-pipeline/actions/workflows/firmware-security-scan.yml)

A working **Software Composition Analysis (SCA) security gate** wired into a firmware
CI/CD autobuild — the same architecture an enterprise builds with **Black Duck + Polaris**,
recreated with free/open-source tooling against a real secure bootloader, **[wolfBoot](README.wolfBoot.md)**
(C, firmware signing via wolfCrypt).

> Built as a portfolio prototype for a Firmware Security Engineer role. It demonstrates
> the *pattern and reasoning* of Black Duck-style scanning, not the licensed product.

---

## What it does (every push)

```
checkout → build → SCA scan → POLICY GATE (fail on CRITICAL/HIGH) → SBOM → reports/artifacts → SARIF
```

| Pipeline step | Enterprise equivalent |
|---|---|
| SCA scan (OWASP Dependency-Check) | Black Duck Detect (`detect.jar`) |
| Policy gate: fail on CRITICAL/HIGH | Black Duck policy rule |
| `components.csv` manual inventory | Black Duck KnowledgeBase signature match |
| CycloneDX SBOM | Black Duck BDIO / SBOM export |
| Job summary + `dashboard/index.html` | Black Duck risk dashboard |
| SARIF → Security tab | Black Duck → ticketing integration |

## See it work — two runs

- 🟢 **Clean firmware passes** — baseline run, gate green.
- 🔴 **Vulnerable build blocked** — demo fixture (OpenSSL 1.0.1, zlib 1.2.11 with real CVEs)
  trips the gate; the build fails at the **Policy gate** step on a CRITICAL + two HIGH findings.

Run either from the **Actions tab → Firmware Security Scan (SCA) → Run workflow → `scan_mode`**:

| `scan_mode` | Result |
|---|---|
| `baseline` | green clean run (default on push) |
| `demo` | red — gate blocks a known-vulnerable component (real CVEs, labeled fixture) |
| `full` | real Dependency-Check scan vs a seeded NVD database mirror |

## Repository layout

| Path | Purpose |
|---|---|
| `.github/workflows/firmware-security-scan.yml` | the CI/CD pipeline (heavily commented) |
| `scripts/run-sca-scan.sh` | scan runner — CI CLI + local Docker fallback |
| `scripts/components.csv` | audited vendored-crypto component inventory |
| `scripts/generate-sbom.py` | CycloneDX 1.5 SBOM generator |
| `scripts/gate-and-summary.py` | policy gate + GitHub job summary |
| `scripts/build-nvd-db.sh` | one-time NVD database mirror builder |
| `scripts/demo-report.py` + `demo-findings.json` | demo fixture (real CVEs) for the gate |
| `dashboard/index.html` | static report viewer (open from disk, drop the JSON) |
| `SECURITY-SCAN-NOTES.md` | Black Duck / EUCRA Annex I / SSDF mapping + limitations |

## Compliance angle (EUCRA / SSDF)

- **SBOM** in a machine-readable format (CycloneDX) — EUCRA Annex I duty.
- **Vulnerability tracking** — every build scans and retains dated evidence.
- **Security by design** — the gate prevents known-vulnerable components shipping.

See [`SECURITY-SCAN-NOTES.md`](SECURITY-SCAN-NOTES.md) for the full mapping and the honest
limitations vs enterprise Black Duck (no KnowledgeBase, no BDSA feed, weaker C/C++ binary
scanning, no policy UI).

## Honesty notes

- wolfBoot itself scans **clean** — a valid result for a small, well-maintained project.
- The `demo` fixture uses **real** CVEs on **deliberately-included** old components to prove the
  gate fires. It is clearly labeled "DEMO FIXTURE" and is **not** a scan of wolfBoot.
- NIST's NVD API is too slow/throttled for a live in-CI sync, so the real-scan mode mirrors the
  database (build once off-CI, run with `--noupdate`) — the same approach enterprises use.

Upstream wolfBoot documentation: [`README.wolfBoot.md`](README.wolfBoot.md).
