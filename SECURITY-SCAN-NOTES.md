# Firmware SCA Security Pipeline — Notes

A free, open-source prototype of a **Black Duck / Polaris-style SCA gate** wired
into a firmware autobuild, demonstrated against **wolfBoot** (a secure bootloader
for microcontrollers; C; firmware signing/authentication via wolfCrypt). It is
intended to show the *architecture and reasoning* an enterprise pipeline uses,
using OWASP Dependency-Check in place of Black Duck Detect.

---

## 1. What this pipeline does, and the enterprise equivalent

Pipeline flow (`.github/workflows/firmware-security-scan.yml`):

| Step | This prototype | Black Duck / Polaris equivalent |
|------|----------------|---------------------------------|
| Checkout | `actions/checkout` | same |
| Build | `make keytools` (host tools, non-gating) | full firmware autobuild stage |
| SCA scan | OWASP Dependency-Check CLI (`scripts/run-sca-scan.sh`) | **Black Duck Detect** (`detect.jar`) scan |
| Component ID for C | manual inventory `scripts/components.csv` | Black Duck **KnowledgeBase** signature matching |
| SBOM | CycloneDX 1.5 via `scripts/generate-sbom.py` | Black Duck **BDIO** / SBOM export |
| Policy gate | `scripts/gate-and-summary.py` fails on CRITICAL/HIGH | Black Duck **policy rule** ("stop risky builds") |
| Report | HTML/JSON/SARIF artifact + job summary + `dashboard/index.html` | Black Duck project **risk dashboard** |
| Alerts | SARIF → GitHub Security tab | Black Duck → Jira/ticketing integration |

The centrepiece is the **policy gate**: the build *fails* if any CRITICAL or HIGH
CVE is present. That is the core value an SCA tool adds to CI — it stops a known-
vulnerable component from reaching a release stream.

---

## 2. How this would change with real Black Duck Detect

- **Invocation.** Instead of installing the Dependency-Check CLI, the build runs
  Black Duck Detect, e.g. download and run `detect.jar` (or the `detect.sh` /
  `powershell` bootstrap):
  ```
  java -jar detect.jar \
    --blackduck.url=$BD_URL \
    --blackduck.api.token=$BD_TOKEN \
    --detect.project.name=wolfBoot \
    --detect.tools=DETECTOR,SIGNATURE_SCAN,BINARY_SCAN \
    --detect.policy.check.fail.on.severities=CRITICAL,HIGH
  ```
  The `--detect.policy.check.fail.on.severities` flag *is* the gate — no custom
  parsing script needed; the server enforces the policy and returns a failing
  exit code.
- **Output format.** Detect produces **BDIO** (Black Duck I/O) and uploads it to
  the Black Duck server, which correlates against the KnowledgeBase and BDSA.
- **Scanning depth.** Detect does **signature + binary + snippet** scanning. For C
  firmware this matters: it can fingerprint a *statically linked / vendored copy*
  of wolfCrypt even with no manifest, identify the exact version, and flag
  modified or copy-pasted code (snippet). Dependency-Check cannot.
- **No manual component list.** `components.csv` exists here only because
  Dependency-Check can't identify C components by signature; Black Duck removes
  that manual step.

---

## 3. How this supports EUCRA (EU Cyber Resilience Act) Annex I

The CRA requires manufacturers of products with digital elements to manage
vulnerabilities across the lifecycle. This pipeline produces the evidence trail:

- **SBOM (Annex I, Part II §1 — "draw up an SBOM in a commonly used, machine-
  readable format").** `generate-sbom.py` emits **CycloneDX 1.5** JSON listing
  wolfBoot and its crypto dependencies with versions and pinned commits.
- **Vulnerability tracking & handling (Annex I, Part II §1–§2).** Every build
  scans for known CVEs and records the result as a retained artifact, giving a
  dated, auditable history of what was known and when.
- **Security by design / due diligence on components (Annex I, Part I §2).** The
  CRITICAL/HIGH gate is enforced *before* release, demonstrating that known-
  vulnerable components are actively prevented from shipping.
- **Reproducible evidence.** Reports (HTML/JSON/SARIF) and the SBOM are uploaded
  on every run (including failures), which is the kind of artifact an auditor or
  a conformity assessment under the CRA expects. The same evidence model maps to
  the US **SSDF (NIST SP 800-218)** practices PW.4 / RV.1.

> Scope note: this is a developer-pipeline prototype, not a legal compliance
> attestation. It produces the *technical evidence* those frameworks require.

---

## 4. Known limitations of this prototype vs enterprise Black Duck

- **No KnowledgeBase.** C/C++ component identification is best-effort. Vendored
  libraries are tracked by a hand-maintained `components.csv`, not signature
  matching. Dependency-Check's native C/C++ support is weak (filename/archive/CPE
  heuristics only).
- **No BDSA early-warning feed.** We rely on the public NVD, which lags behind
  Black Duck Security Advisories (BDSA often publish before NVD).
- **No binary or snippet scanning.** A modified or statically linked copy of a
  vulnerable library can be missed.
- **No policy management UI.** The gate is a Python script with one rule
  (CRITICAL/HIGH). Black Duck offers configurable, governable policies with
  approvals, waivers, and license-compliance rules.
- **NVD rate limits.** Without an NVD API key the database update is throttled;
  this prototype caches the NVD data and uses a key (repo secret `NVD_API_KEY`).
- **A clean result is expected.** wolfBoot is small and well-maintained, so a
  zero-findings scan is a normal, honest outcome — the gate passing is itself the
  demonstration. No results are fabricated.

---

## 5. Running it

**In CI (the demo):** push to `main`/`master` triggers the workflow. View the run,
the job summary (severity table + top CVEs), the `firmware-sca-reports` artifact,
and any SARIF alerts in the Security tab.

**Locally (no Java needed — uses Docker):**
```bash
export NVD_API_KEY=your-key      # optional but strongly recommended
bash scripts/run-sca-scan.sh .
python3 scripts/generate-sbom.py scripts/components.csv reports/sbom.cyclonedx.json
python3 scripts/gate-and-summary.py reports/dependency-check-report.json
# then open dashboard/index.html and drop the two JSON files onto it
```

**Repo setup (one-time):** add an NVD API key as the repository secret
`NVD_API_KEY` (Settings → Secrets and variables → Actions). Free key:
https://nvd.nist.gov/developers/request-an-api-key
