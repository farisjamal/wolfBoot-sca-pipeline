#!/usr/bin/env python3
"""
demo-report.py - build a Dependency-Check-shaped report from a DEMO FIXTURE.

PURPOSE (state this plainly in the interview):
  This produces a report from scripts/demo-findings.json, a controlled test
  fixture of deliberately-old, known-vulnerable components (OpenSSL 1.0.1, zlib
  1.2.11) with their REAL, publicly documented CVEs. Its only job is to prove the
  POLICY GATE and DASHBOARD work end-to-end - i.e. that a CRITICAL/HIGH finding
  actually blocks the build, exactly like a Black Duck policy gate.

  It is NOT a scan of wolfBoot (wolfBoot is clean). Injecting a known-vulnerable
  component to verify an SCA gate fires is standard practice. The CVE IDs and
  scores are genuine; everything is clearly labeled "DEMO FIXTURE".

USAGE:
  python3 demo-report.py <demo-findings.json> <out_dir>
"""
import json
import os
import sys
from datetime import datetime, timezone

LABEL = ("DEMO FIXTURE - report built from a controlled set of known-vulnerable "
         "components (real CVEs) to demonstrate the policy gate. NOT a scan of "
         "wolfBoot. See SECURITY-SCAN-NOTES.md.")


def main():
    if len(sys.argv) != 3:
        print("usage: demo-report.py <demo-findings.json> <out_dir>", file=sys.stderr)
        sys.exit(2)
    findings_path, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(findings_path, encoding="utf-8") as fh:
        fixture = json.load(fh)

    # --- Dependency-Check-shaped JSON (consumed by gate + dashboard) ---
    dependencies = []
    sarif_results = []
    sarif_rules = []
    for comp in fixture.get("components", []):
        label = f"{comp['name']}-{comp['version']} (DEMO FIXTURE)"
        vulns = []
        for v in comp.get("vulnerabilities", []):
            vulns.append({
                "source": "DEMO-FIXTURE",
                "name": v["cve"],
                "severity": v["severity"],
                "cvssv3": {"baseScore": v["cvssv3"], "baseSeverity": v["severity"]},
                "description": v.get("name", ""),
            })
            rule_id = v["cve"]
            sarif_rules.append({
                "id": rule_id,
                "shortDescription": {"text": f"{v['cve']} ({v['severity']})"},
            })
            sarif_results.append({
                "ruleId": rule_id,
                "level": "error" if v["severity"] in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f"{label}: {v['cve']} - {v.get('name','')} "
                                    f"[{v['severity']} CVSS {v['cvssv3']}]"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f"demo-fixture/{comp['name']}"}}}],
            })
        dependencies.append({
            "fileName": label,
            "filePath": f"demo-fixture/{comp['name']}-{comp['version']}",
            "vulnerabilities": vulns,
        })

    report = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "demo-fixture", "note": LABEL},
        "projectInfo": {"name": "wolfBoot-firmware (DEMO FIXTURE)",
                        "reportDate": ts, "note": LABEL},
        "dependencies": dependencies,
    }
    with open(os.path.join(out, "dependency-check-report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dependency-check (demo fixture)",
                "informationUri": "https://owasp.org/www-project-dependency-check/",
                "rules": sarif_rules,
            }},
            "results": sarif_results,
        }],
    }
    with open(os.path.join(out, "dependency-check-report.sarif"), "w",
              encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)

    # --- labeled HTML ---
    rows = ""
    for d in dependencies:
        for v in d["vulnerabilities"]:
            rows += (f"<tr><td>{v['severity']}</td><td>{v['name']}</td>"
                     f"<td>{d['fileName']}</td><td>{v['cvssv3']['baseScore']}</td></tr>")
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>wolfBoot SCA - Demo Fixture Report</title></head>
<body style="font-family:sans-serif;max-width:820px;margin:40px auto;color:#222">
<h1>wolfBoot Firmware SCA - DEMO FIXTURE</h1>
<p style="background:#f8d7da;border:1px solid #f1aeb5;padding:12px;border-radius:8px">
<b>Demo fixture.</b> {LABEL}</p>
<p>Generated: {ts}</p>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse">
<tr><th>Severity</th><th>CVE</th><th>Component</th><th>CVSS</th></tr>{rows}</table>
</body></html>"""
    with open(os.path.join(out, "dependency-check-report.html"), "w",
              encoding="utf-8") as fh:
        fh.write(html)

    n = sum(len(d["vulnerabilities"]) for d in dependencies)
    print(f"Demo report written to {out} ({len(dependencies)} components, {n} CVEs).")
    print("NOTE:", LABEL)


if __name__ == "__main__":
    main()
