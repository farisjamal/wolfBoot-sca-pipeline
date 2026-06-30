#!/usr/bin/env python3
"""
gate-and-summary.py - policy gate + GitHub Actions job summary.

WHAT IT DOES (this is the Black Duck "policy rule" analogue):
  1. Reads the Dependency-Check JSON report.
  2. Counts findings by severity.
  3. Writes a severity table + the top CVEs to the GitHub Actions job summary.
  4. FAILS the build (exit 1) if any finding matches GATE_SEVERITIES
     (default: CRITICAL,HIGH) - i.e. "stop the build if risky components make
     it into a release stream", exactly like a Black Duck policy gate.

A clean, zero-findings result is a valid outcome: the gate passes and the
summary says so. Nothing is fabricated.

USAGE:
  GATE_SEVERITIES="CRITICAL,HIGH" python3 gate-and-summary.py <dc-report.json>
"""
import json
import os
import sys

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def normalize_severity(raw):
    if raw is None:
        return "UNKNOWN"
    s = str(raw).strip().upper()
    if s in ("MODERATE",):
        return "MEDIUM"
    if s in SEV_ORDER:
        return s
    # Some entries store a CVSS number in 'severity' - bucket it.
    try:
        score = float(s)
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"
    except ValueError:
        return "UNKNOWN"


def cvss_score(vuln):
    v3 = vuln.get("cvssv3") or {}
    if v3.get("baseScore") is not None:
        return v3["baseScore"]
    v2 = vuln.get("cvssv2") or {}
    if v2.get("score") is not None:
        return v2["score"]
    return ""


def main():
    if len(sys.argv) != 2:
        print("usage: gate-and-summary.py <dc-report.json>", file=sys.stderr)
        sys.exit(2)
    report_path = sys.argv[1]

    gate = [s.strip().upper() for s in
            os.environ.get("GATE_SEVERITIES", "CRITICAL,HIGH").split(",") if s.strip()]

    if not os.path.exists(report_path):
        print(f"ERROR: report not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)

    deps = report.get("dependencies", [])
    counts = {s: 0 for s in SEV_ORDER}
    findings = []  # (severity, cve, component, cvss)

    for dep in deps:
        comp = dep.get("fileName", "unknown")
        for vuln in dep.get("vulnerabilities", []) or []:
            sev = normalize_severity(vuln.get("severity"))
            counts[sev] += 1
            findings.append((sev, vuln.get("name", "?"), comp, cvss_score(vuln)))

    total_components = len(deps)
    total_vulns = sum(counts.values())

    # Sort findings worst-first for the "top CVEs" table.
    findings.sort(key=lambda f: (SEV_ORDER.index(f[0]),
                                 -(float(f[3]) if str(f[3]) not in ("", "None") else 0)))

    # ---- build the markdown summary ----
    lines = []
    lines.append("# Firmware SCA Scan Results\n")
    lines.append(f"**Components scanned:** {total_components}  ")
    lines.append(f"**Total findings:** {total_vulns}  ")
    lines.append(f"**Policy gate severities:** {', '.join(gate)}\n")

    lines.append("## Findings by severity\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for s in SEV_ORDER:
        if counts[s]:
            lines.append(f"| {s} | {counts[s]} |")
    if total_vulns == 0:
        lines.append("| (none) | 0 |")
    lines.append("")

    if findings:
        lines.append("## Top findings\n")
        lines.append("| Severity | CVE | Component | CVSS |")
        lines.append("|----------|-----|-----------|------|")
        for sev, cve, comp, score in findings[:25]:
            lines.append(f"| {sev} | {cve} | {comp} | {score} |")
        lines.append("")
    else:
        lines.append("No known vulnerabilities were reported by Dependency-Check. "
                     "For a small, well-maintained project this is a valid clean result.\n")

    summary_md = "\n".join(lines)
    print(summary_md)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary_md + "\n")

    # ---- the gate ----
    blocking = sum(counts[s] for s in gate if s in counts)
    if blocking > 0:
        print(f"\nPOLICY GATE: FAIL - {blocking} finding(s) at severity "
              f"{'/'.join(gate)}. Failing the build.", file=sys.stderr)
        sys.exit(1)
    print(f"\nPOLICY GATE: PASS - no findings at severity {'/'.join(gate)}.")


if __name__ == "__main__":
    main()
