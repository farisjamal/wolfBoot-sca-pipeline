#!/usr/bin/env python3
"""
generate-sbom.py - build a CycloneDX 1.5 SBOM from the audited component list.

WHY:
  OWASP Dependency-Check does NOT emit CycloneDX (its formats are HTML/XML/CSV/
  JSON/SARIF/JUNIT/JENKINS/GITLAB). EUCRA Annex I and US SSDF both expect a
  machine-readable SBOM, so we generate one here from scripts/components.csv.
  This is the free analogue of Black Duck's BDIO / SBOM export.

USAGE:
  python3 generate-sbom.py <components.csv> <out.json>
"""
import csv
import json
import sys
import uuid
from datetime import datetime, timezone


def read_components(csv_path):
    """Read the CSV, skipping comment lines that start with '#'."""
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        data_lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    reader = csv.DictReader(data_lines)
    for row in reader:
        if row.get("name"):
            rows.append(row)
    return rows


def to_cyclonedx(rows):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # The first row (wolfBoot itself) is the subject of the SBOM (metadata.component);
    # everything else is a dependency component.
    root = rows[0] if rows else {"name": "wolfBoot", "version": "unknown"}
    deps = rows[1:]

    def component(row, ctype_default="library"):
        comp = {
            "type": row.get("type") or ctype_default,
            "name": row["name"],
            "version": row.get("version") or "unknown",
        }
        if row.get("supplier"):
            comp["supplier"] = {"name": row["supplier"]}
        if row.get("purl"):
            comp["purl"] = row["purl"]
        if row.get("notes"):
            comp["description"] = row["notes"]
        externals = []
        if row.get("vcs_url"):
            externals.append({"type": "vcs", "url": row["vcs_url"]})
        if externals:
            comp["externalReferences"] = externals
        if row.get("pinned_commit"):
            comp["properties"] = [
                {"name": "wolfboot:pinnedCommit", "value": row["pinned_commit"]}
            ]
        return comp

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "wolfBoot-sca-pipeline",
                    "name": "generate-sbom.py",
                    "version": "1.0",
                }
            ],
            "component": component(root, ctype_default="application"),
        },
        "components": [component(r) for r in deps],
    }
    return bom


def main():
    if len(sys.argv) != 3:
        print("usage: generate-sbom.py <components.csv> <out.json>", file=sys.stderr)
        sys.exit(2)
    csv_path, out_path = sys.argv[1], sys.argv[2]
    rows = read_components(csv_path)
    if not rows:
        print(f"ERROR: no components found in {csv_path}", file=sys.stderr)
        sys.exit(1)
    bom = to_cyclonedx(rows)
    import os
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
    print(f"CycloneDX SBOM written to {out_path} "
          f"({len(bom['components'])} dependency components + 1 root).")


if __name__ == "__main__":
    main()
