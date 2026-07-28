"""
betterbom.py — Unified SBOM extractor for C/C++ binaries.

Combines syft, otool, and strings, outputs SPDX-JSON.

Usage:
    python3 betterbom.py /usr/bin/curl
    python3 betterbom.py /usr/bin/curl --output sbom.spdx.json
"""

import sys
import json
import subprocess
import argparse
import datetime
import uuid
import os

from otool_parser import parse_otool
from strings_parser import parse_strings
from syft_parser import parse_syft


def is_macho(binary_path):
    try:
        result = subprocess.run(
            ["file", "-b", binary_path],
            capture_output=True, text=True, check=True,
        )
        return "Mach-O" in result.stdout
    except Exception:
        return False


def merge(syft_libs, otool_libs, strings_libs):
    merged = {}

    def add(libs):
        for lib in libs:
            key = lib["name"].lower()
            if key in merged:
                existing = merged[key]
                for src in lib["detected_by"]:
                    if src not in existing["detected_by"]:
                        existing["detected_by"].append(src)
                if not existing.get("path") and lib.get("path"):
                    existing["path"] = lib["path"]
                if not existing.get("evidence") and lib.get("evidence"):
                    existing["evidence"] = lib["evidence"]
                if not existing.get("foundBy") and lib.get("foundBy"):
                    existing["foundBy"] = lib["foundBy"]
            else:
                merged[key] = dict(lib)

    add(syft_libs)
    add(otool_libs)
    add(strings_libs)
    return list(merged.values())


def to_spdx(binary_path, merged_libs):
    """Convert merged library list to SPDX-JSON format."""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = f"SPDXRef-DOCUMENT"
    binary_name = os.path.basename(binary_path)

    packages = []
    relationships = []

    # The binary itself
    bin_spdx_id = f"SPDXRef-Package-{binary_name}"
    packages.append({
        "SPDXID": bin_spdx_id,
        "name": binary_name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "NOASSERTION",
    })
    relationships.append({
        "spdxElementId": doc_id,
        "relatedSpdxElement": bin_spdx_id,
        "relationshipType": "DESCRIBES",
    })

    # Each detected library
    for i, lib in enumerate(merged_libs):
        spdx_id = f"SPDXRef-Package-{lib['name']}-{i}"
        pkg = {
            "SPDXID": spdx_id,
            "name": lib["name"],
            "versionInfo": lib.get("version", "NOASSERTION"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "comment": f"Detected by: {', '.join(lib['detected_by'])}",
        }
        packages.append(pkg)
        relationships.append({
            "spdxElementId": bin_spdx_id,
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DEPENDS_ON",
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": f"betterbom-sbom-{binary_name}",
        "documentNamespace": f"https://betterbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: betterbom-0.1 (syft+otool+strings)"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--output", "-o", help="Write SPDX-JSON to this file")
    args = ap.parse_args()

    print(f"# Scanning {args.binary}\n")

    print("[1/3] Running syft ...")
    syft_libs = parse_syft(args.binary)
    print(f"      syft detected: {len(syft_libs)}")

    print("[2/3] Running otool -L ...")
    if is_macho(args.binary):
        otool_libs = parse_otool(args.binary)
        print(f"      otool detected: {len(otool_libs)}")
    else:
        otool_libs = []
        print("      (skipped — not a Mach-O binary)")

    print("[3/3] Running strings ...")
    strings_libs = parse_strings(args.binary)
    print(f"      strings detected: {len(strings_libs)}")

    merged = merge(syft_libs, otool_libs, strings_libs)
    spdx = to_spdx(args.binary, merged)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(spdx, f, indent=2)
        print(f"\n# Wrote SPDX-JSON to {args.output}")
    else:
        print(f"\n# Merged SBOM ({len(merged)} unique librar(ies)):\n")
        print(json.dumps(merged, indent=2))

    print(f"\n# Summary")
    print(f"  syft alone:      {len(syft_libs)}")
    print(f"  otool alone:     {len(otool_libs)}")
    print(f"  strings alone:   {len(strings_libs)}")
    print(f"  betterbom total: {len(merged)}")


if __name__ == "__main__":
    main()