"""
betterbom.py — Unified SBOM extractor for C/C++ binaries.

Combines syft, otool, and strings, outputs SPDX-JSON with standard
package identifiers (PURL + CPE) so vulnerability scanners can match.

Usage:
    python3 betterbom.py /usr/bin/curl
    python3 betterbom.py /usr/bin/curl --output sbom.spdx.json
"""

import sys
import json
import re
import subprocess
import argparse
import datetime
import uuid
import os
import hashlib

from otool_parser import parse_otool
from strings_parser import parse_strings
from syft_parser import parse_syft


# ---------------------------------------------------------------------------
# Knowledge tables
# ---------------------------------------------------------------------------

# Which source do we trust for a VERSION number?
# otool reports the dylib's internal compatibility stamp (e.g. libcurl "9.0.0"),
# which is NOT the real software release. syft and strings report real versions.
SOURCE_TRUST = {"syft": 3, "strings": 2, "otool": 1}

# Map the many spellings of a library onto one canonical package name.
# This is what lets "curl" (syft) and "libcurl" (otool) merge into one entry.
CANONICAL_NAMES = {
    "libcurl": "curl",
    "libz": "zlib",
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libsqlite3": "sqlite",
    "sqlite3": "sqlite",
    "libnghttp2": "nghttp2",
    "liblzma": "xz",
    "libbz2": "bzip2",
    "libxml2": "libxml2",
    "libexpat": "expat",
    "libarchive": "libarchive",
    "libncurses": "ncurses",
    "libncursesw": "ncurses",
    "libreadline": "readline",
    "libedit": "libedit",
    "libpcre": "pcre",
    "libpcre2": "pcre2",
    "libzstd": "zstd",
    "libbrotlidec": "brotli",
    "libbrotlienc": "brotli",
    "libbrotlicommon": "brotli",
    "libidn2": "libidn2",
    "libssh2": "libssh2",
    "libiconv": "libiconv",
    "libpsl": "libpsl",
    "libgcc_s": "gcc",
}

# CPE vendor guesses. A CPE looks like:
#   cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
# Scanners match on vendor+product, and the "right" vendor is not obvious,
# so we emit every plausible vendor for a library and let the scanner decide.
CPE_VENDORS = {
    "curl": ["haxx", "curl"],
    "openssl": ["openssl"],
    "zlib": ["zlib", "gnu"],
    "sqlite": ["sqlite"],
    "nghttp2": ["nghttp2"],
    "xz": ["tukaani"],
    "bzip2": ["bzip", "bzip2_project"],
    "libxml2": ["xmlsoft", "gnome"],
    "expat": ["libexpat", "libexpat_project"],
    "libarchive": ["libarchive"],
    "ncurses": ["gnu"],
    "readline": ["gnu"],
    "pcre": ["pcre"],
    "pcre2": ["pcre"],
    "zstd": ["facebook"],
    "brotli": ["google"],
    "libidn2": ["gnu"],
    "libssh2": ["libssh2"],
    "libiconv": ["gnu"],
    "python": ["python", "python_software_foundation"],
    "git": ["git", "git_project"],
    "openssh": ["openbsd"],
    "tar": ["gnu"],
    "grep": ["gnu"],
}

# Apple-shipped system libraries. These are real dependencies and belong in the
# SBOM, but they carry Apple build stamps (e.g. libSystem.B "1356.0.0") and have
# no public CVE records, so tagging them with a PURL/CPE would only create noise.
APPLE_SYSTEM_PREFIXES = (
    "libsystem", "libobjc", "libc++", "libresolv", "libdyld", "libcache",
    "libcommoncrypto", "libdispatch", "libmacho", "libxpc", "libcompiler_rt",
    "libkeymgr", "libunwind", "libunc", "libinfo", "libcorecrypto",
    "corefoundation", "security", "systemconfiguration", "foundation",
    "coreservices", "iokit", "libapple", "libnetwork", "libenergytrace",
)


def canonical_name(raw_name):
    """Normalize a library name so the same library from different tools merges."""
    name = raw_name.strip()
    # Drop a trailing .N version chunk some paths leave behind (libcurl.4 -> libcurl)
    name = re.sub(r"\.\d+$", "", name)
    lowered = name.lower()
    return CANONICAL_NAMES.get(lowered, lowered)


def is_apple_system_lib(name):
    lowered = name.lower()
    return any(lowered.startswith(prefix) for prefix in APPLE_SYSTEM_PREFIXES)


def sanitize_spdx_id(text):
    """SPDX IDs may only contain letters, digits, '.', and '-'."""
    return re.sub(r"[^A-Za-z0-9.\-]", "-", text)


def is_usable_version(version):
    """A version we can put in an identifier: present and numeric-looking."""
    if not version:
        return False
    if version in ("unknown", "NOASSERTION"):
        return False
    return bool(re.match(r"^\d", str(version)))


def build_external_refs(name, version):
    """Build the PURL and CPE identifiers a vulnerability scanner matches on."""
    refs = []
    if is_apple_system_lib(name) or not is_usable_version(version):
        return refs

    refs.append({
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": f"pkg:generic/{name}@{version}",
    })

    for vendor in CPE_VENDORS.get(name, [name]):
        refs.append({
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*",
        })

    return refs


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

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
    """Merge all three sources under a canonical name, keeping the best version."""
    merged = {}

    def add(libs):
        for lib in libs:
            key = canonical_name(lib["name"])
            source = lib["detected_by"][0]
            version = lib.get("version")

            if key not in merged:
                merged[key] = {
                    "name": key,
                    "aliases": set(),
                    "path": None,
                    "version": None,
                    "version_source": None,
                    "version_candidates": {},
                    "detected_by": [],
                }

            entry = merged[key]
            entry["aliases"].add(lib["name"])

            if source not in entry["detected_by"]:
                entry["detected_by"].append(source)

            if is_usable_version(version):
                entry["version_candidates"][source] = version
                current_trust = SOURCE_TRUST.get(entry["version_source"], -1)
                if SOURCE_TRUST.get(source, 0) > current_trust:
                    entry["version"] = version
                    entry["version_source"] = source

            if not entry.get("path") and lib.get("path"):
                entry["path"] = lib["path"]
            if not entry.get("evidence") and lib.get("evidence"):
                entry["evidence"] = lib["evidence"]
            if not entry.get("foundBy") and lib.get("foundBy"):
                entry["foundBy"] = lib["foundBy"]

    add(syft_libs)
    add(otool_libs)
    add(strings_libs)

    out = []
    for entry in merged.values():
        entry["aliases"] = sorted(entry["aliases"])
        if not entry["version"]:
            entry["version"] = "NOASSERTION"
        out.append(entry)
    return out


def to_spdx(binary_path, merged_libs):
    """Convert merged library list to SPDX-JSON format."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = "SPDXRef-DOCUMENT"
    binary_name = os.path.basename(binary_path)
    binary_key = canonical_name(binary_name)

    # The binary itself is one of the detected components. Pull it out of the
    # dependency list so it is not counted twice, and use its version for the
    # root package. Without a version, a scanner falls back to matching on name
    # alone, which pulls in advisories for unrelated packages that share the
    # name (e.g. GNU tar vs the npm "tar" package).
    self_entry = None
    dependencies = []
    for lib in merged_libs:
        if self_entry is None and lib["name"] == binary_key:
            self_entry = lib
        else:
            dependencies.append(lib)

    packages = []
    files = []
    relationships = []

    self_version = self_entry.get("version") if self_entry else None
    have_self_id = self_entry is not None and is_usable_version(self_version)

    if have_self_id:
        # We can identify the scan target, so assert it as a package.
        bin_spdx_id = f"SPDXRef-Package-{sanitize_spdx_id(binary_name)}"
        root_pkg = {
            "SPDXID": bin_spdx_id,
            "name": binary_key,
            "versionInfo": self_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "comment": f"Detected by: {', '.join(self_entry['detected_by'])}",
        }
        refs = build_external_refs(binary_key, self_version)
        if refs:
            root_pkg["externalRefs"] = refs
        packages.append(root_pkg)
        container_id = bin_spdx_id
        contains = "DEPENDS_ON"
    else:
        # No version for the scan target. Declaring it as a package would let a
        # scanner match on name alone and return advisories for unrelated
        # software that shares the name (GNU tar vs the npm "tar" package).
        # SPDX lets us describe the target as a file instead; scanners do not
        # look up files, so the false matches disappear.
        bin_spdx_id = f"SPDXRef-File-{sanitize_spdx_id(binary_name)}"
        sha1 = "0" * 40
        try:
            h = hashlib.sha1()
            with open(binary_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            sha1 = h.hexdigest()
        except Exception:
            pass
        files.append({
            "SPDXID": bin_spdx_id,
            "fileName": f"./{binary_name}",
            "checksums": [{"algorithm": "SHA1", "checksumValue": sha1}],
            "comment": "Scan target. No version identified, so not asserted as a package.",
        })
        container_id = bin_spdx_id
        contains = "CONTAINS"

    relationships.append({
        "spdxElementId": doc_id,
        "relatedSpdxElement": bin_spdx_id,
        "relationshipType": "DESCRIBES",
    })

    for i, lib in enumerate(dependencies):
        spdx_id = f"SPDXRef-Package-{sanitize_spdx_id(lib['name'])}-{i}"

        comment_bits = [f"Detected by: {', '.join(lib['detected_by'])}"]
        if lib.get("version_source"):
            comment_bits.append(f"Version from: {lib['version_source']}")
        if lib.get("version_candidates"):
            reported = ", ".join(
                f"{src}={ver}" for src, ver in sorted(lib["version_candidates"].items())
            )
            comment_bits.append(f"Versions reported: {reported}")
        if lib.get("aliases") and lib["aliases"] != [lib["name"]]:
            comment_bits.append(f"Aliases: {', '.join(lib['aliases'])}")
        if is_apple_system_lib(lib["name"]):
            comment_bits.append("Apple system library — no public CVE data; not identifier-tagged")

        pkg = {
            "SPDXID": spdx_id,
            "name": lib["name"],
            "versionInfo": lib.get("version", "NOASSERTION"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "comment": ". ".join(comment_bits),
        }

        refs = build_external_refs(lib["name"], lib.get("version"))
        if refs:
            pkg["externalRefs"] = refs

        packages.append(pkg)
        relationships.append({
            "spdxElementId": container_id,
            "relatedSpdxElement": spdx_id,
            "relationshipType": contains,
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": f"betterbom-sbom-{binary_name}",
        "documentNamespace": f"https://betterbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: betterbom-0.4 (syft+otool+strings)"],
        },
        "packages": packages,
        "files": files,
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

    tagged = sum(1 for p in spdx["packages"] if p.get("externalRefs"))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(spdx, f, indent=2)
        print(f"\n# Wrote SPDX-JSON to {args.output}")
    else:
        print(f"\n# Merged SBOM ({len(merged)} unique librar(ies)):\n")
        print(json.dumps(merged, indent=2, default=list))

    print("\n# Summary")
    print(f"  syft alone:      {len(syft_libs)}")
    print(f"  otool alone:     {len(otool_libs)}")
    print(f"  strings alone:   {len(strings_libs)}")
    print(f"  betterbom total: {len(merged)}")
    print(f"  scanner-ready:   {tagged} of {len(merged)} tagged with PURL/CPE")


if __name__ == "__main__":
    main()
