"""
strings_parser.py — Detect embedded library version strings inside a binary.

Catches libraries that are statically linked or otherwise bundled, where
`otool -L` won't see them but their version banners survive in the bytes.

Usage:
    python3 strings_parser.py /usr/bin/curl
    python3 strings_parser.py ~/syft-research/curl-linux
"""

import subprocess
import re
import sys
import json


# Patterns for known library version strings. Each entry: (library_name, regex).
# The regex must have one capture group: the version string itself.
PATTERNS = [
    ("libcurl",   re.compile(r"libcurl/(\d+\.\d+\.\d+)")),
    ("openssl",   re.compile(r"OpenSSL (\d+\.\d+\.\d+[a-z]?)")),
    ("nghttp2",   re.compile(r"nghttp2/(\d+\.\d+\.\d+)")),
    ("zlib",      re.compile(r"zlib (?:version )?(\d+\.\d+\.\d+)")),
    ("libssh2",   re.compile(r"libssh2/(\d+\.\d+\.\d+)")),
    ("libidn2",   re.compile(r"libidn2/(\d+\.\d+\.\d+)")),
    ("brotli",    re.compile(r"brotli/(\d+\.\d+\.\d+)")),
    ("zstd",      re.compile(r"zstd/(\d+\.\d+\.\d+)")),
    ("sqlite",    re.compile(r"SQLite (?:version )?(\d+\.\d+\.\d+)")),
    ("python",    re.compile(r"Python (\d+\.\d+\.\d+)")),
    ("libxml2",   re.compile(r"libxml/(\d+\.\d+\.\d+)")),
    ("pcre",      re.compile(r"PCRE2? (\d+\.\d+)")),
    ("ncurses",   re.compile(r"ncurses (\d+\.\d+)")),
    ("readline",  re.compile(r"readline (\d+\.\d+)")),
]


def parse_strings(binary_path):
    """Run `strings` on a binary and return libraries detected by version pattern."""
    try:
        result = subprocess.run(
            ["strings", "-a", binary_path],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("ERROR: `strings` not found. It ships with Xcode command-line tools.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: strings failed for {binary_path}: {e.stderr}")
        sys.exit(1)

    found = {}  # name -> (version, matched_text). Dedup by library name.

    for line in result.stdout.splitlines():
        for name, pattern in PATTERNS:
            match = pattern.search(line)
            if match:
                version = match.group(1)
                if name not in found:
                    found[name] = (version, line.strip())

    libraries = []
    for name, (version, snippet) in found.items():
        libraries.append({
            "name": name,
            "path": None,            # strings can't tell us a path
            "version": version,
            "evidence": snippet[:120],  # keep the raw line as proof
            "detected_by": ["strings"],
        })

    return libraries


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 strings_parser.py <binary_path>")
        sys.exit(1)

    binary = sys.argv[1]
    libs = parse_strings(binary)
    print(json.dumps(libs, indent=2))