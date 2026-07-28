"""
otool_parser.py — Extract linked libraries from a Mach-O binary using otool -L.

Usage:
    python3 otool_parser.py /usr/bin/curl
"""

import subprocess
import re
import sys
import json


def parse_otool(binary_path):
    """Run `otool -L` on a binary and return a list of linked libraries."""
    try:
        result = subprocess.run(
            ["otool", "-L", binary_path],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("ERROR: otool not found. Install Xcode command-line tools: xcode-select --install")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: otool failed for {binary_path}: {e.stderr}")
        sys.exit(1)

    libraries = []
    lines = result.stdout.strip().split("\n")

    # First line is just the binary path (e.g., "/usr/bin/curl:"), skip it.
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        # Expected format:
        # /usr/lib/libcurl.4.dylib (compatibility version 7.0.0, current version 9.0.0)
        match = re.match(
            r"^(?P<path>\S+)\s+\(compatibility version \S+, current version (?P<version>\S+)\)",
            line,
        )
        if not match:
            continue

        path = match.group("path")
        version = match.group("version")

        # Extract a clean name from the path (e.g., "/usr/lib/libcurl.4.dylib" -> "libcurl")
        filename = path.split("/")[-1]
        name = re.sub(r"\.\d+\.dylib$|\.dylib$", "", filename)

        libraries.append({
            "name": name,
            "path": path,
            "version": version,
            "detected_by": ["otool"],
        })

    return libraries


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 otool_parser.py <binary_path>")
        sys.exit(1)

    binary = sys.argv[1]
    libs = parse_otool(binary)
    print(json.dumps(libs, indent=2))