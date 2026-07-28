"""
syft_parser.py — Run syft on a binary and parse its output into our format.

Usage:
    python3 syft_parser.py /usr/bin/curl
"""

import subprocess
import json
import sys


def parse_syft(binary_path):
    """Run syft on a binary and return its detected packages as a list of dicts."""
    try:
        result = subprocess.run(
            ["syft", binary_path, "-o", "syft-json", "-q"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("ERROR: syft not found. Install with: brew install syft")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: syft failed for {binary_path}: {e.stderr}")
        sys.exit(1)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"ERROR: failed to parse syft JSON: {e}")
        sys.exit(1)

    libraries = []
    for artifact in data.get("artifacts", []):
        libraries.append({
            "name": artifact.get("name", "unknown"),
            "path": None,
            "version": artifact.get("version", "unknown"),
            "foundBy": artifact.get("foundBy"),
            "detected_by": ["syft"],
        })

    return libraries


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 syft_parser.py <binary_path>")
        sys.exit(1)

    binary = sys.argv[1]
    libs = parse_syft(binary)
    print(json.dumps(libs, indent=2))