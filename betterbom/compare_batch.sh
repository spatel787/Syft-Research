#!/bin/bash
# compare_batch.sh — Syft-only vs BetterBOM, across the full binary set.
#
# For each binary:
#   1. build a Syft-only SBOM
#   2. build a BetterBOM SBOM
#   3. scan BOTH with grype
#   4. record components found and vulnerabilities found
#
# Output: comparison_results.csv  (paste this table into your slides)

mkdir -p sboms-compare

CSV="comparison_results.csv"
echo "binary,syft_components,betterbom_components,syft_vulns,betterbom_vulns" > "$CSV"

# Counts packages listed in an SPDX file (minus the binary's own entry).
count_components() {
  python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    pkgs=d.get('packages',[])
    # The SBOM names its own scan target via a DESCRIBES relationship.
    # Exclude that entry; everything else is a real detected component.
    described={r.get('relatedSpdxElement') for r in d.get('relationships',[])
               if r.get('relationshipType')=='DESCRIBES'}
    print(sum(1 for p in pkgs if p.get('SPDXID') not in described))
except Exception:
    print(0)
" "$1"
}

# Counts vulnerability matches grype reports for an SBOM.
count_vulns() {
  grype "sbom:$1" -o json -q 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(len(d.get('matches',[])))
except Exception:
    print(0)
"
}

scan_one() {
  local path="$1"
  local name="$2"

  if [ ! -f "$path" ]; then
    echo "  (skipping $name — not found at $path)" >&2
    return
  fi

  echo "=== $name ===" >&2

  local syft_sbom="sboms-compare/${name}-syft.spdx.json"
  local bb_sbom="sboms-compare/${name}-betterbom.spdx.json"

  syft "$path" -o spdx-json -q > "$syft_sbom" 2>/dev/null
  python3 betterbom.py "$path" --output "$bb_sbom" > /dev/null 2>&1

  local sc bc sv bv
  sc=$(count_components "$syft_sbom")
  bc=$(count_components "$bb_sbom")
  sv=$(count_vulns "$syft_sbom")
  bv=$(count_vulns "$bb_sbom")

  echo "  syft: $sc components, $sv vulns  |  betterbom: $bc components, $bv vulns" >&2
  echo "$name,$sc,$bc,$sv,$bv" >> "$CSV"
}

for bin in curl git ssh tar openssl python3 sqlite3 grep; do
  scan_one "/usr/bin/$bin" "$bin"
done

scan_one "$HOME/syft-research/curl-linux" "curl-linux"

echo "" >&2
echo "Done. Results written to $CSV" >&2
echo "" >&2
cat "$CSV"
