#!/bin/bash
mkdir -p sboms
echo "binary,syft,otool,strings,betterbom_total"
for bin in curl git ssh tar openssl python3 sqlite3 grep; do
  out=$(python3 betterbom.py /usr/bin/$bin --output sboms/$bin.spdx.json 2>/dev/null)
  syft=$(echo "$out" | grep "syft alone:" | awk '{print $3}')
  otool=$(echo "$out" | grep "otool alone:" | awk '{print $3}')
  strings=$(echo "$out" | grep "strings alone:" | awk '{print $3}')
  total=$(echo "$out" | grep "betterbom total:" | awk '{print $3}')
  echo "$bin,$syft,$otool,$strings,$total"
done

# curl-linux separately (not in /usr/bin/)
out=$(python3 betterbom.py ~/syft-research/curl-linux --output sboms/curl-linux.spdx.json 2>/dev/null)
syft=$(echo "$out" | grep "syft alone:" | awk '{print $3}')
otool=$(echo "$out" | grep "otool alone:" | awk '{print $3}')
strings=$(echo "$out" | grep "strings alone:" | awk '{print $3}')
total=$(echo "$out" | grep "betterbom total:" | awk '{print $3}')
echo "curl-linux,$syft,$otool,$strings,$total"