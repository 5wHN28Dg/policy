#!/usr/bin/env bash
# Download a release binary, check its SHA-256, and put it on PATH (DEP-7: pinned and verified).
# Usage: fetch-tool.sh <name> <url> <sha256> [<path inside tar.gz>]
set -euo pipefail
name=$1 url=$2 sha=$3 member=${4:-}
dir="${RUNNER_TEMP:-/tmp}/policy-tools"
mkdir -p "$dir"
file="$dir/$(basename "$url")"
curl -fsSL --retry 3 -o "$file" "$url"
if ! echo "$sha  $file" | sha256sum -c --quiet -; then
  rm -f "$file"
  echo "::error::$name: checksum mismatch for $url" >&2
  exit 1
fi
if [[ -n $member ]]; then
  unpack=$(mktemp -d "$dir/unpack.XXXXXX")
  tar -xzf "$file" -C "$unpack" "$member"
  mv "$unpack/$member" "$dir/$name"
  rm -rf "$unpack" "$file"
elif [[ $file != "$dir/$name" ]]; then
  mv "$file" "$dir/$name"
fi
chmod +x "$dir/$name"
echo "$dir" >> "${GITHUB_PATH:-/dev/null}"
echo "$name: $("$dir/$name" --version 2>&1 | head -1)"
