#!/usr/bin/env bash
set -euo pipefail
if (( $# != 5 )); then
  echo 'usage: package-ui.sh WEB_EXTENSION_TOOL OUTPUT SEQUENCE EXPIRES_UNIX SECRET_HEX_FILE' >&2
  exit 2
fi
repository=$(cd -- "$(dirname -- "$0")/.." && pwd)
output_parent=$(dirname -- "$2")
mkdir -p -- "$output_parent"
assets=$(mktemp -d "$output_parent/.ui-assets.XXXXXX")
trap 'rm -rf -- "$assets"' EXIT
cp -- "$repository/ui/settings.js" "$assets/settings.js"
"$1" pack "$assets" "$2" frame-limiter "Frame limiting" settings.js "$3" "$4" "$5" "$repository/ui/ui.json"
