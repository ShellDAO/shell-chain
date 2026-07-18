#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE="${1:-$ROOT_DIR/Dockerfile}"

images=$(awk '
    toupper($1) == "FROM" {
        for (i = 2; i <= NF; i++) {
            if ($i !~ /^--/) {
                print $i
                break
            }
        }
    }
' "$DOCKERFILE")

if [ -z "$images" ]; then
    echo "Dockerfile base pin check failed: no base images found" >&2
    exit 1
fi

while IFS= read -r image; do
    if [[ ! "$image" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "Dockerfile base pin check failed: '$image' is not pinned by digest" >&2
        exit 1
    fi
done <<< "$images"

echo "Dockerfile base images are pinned by digest"
