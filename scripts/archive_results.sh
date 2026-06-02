#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LABEL="${1:-experiment_artifacts}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_DIR="runpod_artifacts/archives"
ARCHIVE_PATH="$ARCHIVE_DIR/${LABEL}_${TIMESTAMP}.tar.gz"

mkdir -p "$ARCHIVE_DIR"

INCLUDE_PATHS=(
  "results"
  "reports"
  "configs"
  "manifests"
  "datasets/splits"
)

EXISTING_PATHS=()
for path in "${INCLUDE_PATHS[@]}"; do
  if [ -e "$path" ]; then
    EXISTING_PATHS+=("$path")
  fi
done

if [ "${#EXISTING_PATHS[@]}" -eq 0 ]; then
  echo "No artifact paths exist to archive." >&2
  exit 1
fi

tar -czf "$ARCHIVE_PATH" "${EXISTING_PATHS[@]}"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARCHIVE_PATH" > "$ARCHIVE_PATH.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$ARCHIVE_PATH" > "$ARCHIVE_PATH.sha256"
else
  echo "Warning: no SHA256 command found; checksum not written." >&2
fi

echo "Created archive: $ARCHIVE_PATH"
if [ -f "$ARCHIVE_PATH.sha256" ]; then
  echo "Created checksum: $ARCHIVE_PATH.sha256"
fi
