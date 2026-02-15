#!/bin/sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_ROOT="$SCRIPT_DIR"

PROTO_DIRS="
spotify_dl_cli/clt_extended_metadata
spotify_dl_cli/clt_playlist
spotify_dl_cli/clt_playplay
spotify_dl_cli/clt_storage_resolve
"

PROTO_FILES=$(find $PROTO_DIRS -type f -name "*.proto")

if [ -z "$PROTO_FILES" ]; then
  echo "No .proto files found" >&2
  exit 1
fi

protoc \
  -I "$PROTO_ROOT" \
  --python_out="." \
  --pyi_out="." \
  $PROTO_FILES
