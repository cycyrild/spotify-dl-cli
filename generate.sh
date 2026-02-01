#!/bin/sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PROTO_DIR="$SCRIPT_DIR/proto"
OUT_DIR="$PROTO_DIR"

PROTO_FILES="
track.proto
storage-resolve.proto
playplay.proto
"

for PROTO in $PROTO_FILES; do
  protoc \
    -I "$PROTO_DIR" \
    --python_out="$OUT_DIR" \
    --pyi_out="$OUT_DIR" \
    "$PROTO_DIR/$PROTO"
done
