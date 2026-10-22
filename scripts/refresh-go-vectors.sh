#!/bin/bash
# Regenerates the golden wire vectors from the Go reference repository.
#
# The Go implementation ships a dumper test that prints every wire format it
# encodes as "VECTOR <name> = <hex>" lines. This script runs that dumper
# against SSH3_GO_REPO (or the usual sibling checkouts) and rewrites
# ssh3-proto/tests/data/wire_vectors.txt. A diff in the committed file after
# this run means the Go reference changed its wire formats: update the Rust
# encoders/decoders and the tests before merging.
#
# Usage:
#   SSH3_GO_REPO=/path/to/ssh3-go ./scripts/refresh-go-vectors.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="$REPO_ROOT/ssh3-proto/tests/data/wire_vectors.txt"

if [ -z "${SSH3_GO_REPO:-}" ]; then
  echo "error: SSH3_GO_REPO is not set; point it at a checkout of nagual2/ssh3-go" >&2
  exit 1
fi

if [ ! -f "$SSH3_GO_REPO/go.mod" ]; then
  echo "error: SSH3_GO_REPO=$SSH3_GO_REPO is not the Go repository (no go.mod)" >&2
  exit 1
fi

echo "regenerating golden vectors from $SSH3_GO_REPO ..."
(cd "$SSH3_GO_REPO" && go test -run TestDumpWireVectors -v ./) \
  | grep '^VECTOR ' > "$TARGET.tmp"

if [ ! -s "$TARGET.tmp" ]; then
  echo "error: the Go dumper produced no vectors" >&2
  rm -f "$TARGET.tmp"
  exit 1
fi

mv "$TARGET.tmp" "$TARGET"
count=$(grep -c '^VECTOR ' "$TARGET")
echo "wrote $count vectors to $TARGET"
echo "review the diff and update the Rust encoders before committing:"
echo "  git diff -- $REPO_ROOT/ssh3-proto/tests/data/wire_vectors.txt"
