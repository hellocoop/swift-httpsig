#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SWIFT_PKG_DIR="$(dirname "$SCRIPT_DIR")"
TMP_DIR=$(mktemp -d)

trap "rm -rf $TMP_DIR" EXIT

echo "=== Cross-Library HTTP Message Signatures Test ==="
echo ""

# Build Swift CrossTest tool
echo "Building Swift CrossTest..."
cd "$SWIFT_PKG_DIR"
swift build --product CrossTest 2>&1 | tail -1
echo ""

# Step 1: TypeScript signs → Swift verifies
echo "--- TypeScript → Swift ---"
echo "Generating test vectors with TypeScript..."
node "$SCRIPT_DIR/generate-ts.mjs" "$TMP_DIR/ts-vectors.json"
echo ""
echo "Verifying with Swift..."
swift run CrossTest verify "$TMP_DIR/ts-vectors.json"
echo ""

# Step 2: Swift signs → TypeScript verifies
echo "--- Swift → TypeScript ---"
echo "Generating test vectors with Swift..."
swift run CrossTest generate "$TMP_DIR/swift-vectors.json"
echo ""
echo "Verifying with TypeScript..."
node "$SCRIPT_DIR/verify-ts.mjs" "$TMP_DIR/swift-vectors.json"
echo ""

echo "=== All cross-library tests passed! ==="
