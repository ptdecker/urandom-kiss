#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "Running CI checks from project root: $PROJECT_ROOT"
echo

echo "==> Applying rustfmt..."
cargo fmt --all

echo "==> Running Clippy with all features..."
cargo clippy --all-features -- -D warnings

echo "==> Running tests..."
cargo test --all-features --verbose

echo "==> Building docs..."
cargo doc --all-features --no-deps

echo
echo "All local CI checks passed."
