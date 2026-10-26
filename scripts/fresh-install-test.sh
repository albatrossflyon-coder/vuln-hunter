#!/usr/bin/env bash
# scripts/fresh-install-test.sh
# Verifies that vuln-hunter can install and scan from a clean clone.
# Clones to a temporary directory, creates a venv, installs requirements,
# runs a test scan, and exits non-zero on any failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vh-fresh-install-XXXXXX")"
echo "=== Fresh Install Test ==="
echo "Temporary directory: $TEMP_DIR"

cleanup() {
    echo "Cleaning up temporary directory: $TEMP_DIR"
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "--- Step 1: Cloning repository into clean directory ---"
git clone "$REPO_DIR" "$TEMP_DIR/clone"
cd "$TEMP_DIR/clone"

echo "--- Step 2: Creating virtual environment ---"
VENV_PATH="$TEMP_DIR/venv"
if command -v uv >/dev/null 2>&1; then
    uv venv --seed "$VENV_PATH"
elif python3 -m venv "$VENV_PATH" 2>/dev/null; then
    :
elif command -v virtualenv >/dev/null 2>&1; then
    virtualenv "$VENV_PATH"
else
    echo "ERROR: No supported tool found to create venv (uv, python3 -m venv, or virtualenv)." >&2
    exit 1
fi

source "$VENV_PATH/bin/activate"

echo "--- Step 3: Installing backend requirements ---"
if command -v uv >/dev/null 2>&1; then
    uv pip install -r backend/requirements.txt
else
    pip install -r backend/requirements.txt
fi

echo "--- Step 4: Running test scan on backend/test_sample ---"
export HERDR_REVIEWER="${HERDR_REVIEWER:-1}"
unset ANTHROPIC_API_KEY OPENAI_API_KEY ZAI_API_KEY GROQ_API_KEY LANGFUSE_SECRET_KEY

SCAN_OUTPUT=$(python backend/cli.py scan backend/test_sample 2>&1)
echo "$SCAN_OUTPUT"

echo "--- Step 5: Validating scan output ---"
if ! echo "$SCAN_OUTPUT" | grep -q "finding(s)"; then
    echo "ERROR: Scan did not report findings as expected." >&2
    exit 1
fi

echo "=== Fresh Install Test PASSED ==="
