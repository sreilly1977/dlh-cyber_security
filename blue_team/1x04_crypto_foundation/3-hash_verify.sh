#!/bin/bash
#
# 3-hash_verify.sh
# MedDefense Health Systems - Cryptographic Foundation Project (1x04)
# Task 3: File Integrity Verification Tool
#
# Purpose: Compute SHA-256 hash of a file and compare against an expected value
#
# Usage: ./3-hash_verify.sh <file_path> <expected_sha256_hash>
#
# Exit codes:
#   0 - Integrity verified (hashes match)
#   1 - Integrity failed (hashes do not match)
#   2 - Invalid arguments
#   3 - File not found or not readable

set -euo pipefail

readonly SCRIPT_NAME="3-hash_verify.sh"

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <file_path> <expected_sha256_hash>

Arguments:
    file_path           Path to the file to verify
    expected_sha256     Expected SHA-256 hash (64 hex characters)

Examples:
    ${SCRIPT_NAME} patient_record.txt 8a3d7e2f1b9c4a6e8d2f0b4a6c8e2d0f1a3b5c7e9d1f3a5b7c9e1d3f5a7b9c1
    ${SCRIPT_NAME} backup.tar.gz ef2d8e3a1b...

Exit codes:
    0 - INTEGRITY OK
    1 - INTEGRITY FAILED
    2 - Invalid arguments
    3 - File not found
EOF
}

die() {
    local exit_code="$1"
    shift
    echo "[ERROR] $*" >&2
    exit "${exit_code}"
}

# ---------------------------------------------------------------------------
# Validate arguments
# ---------------------------------------------------------------------------
if [[ $# -ne 2 ]]; then
    usage
    die 2 "Exactly 2 arguments required (file_path and expected_hash), got $#."
fi

FILE_PATH="$1"
EXPECTED_HASH="$2"

# ---------------------------------------------------------------------------
# Validate file exists and is readable
# ---------------------------------------------------------------------------
if [[ ! -f "${FILE_PATH}" ]]; then
    die 3 "File not found: ${FILE_PATH}"
fi

if [[ ! -r "${FILE_PATH}" ]]; then
    die 3 "File is not readable: ${FILE_PATH}"
fi

# ---------------------------------------------------------------------------
# Validate expected hash format (64 hex characters)
# ---------------------------------------------------------------------------
EXPECTED_HASH_LOWER=$(echo "${EXPECTED_HASH}" | tr '[:upper:]' '[:lower:]')

if [[ ! "${EXPECTED_HASH_LOWER}" =~ ^[a-f0-9]{64}$ ]]; then
    die 2 "Expected hash must be 64 hexadecimal characters. Received: ${EXPECTED_HASH}"
fi

# ---------------------------------------------------------------------------
# Compute SHA-256 hash of the file
# ---------------------------------------------------------------------------
COMPUTED_HASH=$(sha256sum "${FILE_PATH}" | awk '{print $1}')

echo "File:       ${FILE_PATH}"
echo "Expected:   ${EXPECTED_HASH_LOWER}"
echo "Computed:   ${COMPUTED_HASH}"
echo ""

# ---------------------------------------------------------------------------
# Compare hashes
# ---------------------------------------------------------------------------
if [[ "${COMPUTED_HASH}" == "${EXPECTED_HASH_LOWER}" ]]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected ${EXPECTED_HASH_LOWER} got ${COMPUTED_HASH}"
    exit 1
fi
