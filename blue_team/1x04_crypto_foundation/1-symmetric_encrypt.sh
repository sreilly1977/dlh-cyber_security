#!/bin/bash
#
# 1-symmetric_encrypt.sh
# MedDefense Health Systems - Cryptographic Foundation Project (1x04)
# Task 1: Symmetric Encryption Utility
#
# Purpose: Encrypt a file using AES-256 in CBC or GCM mode
#
# Usage: ./1-symmetric_encrypt.sh <input_file> <output_file> <mode>
#   mode: cbc | gcm
#
# Exit codes:
#   0 - Success
#   1 - Invalid arguments
#   2 - Input file not found
#   3 - Unsupported mode
#   4 - Encryption failed
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly SCRIPT_NAME="1-symmetric_encrypt.sh"
readonly KEY_DERIVATION="pbkdf2"
readonly ITERATIONS=100000
readonly CIPHER_BASE="aes-256"

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <input_file> <output_file> <mode>

Arguments:
    input_file    Path to the file to encrypt
    output_file   Path for the encrypted output
    mode          Encryption mode: cbc or gcm

Examples:
    ${SCRIPT_NAME} patient_record.txt encrypted.enc cbc
    ${SCRIPT_NAME} backup.sql backup.enc gcm

Note:
    You will be prompted for a password. Use a strong passphrase (20+ characters).
    The script uses PBKDF2 key derivation with ${ITERATIONS} iterations.
EOF
}

log() {
    local level="$1"
    shift
    echo "[${level}] $*" >&2
}

die() {
    local exit_code="$1"
    shift
    log "ERROR" "$*"
    exit "${exit_code}"
}

# ---------------------------------------------------------------------------
# Validate arguments
# ---------------------------------------------------------------------------
if [[ $# -ne 3 ]]; then
    usage
    die 1 "Exactly 3 arguments required, got $#."
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"
MODE_ARG="$3"

# Normalize mode argument to lowercase
MODE=$(echo "${MODE_ARG}" | tr '[:upper:]' '[:lower:]')

# ---------------------------------------------------------------------------
# Validate input file
# ---------------------------------------------------------------------------
if [[ ! -f "${INPUT_FILE}" ]]; then
    die 2 "Input file not found: ${INPUT_FILE}"
fi

if [[ ! -r "${INPUT_FILE}" ]]; then
    die 2 "Input file is not readable: ${INPUT_FILE}"
fi

# ---------------------------------------------------------------------------
# Validate mode
# ---------------------------------------------------------------------------
case "${MODE}" in
    cbc)
        CIPHER="${CIPHER_BASE}-cbc"
        ;;
    gcm)
        CIPHER="${CIPHER_BASE}-gcm"
        ;;
    *)
        usage
        die 3 "Unsupported mode '${MODE_ARG}'. Use 'cbc' or 'gcm'."
        ;;
esac

# ---------------------------------------------------------------------------
# Check OpenSSL availability
# ---------------------------------------------------------------------------
if ! command -v openssl &>/dev/null; then
    die 4 "OpenSSL is not installed or not in PATH."
fi

OPENSSL_VERSION=$(openssl version 2>/dev/null)
log "INFO" "Using ${OPENSSL_VERSION}"

# ---------------------------------------------------------------------------
# Display encryption parameters
# ---------------------------------------------------------------------------
log "INFO" "Encryption Parameters:"
log "INFO" "  Input file:    ${INPUT_FILE} ($(du -h "${INPUT_FILE}" | cut -f1))"
log "INFO" "  Output file:   ${OUTPUT_FILE}"
log "INFO" "  Cipher:        ${CIPHER}"
log "INFO" "  Key derivation: ${KEY_DERIVATION} (${ITERATIONS} iterations)"
log "INFO" ""

# ---------------------------------------------------------------------------
# Perform encryption
# ---------------------------------------------------------------------------
log "INFO" "Starting encryption..."

START_TIME=$(date +%s%N)

if openssl enc -"${CIPHER}" -salt -${KEY_DERIVATION} -iter ${ITERATIONS} \
    -in "${INPUT_FILE}" \
    -out "${OUTPUT_FILE}" \
    -pass stdin <<< "$(read -s -p 'Enter encryption password: ' PASS; echo "$PASS")"; then

    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

    log "INFO" ""
    log "INFO" "Encryption completed successfully."
    log "INFO" "  Elapsed time: ${ELAPSED_MS} ms"
    log "INFO" "  Output size: $(du -h "${OUTPUT_FILE}" | cut -f1)"
    log "INFO" ""
    log "INFO" "To decrypt, run:"
    log "INFO" "  openssl enc -d -${CIPHER} -${KEY_DERIVATION} -iter ${ITERATIONS} -in ${OUTPUT_FILE} -out decrypted.txt"
else
    die 4 "Encryption failed. Check OpenSSL error output above."
fi

exit 0
