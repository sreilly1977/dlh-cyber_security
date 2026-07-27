#!/bin/bash
#
# 5-sign_verify.sh
# MedDefense Health Systems - Cryptographic Foundation Project (1x04)
# Task 5: Digital Signature Tool
#
# Purpose: Sign files with RSA-SHA256 or verify signatures
#
# Usage:
#   Sign:  ./5-sign_verify.sh sign <file_path> <private_key_path> [output_sig_path]
#   Verify: ./5-sign_verify.sh verify <file_path> <signature_path> <public_key_path>
#
# Exit codes:
#   0 - Success (verified or signed successfully)
#   1 - Verification failed
#   2 - Invalid arguments
#   3 - File not found
#   4 - OpenSSL operation failed

set -euo pipefail

SCRIPT_NAME=$(basename "$0")
SIGNATURE_ALGO="sha256"

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <mode> [arguments]

Modes:
    sign <file_path> <private_key_path> [output_sig_path]
        Sign a file with RSA private key using SHA-256
        Output: creates .sig file (or specified output path)

    verify <file_path> <signature_path> <public_key_path>
        Verify a file against its RSA-SHA256 signature

Examples:
    ${SCRIPT_NAME} sign prescription.txt rsa_private.pem prescription.sig
    ${SCRIPT_NAME} verify prescription.txt prescription.sig rsa_public.pem

Requirements:
    OpenSSL 1.1.1 or newer
    RSA private/public key pair
EOF
}

die() {
    local exit_code="$1"
    shift
    echo "[ERROR] $*" >&2
    exit "${exit_code}"
}

log_info() {
    echo "[INFO] $*" >&2
}

# ---------------------------------------------------------------------------
# Validate arguments
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    usage
    die 2 "Mode required: sign or verify"
fi

MODE="$1"
shift

case "${MODE}" in
    sign)
        if [[ $# -lt 2 ]]; then
            usage
            die 2 "sign requires: <file_path> <private_key_path>"
        fi

        FILE_PATH="$1"
        PRIVATE_KEY="$2"
        OUTPUT_SIG="${3:-${FILE_PATH}.sig}"

        # Validate inputs
        [[ -f "${PRIVATE_KEY}" ]] || die 3 "Private key not found: ${PRIVATE_KEY}"
        [[ -f "${FILE_PATH}" ]] || die 3 "File to sign not found: ${FILE_PATH}"
        [[ -r "${FILE_PATH}" ]] || die 3 "File to sign not readable: ${FILE_PATH}"

        log_info "Signing: ${FILE_PATH}"
        log_info "Using private key: ${PRIVATE_KEY}"
        log_info "Output signature: ${OUTPUT_SIG}"

        # Create signature
        if openssl dgst "-${SIGNATURE_ALGO}" \
            -sign "${PRIVATE_KEY}" \
            -out "${OUTPUT_SIG}" \
            "${FILE_PATH}"; then
            log_info "Signature created: ${OUTPUT_SIG}"
            echo "OK: Signature created successfully"
            exit 0
        else
            die 4 "Signing failed"
        fi
        ;;

    verify)
        if [[ $# -lt 3 ]]; then
            usage
            die 2 "verify requires: <file_path> <signature_path> <public_key_path>"
        fi

        FILE_PATH="$1"
        SIGNATURE_FILE="$2"
        PUBLIC_KEY="$3"

        # Validate inputs
        [[ -f "${PUBLIC_KEY}" ]] || die 3 "Public key not found: ${PUBLIC_KEY}"
        [[ -f "${FILE_PATH}" ]] || die 3 "Signed file not found: ${FILE_PATH}"
        [[ -f "${SIGNATURE_FILE}" ]] || die 3 "Signature file not found: ${SIGNATURE_FILE}"
        [[ -r "${FILE_PATH}" ]] || die 3 "Signed file not readable: ${FILE_PATH}"

        log_info "Verifying: ${FILE_PATH}"
        log_info "Using public key: ${PUBLIC_KEY}"
        log_info "Signature file: ${SIGNATURE_FILE}"

        # Verify signature
        if openssl dgst "-${SIGNATURE_ALGO}" \
            -verify "${PUBLIC_KEY}" \
            -signature "${SIGNATURE_FILE}" \
            "${FILE_PATH}" 2>&1 | grep -q "Verified OK"; then
            log_info "VERIFICATION PASSED"
            echo "OK: File integrity verified; signature authentic"
            exit 0
        else
            log_info "VERIFICATION FAILED"
            echo "FAILED: File may have been modified or signature invalid"
            exit 1
        fi
        ;;

    *)
        usage
        die 2 "Unknown mode: ${MODE}. Use 'sign' or 'verify'"
        ;;
esac
