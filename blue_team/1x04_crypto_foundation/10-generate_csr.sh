#!/bin/bash
# 10-generate_csr.sh
# MedDefense Health Systems - Cryptographic Foundations Project (1x04)
# Task 10: CSR Generation Automation
# Purpose: Automate the key generation and CSR creation process
# for the MedDefense patient portal certificate renewal
# Usage: ./10-generate_csr.sh [output_directory]
# Defaults to current directory if output_directory not specified
# Exit codes:
# 0 - Success
# 1 - OpenSSL command failed
# 2 - Invalid arguments
# 3 - Output directory not writable

set -euo pipefail

readonly SCRIPT_NAME="10-generate_csr.sh"
readonly KEY_ALGORITHM="rsa"
readonly KEY_SIZE="2048"
readonly HASH_ALGORITHM="sha256"

# Certificate subject details
readonly CERT_C="US"
readonly CERT_ST="California"
readonly CERT_L="San Francisco"
readonly CERT_O="MedDefense Health Systems"
readonly CERT_OU="Information Technology"
readonly CERT_CN="portal.meddefense.local"

# Subject Alternative Names
readonly SAN_DNS_1="portal.meddefense.local"
readonly SAN_DNS_2="patient.meddefense.local"
readonly SAN_DNS_3="www.portal.meddefense.local"
readonly SAN_DNS_4="api.meddefense.local"

# File names
readonly KEY_FILE="portal_key.pem"
readonly CSR_FILE="portal.csr"
readonly CONFIG_FILE="openssl_csr.cnf"

#---------------------------------------------------------------------------
# Functions
#---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [output_directory]

Generates an RSA-2048 private key and Certificate Signing Request for the MedDefense patient portal certificate renewal.

Arguments:
  output_directory    Directory to save key, CSR, and config files (defaults to current directory)

Output files:
  ${KEY_FILE}         RSA-2048 private key (permissions: 600)
  ${CSR_FILE}         Certificate Signing Request
  ${CONFIG_FILE}      OpenSSL configuration file used for CSR generation

Exit codes:
  0 - Success
  1 - OpenSSL command failed
  2 - Invalid arguments
  3 - Output directory not writable

Example:
  ${SCRIPT_NAME} /home/steve/projects/cert
  ${SCRIPT_NAME}
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

log_success() {
    echo "[OK] $*" >&2
}

#---------------------------------------------------------------------------
# Validate arguments
#---------------------------------------------------------------------------

OUTPUT_DIR="."

if [[ $# -gt 1 ]]; then
    usage
    die 2 "Too many arguments. Expected 0 or 1 (output directory), got $#."
fi

if [[ $# -eq 1 ]]; then
    OUTPUT_DIR="$1"
fi

# Normalize path and verify directory exists
OUTPUT_DIR="${OUTPUT_DIR%/}"

if [[ ! -d "${OUTPUT_DIR}" ]]; then
    die 3 "Output directory does not exist: ${OUTPUT_DIR}"
fi

if [[ ! -w "${OUTPUT_DIR}" ]]; then
    die 3 "Output directory is not writable: ${OUTPUT_DIR}"
fi

# Set full file paths
KEY_PATH="${OUTPUT_DIR}/${KEY_FILE}"
CSR_PATH="${OUTPUT_DIR}/${CSR_FILE}"
CONFIG_PATH="${OUTPUT_DIR}/${CONFIG_FILE}"

log_info "Output directory: ${OUTPUT_DIR}"
log_info "Algorithm: ${KEY_ALGORITHM}-${KEY_SIZE}"
log_info "Hash: ${HASH_ALGORITHM}"
log_info ""

#---------------------------------------------------------------------------
# Step 1: Generate the OpenSSL configuration file
#---------------------------------------------------------------------------

log_info "Step 1/3: Generating OpenSSL configuration file..."

cat > "${CONFIG_PATH}" <<EOF
[req]
default_bits = ${KEY_SIZE}
default_md = ${HASH_ALGORITHM}
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
C = ${CERT_C}
ST = ${CERT_ST}
L = ${CERT_L}
O = ${CERT_O}
OU = ${CERT_OU}
CN = ${CERT_CN}

[req_ext]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = ${SAN_DNS_1}
DNS.2 = ${SAN_DNS_2}
DNS.3 = ${SAN_DNS_3}
DNS.4 = ${SAN_DNS_4}
EOF

log_success "Configuration file created: ${CONFIG_PATH}"

#---------------------------------------------------------------------------
# Step 2: Generate the RSA-2048 private key
#---------------------------------------------------------------------------

log_info "Step 2/3: Generating RSA-${KEY_SIZE} private key..."

if openssl genrsa -out "${KEY_PATH}" "${KEY_SIZE}" 2>&1; then
    chmod 600 "${KEY_PATH}"
    log_success "Private key created: ${KEY_PATH} (permissions: 600)"
else
    die 1 "Failed to generate private key"
fi

# Verify the key
log_info "Key verification:"
openssl rsa -in "${KEY_PATH}" -text -noout 2>&1 | head -3

#---------------------------------------------------------------------------
# Step 3: Generate the Certificate Signing Request
#---------------------------------------------------------------------------

log_info "Step 3/3: Generating Certificate Signing Request..."

if openssl req -new -key "${KEY_PATH}" -out "${CSR_PATH}" -config "${CONFIG_PATH}" 2>&1; then
    log_success "CSR created: ${CSR_PATH}"
else
    die 1 "Failed to generate CSR"
fi

#---------------------------------------------------------------------------
# Verify the CSR
#---------------------------------------------------------------------------

log_info "CSR verification:"
openssl req -in "${CSR_PATH}" -text -noout 2>&1 | head -15

#---------------------------------------------------------------------------
# Summary
#---------------------------------------------------------------------------

log_success ""
log_success "=== CSR Generation Complete ==="
log_success "Private Key: ${KEY_PATH}"
log_success "CSR: ${CSR_PATH}"
log_success "Config: ${CONFIG_PATH}"
log_success ""
log_info "Next steps:"
log_info "  1. Submit ${CSR_FILE} to your Certificate Authority"
log_info "  2. Wait for certificate issuance"
log_info "  3. Install the signed certificate on your web server"
log_info "  4. Install on web-srv-01"
log_info "  5. Verify with: openssl s_client -connect portal.meddefense.local:443"
log_info ""
log_info "IMPORTANT: Store ${KEY_PATH} securely. Do NOT commit to version control."
