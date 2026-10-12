#!/usr/bin/env bash
# Initialize the evidence store for IR-2026-0414-01.
# Run once before executing the Task 2 preservation runbook.
# Creates a tamper-obvious directory tree and seeds an empty hashes.txt.
set -euo pipefail

INCIDENT_ID="IR-2026-0414-01"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/evidence}"
INCIDENT_DIR="${EVIDENCE_ROOT}/${INCIDENCE_ID:-${INCIDENT_ID}}"

if [[ ! -d "${EVIDENCE_ROOT}" ]]; then
  echo "[init] creating evidence root at ${EVIDENCE_ROOT}"
  sudo mkdir -p "${EVIDENCE_ROOT}"
  sudo chown "$(whoami)":"$(whoami)" "${EVIDENCE_ROOT}"
  sudo chmod 750 "${EVIDENCE_ROOT}"
fi

if [[ -d "${INCIDENT_DIR}" ]]; then
  echo "[init] refusing to re-initialize an existing evidence directory: ${INCIDENT_DIR}"
  echo "[init] aborting to avoid clobbering chain of custody"
  exit 1
fi

mkdir -p "${INCIDENT_DIR}"/{memory,disk,process_tree,network,endpoint_telemetry,siem,proxy_dns,authentication,malware,correlation}
touch "${INCIDENT_DIR}/hashes.txt"

printf '# Chain of custody hash manifest\n# Incident: %s\n# Algorithm: SHA-256\n# Format: <sha256>  <relative_path>\n# Initialized: %s by %s on %s\n' \
  "${INCIDENT_ID}" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$(whoami)" \
  "$(hostname)" \
  >> "${INCIDENT_DIR}/hashes.txt"

chmod -R 750 "${INCIDENT_DIR}"

echo "[init] evidence tree created at ${INCIDENT_DIR}"
echo "[init] next step: execute the preservation runbook in order"
