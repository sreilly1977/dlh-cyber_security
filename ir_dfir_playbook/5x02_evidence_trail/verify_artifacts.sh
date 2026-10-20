#!/bin/bash
#
# Name: verify_artifacts.sh
# Purpose: Establish and verify the SHA-256 cryptographic baseline for the three case
#          artifacts (ART-001 wst-ws-031.dd, ART-002 wst-ws-031.mem, ART-003 wst-ws-017.mem)
#          before any analysis session begins, under litigation hold LH-2026-0414-01.
#          First run: detects that hashes.txt is absent, computes all three hashes, writes
#          hashes.txt, reports BASELINE_SET for each artifact, and exits 0.
#          Later runs: recomputes each hash, compares against the stored baseline, prints
#          [PASS]/[FAIL] with expected and computed values, appends a verification event to
#          verification_log.txt, and exits non-zero on any failure.
#          The script opens artifacts read-only and never modifies them.
# Author: Steve - Cybersecurity Engineer
# Date: 20 October 2026
#
# Usage: ./verify_artifacts.sh [-d <artifact_dir>] [-b <hashes_file>] [-l <log_file>] [-a <actor>] [-h]
#
# Exit codes:
#   0  all artifacts verified, or baseline successfully established
#   1  one or more artifacts failed verification (do not begin analysis)
#   2  usage or environment error (bad arguments, artifact directory or file unavailable)

set -o errexit
set -o nounset
set -o pipefail

readonly SCRIPT_NAME="verify_artifacts.sh"
readonly CASE_ID="LH-2026-0414-01"
readonly INCIDENT_ID="IR-2026-0414-01"

# Defaults (override with flags below)
ART_DIR="./5x02/evidence"
HASH_FILE="hashes.txt"
LOG_FILE="verification_log.txt"
ACTOR="Steve - Cybersecurity Engineer"

usage() {
    echo "Usage: ${SCRIPT_NAME} [-d <artifact_dir>] [-b <hashes_file>] [-l <log_file>] [-a <actor>]" >&2
    echo "" >&2
    echo "Options:" >&2
    echo "  -d <dir>    Directory containing the three artifacts (default: ${ART_DIR})" >&2
    echo "  -b <file>   Baseline hash file (default: ${HASH_FILE})" >&2
    echo "  -l <file>   Append-only verification log (default: ${LOG_FILE})" >&2
    echo "  -a <name>   Actor recorded in the log (default: ${ACTOR})" >&2
    echo "  -h          Show this help and exit" >&2
}

while getopts ":d:b:l:a:h" opt; do
    case "${opt}" in
        d) ART_DIR="${OPTARG}" ;;
        b) HASH_FILE="${OPTARG}" ;;
        l) LOG_FILE="${OPTARG}" ;;
        a) ACTOR="${OPTARG}" ;;
        h) usage; exit 0 ;;
        :) echo "Option -${OPTARG} requires an argument." >&2; usage; exit 2 ;;
        *) echo "Unknown option: -${OPTARG}" >&2; usage; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

# Artifact registry: ART-ID|filename
readonly ART_001="ART-001|wst-ws-031.dd"
readonly ART_002="ART-002|wst-ws-031.mem"
readonly ART_003="ART-003|wst-ws-017.mem"
readonly ARTIFACTS=("${ART_001}" "${ART_002}" "${ART_003}")

utc_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

append_log() {
    # append-only verification event; each field separated by " | "
    printf '%s | %s | %s | %s | %s | %s | %s\n' \
        "$(utc_now)" "${CASE_ID}" "$1" "$2" "$3" "$4" "$5" >>"${LOG_FILE}"
}

die_env() {
    echo "[ERROR] $1" >&2
    exit 2
}

# --- Pre-flight checks -----------------------------------------------------

command -v sha256sum >/dev/null 2>&1 || die_env "sha256sum not found in PATH."

[[ -d "${ART_DIR}" ]] || die_env "Artifact directory not found: ${ART_DIR}"

for entry in "${ARTIFACTS[@]}"; do
    file="${ART_DIR}/${entry#*|}"
    [[ -f "${file}" ]] || die_env "Artifact file not found: ${file}"
    [[ -r "${file}" ]] || die_env "Artifact file not readable: ${file}"
done

# --- Mode selection ---------------------------------------------------------

if [[ ! -f "${HASH_FILE}" ]]; then
    # =========================================================================
    # FIRST RUN: baseline establishment
    # =========================================================================
    echo "No baseline found (${HASH_FILE}). Establishing baseline..."

    tmp_hash="$(mktemp)"
    trap 'rm -f "${tmp_hash}"' EXIT

    for entry in "${ARTIFACTS[@]}"; do
        art_id="${entry%%|*}"
        art_name="${entry#*|}"
        art_path="${ART_DIR}/${art_name}"
        computed="$(sha256sum "${art_path}" | awk '{print $1}')"

        # hashes.txt format: ART_ID filename sha256
        printf '%s %s %s\n' "${art_id}" "${art_name}" "${computed}" >>"${tmp_hash}"

        echo "[BASELINE_SET] ${art_id} ${art_name}  sha256=${computed}"

        append_log "${art_id}" "${art_name}" "BASELINE_SET" \
            "n/a (no prior baseline; acquisition-era hashes not computed)" "${computed}"
    done

    mv "${tmp_hash}" "${HASH_FILE}"
    trap - EXIT
    echo "Baseline written to ${HASH_FILE}. Run again to verify."
    echo "ALL ARTIFACTS BASELINED"
    exit 0
fi

# =========================================================================
# SUBSEQUENT RUN: verification against baseline
# =========================================================================

fail_count=0

for entry in "${ARTIFACTS[@]}"; do
    art_id="${entry%%|*}"
    art_name="${entry#*|}"
    art_path="${ART_DIR}/${art_name}"
    computed="$(sha256sum "${art_path}" | awk '{print $1}')"

    # Look up the baseline entry for this artifact
    baseline_line="$(grep -E "^${art_id}[[:space:]]" "${HASH_FILE}" || true)"

    if [[ -z "${baseline_line}" ]]; then
        echo "[FAIL] ${art_id} ${art_name}  expected=<no baseline entry in ${HASH_FILE}> computed=${computed}"
        append_log "${art_id}" "${art_name}" "FAIL" "<missing baseline entry>" "${computed}"
        fail_count=$((fail_count + 1))
        continue
    fi

    expected="$(echo "${baseline_line}" | awk '{print $3}')"

    if [[ "${computed}" == "${expected}" ]]; then
        echo "[PASS] ${art_id} ${art_name}  expected=${expected} computed=${computed}"
        append_log "${art_id}" "${art_name}" "PASS" "${expected}" "${computed}"
    else
        echo "[FAIL] ${art_id} ${art_name}  expected=${expected} computed=${computed}"
        append_log "${art_id}" "${art_name}" "FAIL" "${expected}" "${computed}"
        fail_count=$((fail_count + 1))
    fi
done

if [[ "${fail_count}" -eq 0 ]]; then
    echo "ALL ARTIFACTS VERIFIED"
    exit 0
else
    echo "VERIFICATION FAILED FOR ${fail_count} ARTIFACT(S) - DO NOT BEGIN ANALYSIS" >&2
    exit 1
fi
