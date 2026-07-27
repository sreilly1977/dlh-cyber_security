#!/bin/bash
# 12-luks_manager.sh
# MedDefense Health Systems - Cryptographic Foundation Project (1x04)
# Task 12: LUKS Volume Manager Script
# Purpose: Automate the creation, opening, and closing of LUKS-encrypted volumes
# Usage:
# ./12-luks_manager.sh create <volume_path> <size_mb>
# ./12-luks_manager.sh open <volume_path> <mount_point>
# ./12-luks_manager.sh close <volume_path> <mount_point>
# Exit codes:
# 0 - Success
# 1 - Operation failed
# 2 - Invalid arguments
# 3 - Permission denied (not root)
# 4 - Volume already exists/open
# 5 - Volume does not exist/closed

set -euo pipefail

readonly SCRIPT_NAME="12-luks_manager.sh"
readonly MAPPER_PREFIX="secure_"

#---------------------------------------------------------------------------
# Functions
#---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <mode> [arguments]

Modes:
  create <volume_path> <size_mb>    Creates a LUKS-encrypted volume of specified size in MB
  open <volume_path> <mount_point>  Opens the LUKS volume and mounts it
  close <volume_path> <mount_point> Unmounts and closes the LUKS volume

Examples:
  ${SCRIPT_NAME} create /path/to/volume.img 500
  ${SCRIPT_NAME} open /path/to/volume.img /mnt/myvol
  ${SCRIPT_NAME} close /path/to/volume.img /mnt/myvol

Requirements:
  - Root privileges required (sudo)
  - cryptsetup package installed
  - For 'create': dd and mkfs.ext4 utilities

Exit codes:
  0 - Success
  1 - Operation failed
  2 - Invalid arguments
  3 - Permission denied
  4 - Volume already exists/open
  5 - Volume does not exist/closed
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
# Check root privileges
#---------------------------------------------------------------------------

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die 3 "Root privileges required. Run with: sudo ${SCRIPT_NAME} ..."
fi

#---------------------------------------------------------------------------
# Validate arguments
#---------------------------------------------------------------------------

if [[ $# -lt 1 ]]; then
    usage
    die 2 "Mode argument required: create, open, or close"
fi

MODE="$1"
shift

case "${MODE}" in
create)
    if [[ $# -ne 2 ]]; then
        usage
        die 2 "create requires: <volume_path> <size_mb>"
    fi

    VOLUME_PATH="$1"
    SIZE_MB="$2"

    # Validate size is numeric
    if ! [[ "${SIZE_MB}" =~ ^[0-9]+$ ]]; then
        die 2 "Size must be a positive integer in MB. Got: ${SIZE_MB}"
    fi

    # Check if volume already exists
    if [[ -f "${VOLUME_PATH}" ]]; then
        die 4 "Volume already exists: ${VOLUME_PATH}"
    fi

    # Get volume name from path
    VOLUME_NAME=$(basename "${VOLUME_PATH}" .img)

    log_info "Creating ${SIZE_MB}MB virtual disk at ${VOLUME_PATH}..."

    # Step 1: Create the raw file
    dd if=/dev/zero of="${VOLUME_PATH}" bs=1M count="${SIZE_MB}" 2>&1 || die 1 "Failed to create disk file"
    log_info "Disk file created: $(ls -lh "${VOLUME_PATH}")"

    # Step 2: Initialize LUKS header
    log_info "Initializing LUKS header..."
    log_info "You will be prompted to enter and verify a passphrase."
    cryptsetup luksFormat "${VOLUME_PATH}" || die 1 "Failed to format with LUKS"
    log_success "LUKS header initialized"

    # Step 3: Open the volume temporarily to create filesystem
    log_info "Opening volume temporarily to create filesystem..."
    cryptsetup luksOpen "${VOLUME_PATH}" "${VOLUME_NAME}" || die 1 "Failed to open volume"

    # Step 4: Create ext4 filesystem
    log_info "Creating ext4 filesystem..."
    mkfs.ext4 "/dev/mapper/${VOLUME_NAME}" || die 1 "Failed to create filesystem"
    log_success "Filesystem created"

    # Step 5: Close the volume
    cryptsetup luksClose "${VOLUME_NAME}" || die 1 "Failed to close volume"
    log_success "Volume closed"

    # Summary
    log_info ""
    log_success "=== Volume Created Successfully ==="
    log_info "Volume path: ${VOLUME_PATH}"
    log_info "Volume name: ${VOLUME_NAME}"
    log_info "Size: ${SIZE_MB}MB"
    log_info ""
    log_info "Next steps:"
    log_info "  To open:  sudo ${SCRIPT_NAME} open ${VOLUME_PATH} /mnt/${VOLUME_NAME}"
    log_info "  To close: sudo ${SCRIPT_NAME} close ${VOLUME_PATH} /mnt/${VOLUME_NAME}"
    log_info ""
    log_info "IMPORTANT: Memorize your passphrase. There is no recovery!"
    exit 0
    ;;

open)
    if [[ $# -ne 2 ]]; then
        usage
        die 2 "open requires: <volume_path> <mount_point>"
    fi

    VOLUME_PATH="$1"
    MOUNT_POINT="$2"

    # Check if volume exists
    if [[ ! -f "${VOLUME_PATH}" ]]; then
        die 5 "Volume file not found: ${VOLUME_PATH}"
    fi

    # Get volume name from path
    VOLUME_NAME=$(basename "${VOLUME_PATH}" .img)

    # Check if already open
    if cryptsetup status "${VOLUME_NAME}" &>/dev/null; then
        die 4 "Volume already open: ${VOLUME_NAME}"
    fi

    # Create mount point if it doesn't exist
    if [[ ! -d "${MOUNT_POINT}" ]]; then
        log_info "Creating mount point: ${MOUNT_POINT}"
        mkdir -p "${MOUNT_POINT}"
    fi

    log_info "Opening LUKS volume..."
    log_info "You will be prompted to enter the passphrase."
    cryptsetup luksOpen "${VOLUME_PATH}" "${VOLUME_NAME}" || die 1 "Failed to open volume"
    log_success "Volume opened"

    # Mount the filesystem
    log_info "Mounting at ${MOUNT_POINT}..."
    mount "/dev/mapper/${VOLUME_NAME}" "${MOUNT_POINT}" || die 1 "Failed to mount volume"
    log_success "Volume mounted"

    # Show mount info
    df -h "${MOUNT_POINT}"
    log_success "Ready to use"
    exit 0
    ;;

close)
    if [[ $# -ne 2 ]]; then
        usage
        die 2 "close requires: <volume_path> <mount_point>"
    fi

    VOLUME_PATH="$1"
    MOUNT_POINT="$2"

    # Get volume name from path
    VOLUME_NAME=$(basename "${VOLUME_PATH}" .img)

    # Check if volume exists
    if [[ ! -f "${VOLUME_PATH}" ]]; then
        die 5 "Volume file not found: ${VOLUME_PATH}"
    fi

    # Check if volume is closed
    if ! cryptsetup status "${VOLUME_NAME}" &>/dev/null; then
        log_info "Volume already closed: ${VOLUME_NAME}"
        exit 0
    fi

    # Check if mounted
    if mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
        log_info "Unmounting ${MOUNT_POINT}..."
        umount "${MOUNT_POINT}" || die 1 "Failed to unmount volume"
        log_success "Volume unmounted"
    else
        log_info "Volume was not mounted"
    fi

    # Close the LUKS mapping
    log_info "Closing LUKS volume..."
    cryptsetup luksClose "${VOLUME_NAME}" || die 1 "Failed to close volume"
    log_success "Volume closed"
    log_success "Data is now encrypted at rest"
    exit 0
    ;;

*)
    usage
    die 2 "Unknown mode: ${MODE}. Use 'create', 'open', or 'close'"
    ;;
esac
