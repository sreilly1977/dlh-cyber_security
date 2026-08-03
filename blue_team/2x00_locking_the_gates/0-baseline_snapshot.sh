#!/bin/bash
#===============================================================================
# 0-baseline_snapshot.sh - Security Baseline Snapshot
# Usage: sudo ./0-baseline_snapshot.sh
#===============================================================================

# Get OS info
source /etc/os-release 2>/dev/null || PRETTY_NAME="Unknown"

# Count running services
SERVICE_COUNT=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l)

# Count open ports
PORT_COUNT=$(ss -tuln 2>/dev/null | grep -c LISTEN) || PORT_COUNT=0

# Count SUID binaries
SUID_COUNT=$(find / -type f -perm -4000 2>/dev/null | wc -l)

# Count SGID binaries
SGID_COUNT=$(find / -type f -perm -2000 2>/dev/null | wc -l)

# Count world-writable files (excluding proc, sys, dev)
WW_COUNT=$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune \
  -o -type f -perm -0002 -print 2>/dev/null | wc -l)

echo "Hostname: $(hostname)"
echo "OS: $PRETTY_NAME"
echo "Running services: $SERVICE_COUNT"
echo "Open ports: $PORT_COUNT"
echo "SUID binaries: $SUID_COUNT"
echo "SGID binaries: $SGID_COUNT"
echo "World-writable files: $WW_COUNT"
