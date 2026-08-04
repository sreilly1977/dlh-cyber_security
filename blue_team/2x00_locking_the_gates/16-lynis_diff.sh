#!/bin/bash

# 16-lynis_diff.sh — Compare pre and post-hardening Lynis results and produce
#                     a structured improvement report showing resolved, remaining,
#                     and new findings.
#
# Context:
#   - Sarah Park needs a report showing which findings disappeared, which remain,
#     and whether hardening introduced new issues
#   - Pre-hardening findings: lynis_findings.json (from Task 2)
#   - Post-hardening findings: lynis_post_findings.json (generated if missing)
#
# Usage:  sudo ./16-lynis_diff.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PRE_FINDINGS_FILE="lynis_findings.json"
POST_FINDINGS_FILE="lynis_post_findings.json"
OUTPUT_FILE="hardening_improvement.json"
LYNIS_BIN=$(which lynis 2>/dev/null || echo "/usr/sbin/lynis")
LYNIS_REPORT_DAT="/var/log/lynis-report.dat"
LYNIS_LOG_DIR="/var/log"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper: Run Lynis and generate post-hardening findings JSON
# ---------------------------------------------------------------------------

generate_post_findings() {
    echo "[*] Running Lynis to generate post-hardening findings..."

    if [[ ! -f "$LYNIS_BIN" ]]; then
        echo "    ERROR: Lynis not found at $LYNIS_BIN"
        echo "    Attempting to install..."
        apt-get update -qq 2>/dev/null && apt-get install -y lynis -qq 2>/dev/null || true
    fi

    if [[ -f "$LYNIS_BIN" ]]; then
        echo "    Running Lynis audit system..."
        "$LYNIS_BIN" audit system --quiet 2>/dev/null || true
    fi

    # Parse Lynis report into JSON using Python3
    python3 << 'PYEOF'
import json
import os
import re

report_dat = "/var/log/lynis-report.dat"
findings = []
score = None

if os.path.exists(report_dat):
    with open(report_dat, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("warning[]=") or line.startswith("suggestion[]="):
                # Extract the finding text
                parts = line.split("=", 1)
                if len(parts) == 2:
                    finding_text = parts[1].strip()
                    finding_type = "warning" if line.startswith("warning") else "suggestion"
                    findings.append({
                        "id": finding_text.split("|")[0] if "|" in finding_text else finding_text,
                        "description": finding_text,
                        "type": finding_type
                    })
            elif line.startswith("hardening_index=") or line.startswith("score="):
                val = line.split("=", 1)[1].strip()
                if val.isdigit():
                    score = int(val)

output = {
    "score": score if score else "N/A",
    "findings": findings
}

with open("lynis_post_findings.json", 'w') as f:
    json.dump(output, f, indent=2)

print("    Post-hardening findings generated: {} findings".format(len(findings)))
PYEOF
}

# ---------------------------------------------------------------------------
# Main: Parse and compare findings
# ---------------------------------------------------------------------------

echo "[*] Loading Lynis findings..."

# Check for pre-hardening findings file
if [[ ! -f "$PRE_FINDINGS_FILE" ]]; then
    echo "    ERROR: Pre-hardening findings file ($PRE_FINDINGS_FILE) not found."
    echo "    Run 2-lynis_parse.sh first to generate the baseline."
    exit 1
fi
echo "    Pre-hardening findings: $PRE_FINDINGS_FILE [FOUND]"

# Check for post-hardening findings file, generate if missing
if [[ ! -f "$POST_FINDINGS_FILE" ]]; then
    echo "    Post-hardening findings not found — generating..."
    generate_post_findings
fi

if [[ ! -f "$POST_FINDINGS_FILE" ]]; then
    echo "    ERROR: Could not generate post-hardening findings."
    echo "    Ensure Lynis is installed and run manually: lynis audit system"
    exit 1
fi
echo "    Post-hardening findings: $POST_FINDINGS_FILE [FOUND]"

# ---------------------------------------------------------------------------
# Compare findings using Python3
# ---------------------------------------------------------------------------

echo "[*] Comparing findings..."

python3 << 'PYEOF'
import json
import os
import sys

pre_file = "lynis_findings.json"
post_file = "lynis_post_findings.json"
output_file = "hardening_improvement.json"

def load_findings(filepath):
    """Load findings from a JSON file, return (score, list_of_finding_ids)"""
    with open(filepath, 'r') as f:
        data = json.load(f)

    score = data.get("score", data.get("lynis_score", "N/A"))
    findings = data.get("findings", [])

    # Extract finding IDs or descriptions for comparison
    finding_ids = set()
    finding_details = {}
    for finding in findings:
        if isinstance(finding, dict):
            fid = finding.get("id", finding.get("control", finding.get("description", str(finding))))
            fdesc = finding.get("description", str(finding))
            ftype = finding.get("type", "unknown")
        else:
            fid = str(finding)
            fdesc = str(finding)
            ftype = "unknown"
        finding_ids.add(fid)
        finding_details[fid] = {"description": fdesc, "type": ftype}

    return score, finding_ids, finding_details

# Load both files
try:
    pre_score, pre_ids, pre_details = load_findings(pre_file)
except Exception as e:
    print("ERROR loading pre-findings: {}".format(e))
    sys.exit(1)

try:
    post_score, post_ids, post_details = load_findings(post_file)
except Exception as e:
    print("ERROR loading post-findings: {}".format(e))
    sys.exit(1)

# Calculate finding differences
resolved_ids = pre_ids - post_ids
remaining_ids = pre_ids & post_ids
new_ids = post_ids - pre_ids

# Build structured finding lists
resolved_findings = [
    {"id": fid, "description": pre_details[fid]["description"], "type": pre_details[fid]["type"]}
    for fid in sorted(resolved_ids)
]

remaining_findings = [
    {"id": fid, "description": post_details[fid]["description"], "type": post_details[fid]["type"]}
    for fid in sorted(remaining_ids)
]

new_findings = [
    {"id": fid, "description": post_details[fid]["description"], "type": post_details[fid]["type"]}
    for fid in sorted(new_ids)
]

# Calculate delta
delta = "N/A"
if isinstance(pre_score, (int, float)) and isinstance(post_score, (int, float)):
    delta = post_score - pre_score

# Build residual risk summary
high_risk_remaining = [f for f in remaining_findings if f["type"] == "warning"]
medium_risk_remaining = [f for f in remaining_findings if f["type"] == "suggestion"]

risk_level = "LOW"
if len(high_risk_remaining) > 5:
    risk_level = "HIGH"
elif len(high_risk_remaining) > 0 or len(medium_risk_remaining) > 10:
    risk_level = "MEDIUM"

residual_risk_summary = (
    "Residual risk: {} — {} warnings and {} suggestions remain unresolved. "
    "{} new findings introduced during hardening."
).format(
    risk_level,
    len(high_risk_remaining),
    len(medium_risk_remaining),
    len(new_findings)
)

# Write output JSON
report = {
    "before_score": pre_score,
    "after_score": post_score,
    "delta": delta,
    "resolved_findings": resolved_findings,
    "remaining_findings": remaining_findings,
    "new_findings": new_findings,
    "resolved_count": len(resolved_findings),
    "remaining_count": len(remaining_findings),
    "new_count": len(new_findings),
    "residual_risk_summary": residual_risk_summary
}

with open(output_file, 'w') as f:
    json.dump(report, f, indent=2)

# Print summary for console output
print("Before: {}".format(pre_score))
print("After: {}".format(post_score))
if isinstance(delta, (int, float)):
    if delta >= 0:
        print("Delta: +{}".format(delta))
    else:
        print("Delta: {}".format(delta))
else:
    print("Delta: {}".format(delta))
print("Findings resolved: {}".format(len(resolved_findings)))
print("Findings remaining: {}".format(len(remaining_findings)))
print("Findings new: {}".format(len(new_findings)))
print("Report saved to: {}".format(output_file))
PYEOF

exit 0
