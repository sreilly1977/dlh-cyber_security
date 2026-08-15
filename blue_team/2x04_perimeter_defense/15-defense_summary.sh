#!/bin/bash
#
# Name:        15-defense_summary.sh
# Purpose:     Emit a machine-readable summary of the network defense posture
# Author:      Steve - Cybersecurity Engineer
# Date:        August 15, 2026
#

set -euo pipefail

# ==============================================================================
# Configuration
# ==============================================================================

# Do not modify system state - this script reads artifacts only, makes no changes
# Generates defense_summary.json - a posture summary for capstone automation
# Output: defense_summary.json (parse downstream with: jq . defense_summary.json)
# nftables version: obtained via 'nft --version'

WORKDIR="$(pwd)"
GAPS_FILE="/home/analyst/MedDefense_Lab/known_gaps.json"

# Input artifacts (read-only):
#   segmentation_rules.json
#   nftables.conf
#   windows_firewall_rules.json
#   setup_verification.json
#   rule_validation.json
#   protocol_audit.json
#   dns_filter_report.json
#   network_artifact_package/manifest/manifest.json
#   perimeter_validation.json (or perimeter_validation_results.json)
#   /home/analyst/MedDefense_Lab/known_gaps.json

export WORKDIR
export GAPS_FILE

echo "================================================================"
echo "   Defensive Posture Summary - $(hostname)"
echo "================================================================"

python3 << 'PYEOF'
import json
import os
import socket
import subprocess
from datetime import datetime, timezone

workdir = os.environ["WORKDIR"]
gaps_file = os.environ["GAPS_FILE"]
output_file = "defense_summary.json"

def load_json(path):
    """Load JSON from a file path, return None if not found or invalid."""
    if os.path.isfile(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None

def run_cmd(cmd):
    """Run a command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ""

def sha256_file(path):
    """Compute SHA-256 of a file, return empty string on failure."""
    if not os.path.isfile(path):
        return ""
    out = run_cmd(["sha256sum", path])
    if out:
        return out.split()[0]
    return ""

# ==============================================================================
# Load all artifacts
# ==============================================================================

seg_rules = load_json(os.path.join(workdir, "segmentation_rules.json"))
windows_fw = load_json(os.path.join(workdir, "windows_firewall_rules.json"))
setup_ver = load_json(os.path.join(workdir, "setup_verification.json"))
rule_val = load_json(os.path.join(workdir, "rule_validation.json"))
proto_audit = load_json(os.path.join(workdir, "protocol_audit.json"))
dns_report = load_json(os.path.join(workdir, "dns_filter_report.json"))
manifest = load_json(os.path.join(workdir, "network_artifact_package", "manifest", "manifest.json"))

# Check both perimeter validation filenames
perim_val = load_json(os.path.join(workdir, "perimeter_validation_results.json"))
if perim_val is None:
    perim_val = load_json(os.path.join(workdir, "perimeter_validation.json"))

known_gaps = load_json(gaps_file)

# Read nftables.conf for reference
nftables_conf_path = os.path.join(workdir, "nftables.conf")
nftables_conf_content = ""
if os.path.isfile(nftables_conf_path):
    with open(nftables_conf_path, 'r') as f:
        nftables_conf_content = f.read()

# ==============================================================================
# 1. zones_defined
# ==============================================================================

zones_count = 0
zones_names = []
zones_cidrs = []

if seg_rules:
    zones = seg_rules.get("zones", {})
    if isinstance(zones, list):
        zones_count = len(zones)
        for z in zones:
            name = z.get("name", "")
            cidr = z.get("cidr", z.get("network", ""))
            if name:
                zones_names.append(name)
            if cidr:
                zones_cidrs.append({"zone": name, "cidr": cidr})
    elif isinstance(zones, dict):
        zones_count = len(zones)
        for name, info in zones.items():
            zones_names.append(name)
            if isinstance(info, dict):
                cidr = info.get("cidr", info.get("network", ""))
                if cidr:
                    zones_cidrs.append({"zone": name, "cidr": cidr})
            elif isinstance(info, str):
                zones_cidrs.append({"zone": name, "cidr": info})

# ==============================================================================
# 2. flows_allowed
# ==============================================================================

flows_count = 0
flows_list = []

if seg_rules:
    flows = seg_rules.get("allowed_flows", seg_rules.get("flows", seg_rules.get("allow_flows", [])))
    if isinstance(flows, list):
        flows_count = len(flows)
        flows_list = flows
    elif isinstance(flows, dict):
        flows_count = len(flows)
        for name, info in flows.items():
            if isinstance(info, dict):
                entry = dict(info)
                entry["flow_name"] = name
                flows_list.append(entry)
            else:
                flows_list.append({"flow_name": name, "value": info})

# ==============================================================================
# 3. firewall_engine
# ==============================================================================

nft_version_raw = run_cmd(["nft", "--version"])
nft_version = ""
if nft_version_raw:
    parts = nft_version_raw.split()
    if len(parts) >= 2:
        nft_version = parts[1]

nft_table_present = False
nft_rules_count = 0

tables_output = run_cmd(["nft", "list", "tables"])
if "meddefense" in tables_output:
    nft_table_present = True
    rules_output = run_cmd(["nft", "list", "table", "inet", "meddefense"])
    if rules_output:
        keywords = ['accept', 'drop', 'reject', 'jump', 'log', 'queue',
                    'dnat', 'snat', 'masquerade', 'redirect', 'tproxy']
        for line in rules_output.split('\n'):
            if any(kw in line for kw in keywords):
                nft_rules_count += 1

# ==============================================================================
# 4. windows_firewall
# ==============================================================================

windows_fw_present = windows_fw is not None
windows_fw_rule_count = 0

if windows_fw_present:
    if "rules" in windows_fw:
        rules = windows_fw["rules"]
        if isinstance(rules, list):
            windows_fw_rule_count = len(rules)
        elif isinstance(rules, dict):
            windows_fw_rule_count = len(rules)
    elif "rule_count" in windows_fw:
        windows_fw_rule_count = windows_fw["rule_count"]
    elif isinstance(windows_fw, list):
        windows_fw_rule_count = len(windows_fw)

# ==============================================================================
# 5. ids_engine
# ==============================================================================

suricata_version = ""
community_rule_count = 0
custom_rule_count = 0
replay_only = False

if setup_ver:
    suricata_version = setup_ver.get("installed_version", "")
    replay_only = setup_ver.get("mode", "") == "offline_replay"

if rule_val:
    custom_rule_count = rule_val.get("rule_count", 0)

if setup_ver:
    total_rules = setup_ver.get("rule_count", 0)
    community_rule_count = max(0, total_rules - custom_rule_count)

# ==============================================================================
# 6. protocol_audit
# ==============================================================================

finding_count_by_severity = {}
high_unaccepted_count = 0
accepted_exceptions_count = 0

if proto_audit and "findings" in proto_audit:
    findings = proto_audit["findings"]
    if isinstance(findings, list):
        for finding in findings:
            sev = finding.get("severity", "unknown")
            finding_count_by_severity[sev] = finding_count_by_severity.get(sev, 0) + 1
            if sev == "high" and not finding.get("exception_accepted", False):
                high_unaccepted_count += 1
            if finding.get("exception_accepted", False):
                accepted_exceptions_count += 1

# ==============================================================================
# 7. dns_filter
# ==============================================================================

dns_active = False
dns_blocklist_size = 0
dns_sinkhole_validated = False

if dns_report:
    dns_active = dns_report.get("service_status", "") == "active"
    dns_blocklist_size = dns_report.get("blocked_domains", 0)
    dns_sinkhole_validated = dns_report.get(
        "sinkhole_validated",
        dns_report.get("validation_passed", dns_active)
    )

# ==============================================================================
# 8. evidence_package
# ==============================================================================

# evidence_package: manifest SHA-256 computed for integrity verification

ep_tarball_path = ""
ep_manifest_sha256 = ""
ep_file_count = 0
ep_schema_version = ""

if manifest:
    ep_tarball_path = manifest.get("tarball_path", "")
    ep_file_count = len(manifest.get("files", []))
    ep_schema_version = manifest.get("field_schema_version", "")
    manifest_path = os.path.join(workdir, "network_artifact_package", "manifest", "manifest.json")
    ep_manifest_sha256 = sha256_file(manifest_path)

# ==============================================================================
# 9. validation_last_run
# ==============================================================================

val_timestamp = ""
val_passed = False
val_passed_count = 0
val_failed_count = 0

if perim_val:
    val_timestamp = perim_val.get("generated_at", perim_val.get("timestamp", ""))
    val_passed = perim_val.get("all_passed", False)
    val_passed_count = perim_val.get("passed", 0)
    val_failed_count = perim_val.get("failed", 0)

# ==============================================================================
# 10. known_gaps
# ==============================================================================

gaps = []
if known_gaps:
    if isinstance(known_gaps, list):
        gaps = known_gaps
    elif isinstance(known_gaps, dict):
        if "gaps" in known_gaps:
            gaps = known_gaps["gaps"]
        elif "known_gaps" in known_gaps:
            gaps = known_gaps["known_gaps"]
        else:
            gaps = [known_gaps]

# ==============================================================================
# Build final JSON
# ==============================================================================

result = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "hostname": socket.gethostname(),
    "zones_defined": {
        "count": zones_count,
        "names": zones_names,
        "cidrs": zones_cidrs
    },
    "flows_allowed": {
        "count": flows_count,
        "list": flows_list
    },
    "firewall_engine": {
        "nftables_version": nft_version,
        "meddefense_table_present": nft_table_present,
        "rules_loaded_count": nft_rules_count,
        "log_file_path": "/home/analyst/MedDefense_Lab/firewall_samples/ufw.log" # firewall log file location
    },
    "windows_firewall": {
        "present": windows_fw_present,
        "rule_count": windows_fw_rule_count
    },
    "ids_engine": { # ids_engine: custom rule count from rule_validation.json
        "suricata_version": suricata_version,
        "community_rule_count": community_rule_count,
        "custom_rule_count": custom_rule_count,
        "replay_only": replay_only
    },
    "protocol_audit": { # protocol_audit: accepted exceptions counted from exception_accepted field
        "finding_count_by_severity": finding_count_by_severity,
        "high_unaccepted_count": high_unaccepted_count,
        "accepted_exceptions_count": accepted_exceptions_count
    },
    "dns_filter": {
        "active": dns_active,
        "blocklist_size": dns_blocklist_size,
        "sinkhole_validation_result": dns_sinkhole_validated
    },
    "evidence_package": {
        "tarball_path": ep_tarball_path,
        "manifest_sha256": ep_manifest_sha256,
        "file_count": ep_file_count,
        "schema_version": ep_schema_version
    },
    "validation_last_run": {
        "timestamp": val_timestamp,
        "passed": val_passed,
        "passed_count": val_passed_count,
        "failed_count": val_failed_count
    },
    "known_gaps": gaps
}

with open(output_file, 'w') as f:
    json.dump(result, f, indent=2)
    f.write("\n")

# ==============================================================================
# Print operator summary
# ==============================================================================

print(f"Zones:                {zones_count} ({', '.join(zones_names)})")
print(f"Allowed flows:        {flows_count}")
print(f"nftables:             {nft_version} | {nft_rules_count} rules loaded")
if windows_fw_present:
    print(f"Windows Firewall:     aligned ({windows_fw_rule_count} rules)") # windows_firewall: rule count extracted from windows_firewall_rules.json
else:
    print(f"Windows Firewall:     not present")
mode_label = "replay" if replay_only else "live"
print(f"Suricata ({mode_label}):    {suricata_version} | {community_rule_count} community + {custom_rule_count} custom")
# Build severity summary (non-high severities)
sev_parts = [f"{v} {k}" for k, v in sorted(finding_count_by_severity.items()) if k != "high"]
sev_summary = ", ".join(sev_parts) if sev_parts else "none"
print(f"Protocol audit:       {high_unaccepted_count} high unaccepted, {sev_summary}, {accepted_exceptions_count} accepted")
if dns_active:
    sinkhole_status = "validated" if dns_sinkhole_validated else "not validated"
    print(f"DNS filter:           active | {dns_blocklist_size} domains | sinkhole {sinkhole_status}")
else:
    print(f"DNS filter:           inactive")
print(f"Evidence package:     {ep_tarball_path}")
total_val = val_passed_count + val_failed_count
val_status = "PASS" if val_passed else "FAIL"
print(f"Last validation:      {val_timestamp} | {val_status} ({val_passed_count}/{total_val})")
print(f"Known gaps:           {len(gaps)}")
print(f"Report: {output_file}")
print("================================================================")

PYEOF
