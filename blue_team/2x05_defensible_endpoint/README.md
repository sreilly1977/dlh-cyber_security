# Introduction

>"The job is not finished when the system is hardened. The job is finished when somebody else can take the hardened system, verify it in one command and use it the same night without calling you." 
>
> — Engineering handoff principle, adapted

For five weeks you built skills on five separate projects. You hardened a Linux server. You hardened a Windows host. You instrumented endpoints with Sysmon, auditd and Script Block Logging. You engineered a patch pipeline. You designed a segmented network with nftables, custom Suricata rules and DNS filtering. Every project produced scripts, configs and structured artifacts on its own island.

This capstone is the project where the islands become a continent.

MedDefense is onboarding a new satellite clinic, Hawthorne Medical Center, a 40-bed community hospital 35 miles north of the main campus. Its IT cabinet contains one Linux application server, one Windows administrative endpoint, a flat switch fabric and zero existing security controls. The cutover is in three weeks. James Chen is handing you the environment and the deadline at the same time. Your job is not to write a plan. Your job is to hand back a defensible endpoint package: the same environment, hardened, instrumented, patched, segmented, validated and documented as structured data, in a form that another engineer can pick up, verify in one command and run in production the same night.

This is not a report. It is not an essay. It is not a design document. Every deliverable is a script, a config file, a structured JSON artifact or a signed handoff bundle. A reviewer armed with ls, jq, grep and the scripts themselves must be able to reach the same pass-fail verdict as you did, line by line, without asking you a single question.

## Why this matters

Real security engineering ends with a handoff. The engineer who hardens a system and then walks away has delivered half the job. The engineer who hardens the system, captures the delta as code, validates it against measurable criteria and packages the result so that operations can own it without further translation has delivered the whole job. Hospitals, banks, regulated environments, auditors: everybody needs the whole job. This capstone is the rehearsal. The evaluation grille at the end of this project is intentionally binary and countable, not because subjective judgment has no value, but because the professional standard you are training for is one where the evidence speaks before you do.

## Context

Week ten at MedDefense Health Systems. Monday morning.

James Chen drops a plastic bag on your desk. Inside it: a printed asset label, a USB stick and a single-page handover sheet.

"Hawthorne Medical Center. Forty beds, one satellite data closet, one Linux app server running the clinical intake application, one Windows host they use for administrative scheduling. They are joining MedDefense in three weeks and their current security posture is whatever Dell shipped in the box. Nothing more. Your job is to turn that box into a system we can put on our network without regretting it."

He hands you the handover sheet:

<pre>
HAWTHORNE MEDICAL CENTER — ENDPOINT HANDOFF
====================================================
Site:              Hawthorne, 35 mi north of HQ
Cutover date:      three weeks from today
Data sensitivity:  HIPAA PHI (clinical intake forms)

Endpoints:
  - hawthorne-app-01    Ubuntu 22.04, fresh install, unmanaged
  - hawthorne-adm-01    Windows 11 Pro, domain-joinable, unmanaged

Network:
  - Flat /24, no segmentation, no firewall on either host
  - Single switch, uplink to a FortiGate we do not control

Controls in place:
  - None
</pre>

Dr. Morales stops by mid-sentence.

"I do not want a PowerPoint next Monday. I want to walk into your office and run one command on the Linux host and another on the Windows host, get a green pass-fail from both and know the environment is ready. If I cannot do that without a phone call, the deliverable is not finished."

Sarah Park adds the continuity constraint.

"And whatever evidence you package at the end has to be readable by the Module 3 analysts we are training right now. Same field names, same layout, same manifest as the exports from 2x02 and 2x04. If they have to reverse-engineer your schema, we lost the point of standardizing it."

Mike Torres is already at the rack in the satellite closet taking pictures.

"Flat switch. One uplink. I will hand you the cable map and the VLAN plan by Tuesday. Everything else is yours."

---

# [0. The Environment Intake](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/0-environment_intake.sh)

## Goal: 

Capture the raw state of the Hawthorne endpoints before any hardening action and produce a structured intake record that every subsequent task can compare against.

## Context: 

The first rule of a professional handoff is that the receiver must be able to reconstruct what was done. The only way to do that is to record where you started. This task takes a complete snapshot of the unhardened environment, on both the Linux and the Windows side, and saves it in one deterministic format. Every later task measures its success by the delta between this snapshot and the post-hardening state.

## Instructions: 

Write a script 0-environment_intake.sh that runs on hawthorne-app-01 (Linux) and a PowerShell script [0-environment_intake.ps1](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/0-environment_intake.ps1) that runs on hawthorne-adm-01 (Windows). For Linux, the script must capture:

    Hostname, kernel release, distribution and patch level

    Installed package count from dpkg-query -W

    Listening sockets from ss -tulnpH

    Active systemd services

    Current sshd_config as a key-value record

    Current sysctl security parameters

    SUID and SGID binaries count from find / -perm /6000 -type f

    World-writable files count from find / -perm -0002 -type f excluding /proc and /sys

    Firewall status (nft list ruleset length)

    Telemetry presence: auditd running, rsyslog running, Sysmon-for-Linux present (if installed)

For Windows, the script must capture:

    Hostname, OS build and patch level

    Installed feature count from Get-WindowsFeature (if server) or Get-WindowsOptionalFeature (if client)

    Running services from Get-Service

    Local user accounts from Get-LocalUser

    Windows Firewall state per profile

    Audit policy summary from auditpol /get /category:*

    Sysmon presence and version via Get-Service Sysmon and event channel size

    PowerShell logging state (Script Block Logging registry key)

    Account lockout and password policy from net accounts

---

# [1. The Baseline Snapshot](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/1-baseline_snapshot.sh)

## Goal: 

Run a recognized hardening audit on both endpoints and persist the raw baseline score as the quantitative starting point for the capstone.

## Context: 

The intake tells you what is there. The baseline tells you how far from hardened it is. For Linux the instrument is lynis. For Windows the instrument is the scored output of a scripted audit that walks the CIS Level 1 controls relevant to a workstation. Both produce a number. That number is the denominator of the delta you will report at the end of the capstone.

## Instructions: 

Write a script [1-baseline_snapshot.sh](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/1-baseline_snapshot.sh) (Linux) and [1-baseline_snapshot.ps1](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/1-baseline_snapshot.ps1) (Windows) that runs the baseline audit and persists the raw output plus the extracted score.

For Linux:

    Run lynis audit system --quick --no-colors and capture the full log to capstone/baseline/lynis_baseline.log

    Parse the Hardening Index from the Lynis output

    Emit capstone/baseline/baseline_linux.json with timestamp, hostname, lynis_version, hardening_index, warnings_count, suggestions_count, log_path

For Windows:

    Run the provided audit helper /home/analyst/MedDefense_Lab/capstone/win_audit.ps1 which walks a fixed list of CIS Level 1 control checks and outputs one line per control with PASS, FAIL or NOT_APPLICABLE

    Count the pass rate and persist the full output to capstone/baseline/windows_baseline.log

    Emit capstone/baseline/baseline_windows.json with timestamp, hostname, controls_total, pass_count, fail_count, na_count, pass_rate_percent, log_path

---

# [2. The Target State Definition](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/2-target_state.sh)

## Goal: 

Declare, in structured data, the exact set of controls the handoff must satisfy and the pass criterion for each one, so that every downstream task can be checked against it.

## Context: 

Every capstone has a finish line. The professional difference between a rushed handoff and a mature one is whether the finish line was defined in data before the work started, or invented retroactively to match whatever was shipped. This task defines the finish line as a machine-readable contract. It is the source of truth for T8 (end-to-end validation) and T10 (compliance report). The grille at the end of this project is evaluated against this same file.

## Instructions: 

Write a script 2-target_state.sh that emits a capstone/target_state.json file declaring the target state. The file must contain:

    A top-level controls array, with one entry per control, each with the fields:

        id (string, stable identifier such as LNX-SSH-01)

        platform (linux, windows, network or both)

        family (hardening, telemetry, patching, network, handoff)

        description (single sentence)

        check_type (file_exists, json_field_equals, json_field_gte, command_exit_zero, grep_match)

        check_target (path or expression evaluated by the validation suite)

        expected_value (value, number or regex as appropriate)

        source_project

        severity (critical, high, medium, low)

    At minimum the following controls:

        SSH PermitRootLogin no, SSH PasswordAuthentication no, sysctl net.ipv4.ip_forward = 0, sysctl kernel.randomize_va_space = 2, auditd active, apparmor enforce mode, Lynis hardening index at least 80

        Windows Firewall default-deny inbound on every profile, Script Block Logging enabled, Sysmon service installed and running, audit policy covers Account Logon, Logon, Object Access and Privilege Use subcategories, CIS Level 1 pass rate at least 85 percent

        Linux auditd rules file present and loaded, structured JSON export path exists, Windows Sysmon event count greater than zero in the last 10 minutes, Script Block Logging event channel size greater than zero

        vulnerability_inventory.json present, patch_plan.json present, patch_execution_log.json present with zero entries in failed state, unattended-upgrades configured with the mandated blacklist

        nftables ruleset loaded with default-deny inbound, segmentation_rules.json present, Suricata custom rule file loaded with at least six rules, Suricata rule validation report shows every rule fired against its target PCAP, DNS filter active

        compliance.json present, manifest.json present with SHA-256 per file, telemetry export package exists and is tarballed, runbook script present and executable

    A top-level schema_version string

    A generated_at timestamp

The script must refuse to overwrite an existing target_state.json unless the --force flag is passed. A corrupted or missing target_state.json must be fatal for every downstream script.

**Expected Output:**

```bash
$ ./2-target_state.sh

$ cat capstone/target_state.json | head
{
  "id": "LNX-SSH-02",
  "description": "SSH must refuse password authentication"
}
{
  "id": "WIN-FW-01",
  "description": "Windows Firewall must default-deny inbound on every profile"
}
{
  "id": "NET-NFT-01",
  "description": "nftables input chain must default to drop"
}
```

---

# [3. The Linux Hardening Execution](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/3-linux_harden.sh)

## Goal: 

Apply the full hardening workflow to hawthorne-app-01 as a single idempotent orchestration and persist the execution evidence.

## Context: 

This is where the skills become a delivered control set. You do not reinvent the work. You orchestrate it. The hardening script from before runs against hawthorne-app-01, every step is logged as structured evidence and the result is compared against the Linux controls in target_state.json.

## Instructions: 

Write a script 3-linux_harden.sh that orchestrates the Linux hardening pass. The script must:

    Invoke the composition of hardening scripts in a deterministic order: SSH hardening, sysctl hardening, permission sweep, service minimization, PAM configuration, AppArmor enforcement, auditd deployment

    Capture the stdout and exit code of each sub-step into capstone/exec/linux_harden.log

    After the run, re-run lynis audit system and capture the new Hardening Index
        controls_touched (list of target-state control IDs modified by this step)

    Exit with code 0 only if every sub-step exited 0 and lynis_after >= target_state.linux.hardening_index. Otherwise exit 1.

    Emit capstone/exec/linux_harden.json with:

        timestamp

        hostname

        steps array, each entry with name, script_path, exit_code, duration_seconds, changed (boolean)

        lynis_before (read from baseline_linux.json)

        lynis_after (from the new audit)

        index_delta

        controls_touched (list of target-state control IDs modified by this step)

Hint: use set -o pipefail and a wrapper function that catches each sub-step's return code.

---

# [4. The Windows Hardening Execution](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/4-windows_harden.ps1)

## Goal: 

Apply the full hardening workflow to hawthorne-adm-01 as a single idempotent orchestration and persist the execution evidence.

## Context: 

The Windows side receives the same treatment as the Linux side. The orchestrator invokes the PowerShell scripts in order and captures each step as a row in a structured execution log. The end state is measured against the Windows controls in target_state.json.

## Instructions: 

Write a PowerShell script 4-windows_harden.ps1 that orchestrates the Windows hardening pass. The script must:

    Invoke the composition of scripts in order: account policy, audit policy, Windows Firewall baseline, Sysmon installation with the MedDefense config, PowerShell Script Block Logging enable, AppLocker or Defender Application Control baseline, service minimization

    Capture the stdout and exit code of each sub-step into capstone\exec\windows_harden.log

    After the run, invoke the provided /home/analyst/MedDefense_Lab/capstone/win_audit.ps1 helper and compute the new CIS Level 1 pass rate

    Exit with code 0 only if every sub-step exited 0 and post_pass_rate >= target_state.windows.pass_rate. Otherwise exit 1.

Note: the script is Windows-native PowerShell but must emit the same JSON schema as the Linux sibling so that the validation suite in T8 can read both without branching.

---

# [5. The Telemetry Instrumentation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/5-telemetry_deploy.sh)

## Goal: 

Deploy the telemetry stack on both endpoints, verify coverage against authorized test actions and persist the coverage evidence.

## Context: 

A hardened system that does not produce evidence is a silent system. The telemetry work is the layer that turns the hardened hosts into observable hosts. This task deploys Sysmon and Script Block Logging on the Windows host, refines the auditd rules on the Linux host, runs the controlled test sequences from and verifies that every authorized test action left the expected trace in the expected log.

## Instructions: 

Write a script [5-telemetry_deploy.sh (Linux)](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/5-telemetry_deploy.sh) and [5-telemetry_deploy.ps1 (Windows)](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/5-telemetry_deploy.ps1) that perform the deployment and coverage verification.

For Linux:

    Ensure auditd is active with the project-provided rules file at /etc/audit/rules.d/meddefense.rules

    Run the controlled test sequence: create a user, remove the user, run a service management action, schedule a cron job, remove it, run a short authorized find as root

    For each test action, query auditd and verify the expected record is present (by key search, e.g. ausearch -k meddefense-user-mgmt)

    Export the last 30 minutes of auditd and syslog records as structured JSON into capstone/telemetry/linux_events.json

For Windows:

    Verify Sysmon is installed, running and using the MedDefense configuration

    Verify Script Block Logging is active by reading the registry key

    Run the controlled test sequence: create a local user, create and run a scheduled task, start and stop a service, run a short authorized PowerShell command

    For each test action, query the relevant event channel (Sysmon Operational, PowerShell Operational, Security) and verify the expected event is present within the last 10 minutes

    Export the last 30 minutes of Sysmon and PowerShell events as structured JSON into capstone\telemetry\windows_events.json

    Emit capstone\telemetry\windows_coverage.json with the same per-action schema as Linux

Both scripts must exit 0 only if every test action produced the expected record.

---

# [6. The Patch Pipeline Deployment](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/6-patch_pipeline.sh)

## Goal: 

Deploy the patch management pipeline on the Linux endpoint, run it against the provided CVE feed and persist every pipeline artifact inside the capstone package.

## Context: 

A production endpoint that cannot be patched safely is a liability. This task takes the pipeline and runs it end-to-end on hawthorne-app-01 with the provided capstone CVE.

## Instructions: 

Write a script 6-patch_pipeline.sh that orchestrates the pipeline end-to-end for here. The script must:

    Invoke the pipeline script from the previous project with CAPSTONE_ARTIFACTS_DIR=capstone/patch/ set in the environment so that all sub-step artifacts land inside the capstone package

    Consume the provided capstone CVE feed at /home/analyst/MedDefense_Lab/capstone/cve_feed.json

    Configure unattended-upgrades with the mandated blacklist from /home/analyst/MedDefense_Lab/capstone/blacklist.json

    Capture the pipeline exit code and every sub-step artifact path

    Exit 0 only if the pipeline exit code was 0 and failed_entries == 0

Hint: this task does not reinvent the pipeline. It wraps it with client specific directory redirection and a summary emitter.

---

# [7. The Network Defense Deployment](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/7-network_deploy.sh)

## Goal: 

Deploy the network defense stack on hawthorne-app-01, validate every rule and run the offline Suricata replay against the capstone PCAP set.

## Context: 

The perimeter comes last because it is the control that isolates the host from everything you have not hardened yet. This task deploys the nftables ruleset, aligns Windows Firewall to the same segmentation contract, runs Suricata in offline replay mode against the capstone PCAP set and produces the full artifact collection inside the capstone package.

## Instructions: 

Write a script 7-network_deploy.sh that orchestrates the deployment and validation the script must:

1.Invoke the pipeline with CAPSTONE_ARTIFACTS_DIR=capstone/network/ set in the environment so that artifacts land inside the capstone package

    Use the capstone segmentation file at /home/analyst/MedDefense_Lab/capstone/segmentation_rules.json (which reflects the Hawthorne site topology, not the main MedDefense topology)

    Run the firewall validation suite and refuse to proceed if any test fails

    Run Suricata in offline replay mode against every PCAP in /home/analyst/MedDefense_Lab/capstone/PCAPs/ and persist the parsed alerts

    Run the custom rule validation against the provided labeled PCAPs

    Configure dnsmasq as the local DNS filter with the capstone blocklist at /home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt

    Exit 0 only if every validation step passed

---

# [8. The End-to-End Validation Suite](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/8-validate_all.sh)

## Goal: 

Run a single validation suite that reads target_state.json, checks every control and produces one machine-readable report that decides whether the environment is ready for handoff.

## Context: 

This is the single command that Dr. Morales said she wanted to run. No human judgment. No narrative. No partial credit. It reads the target state, walks every control, performs the specified check, records the evidence path and produces a per-control verdict. If every control passes, the environment is ready. If any control fails, the exit code is non-zero and the failing controls are listed with their evidence paths so that the engineer can fix the exact gap and re-run.

## Instructions: 

Write a script 8-validate_all.sh that loads capstone/target_state.json and evaluates every control. The script must:

    For each control in target_state.controls:

        Dispatch on check_type:

            file_exists: check check_target path

            json_field_equals: load the JSON file and compare the field to expected_value

            json_field_gte: load the JSON file and compare the numeric field against expected_value

            command_exit_zero: run the command in check_target and check its exit code

            grep_match: run grep -E for expected_value in the file at check_target

        Record the verdict (pass, fail, error) and the evidence (the exact path, command or match that produced the verdict)

    Aggregate: total controls, pass count, fail count, error count, pass percentage

    Print a clean table to stdout showing one row per control family with the family totals

    Exit 0 if fail_count == 0 AND error_count == 0. Otherwise exit 1.

Hint: the script is a dispatcher, not a rewrite of every control. Reuse the artifacts produced by T3 through T7 by pointing check_target at them in target_state.json.

---

# [9. The Telemetry Export](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/9-telemetry_export.sh)
### advanced

## Goal: 

Assemble the structured telemetry export in the exact format, using the same field names and directory layout.

## Context: 

Those analysts ingest telemetry from every site that is in scope. Hawthorne is about to be a site. The moment the environment is accepted, the analysts need the first telemetry bundle in their standard format. This task produces that bundle. Every field name, every directory name, every schema version tag must match what is shipped so that the SIEM ingestion pipeline does not have to branch on the source.

## Instructions: 

Write a script 9-telemetry_export.sh that assembles the export package. The script must:

    Create capstone/telemetry_handoff/ with the subdirectories windows/, linux/, network/, manifest/

    Copy (not move) the following files into the package:

        capstone/telemetry/linux_events.json into linux/

        capstone/telemetry/windows_events.json into windows/

        The auditd rules file used on the Linux host into linux/audit_rules.txt

        The Sysmon configuration used on the Windows host into windows/sysmon_config.xml

        The Script Block Logging registry export into windows/psl_registry.reg

        The structured Suricata alerts from capstone/network/suricata_alerts.json into network/

        The nftables.conf from capstone/network/ into network/

    Emit telemetry_handoff/manifest/manifest.json with:

        schema_version matching the 2x02 and 2x04 schemas exactly

        source_site (hawthorne)

        generated_at

        files array with path, size_bytes, sha256, produced_by

        field_schema_version string matching what Module 3 expects

    Tar the package: tar -czf telemetry_handoff.tar.gz capstone/telemetry_handoff/ and record the tarball size and SHA-256 in the manifest

    Re-read the manifest and verify every hash matches the file on disk

    Exit 0 only if the verification pass succeeded

Note: this task does not transform telemetry. The Linux and Windows exports from T5 are already in the correct schema. This task assembles, manifests and verifies.

---

# [10. The Machine-Readable Compliance Report](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x05_defensible_endpoint/10-compliance_report.sh)
### advanced

## Goal: 

Emit the single compliance report that covers every control in scope, cross-references it to CIS, NIST and the 2x00 through 2x04 source projects, and captures the evidence path for each verdict.

## Context: 

The compliance report is the machine-readable artifact that an auditor or a next-level reviewer can consume without opening any other file. Unlike the validation report from T8, which is raw verdict data, the compliance report adds framework mapping and control lineage so that each capstone control can be traced to a CIS Control, a NIST CSF function and the source project that introduced it. It is the closest thing this project produces to a regulatory deliverable.

## Instructions: 

Write a script 10-compliance_report.sh that emits the compliance report. The script must:

    Read capstone/target_state.json and capstone/validation.json and join them by control ID

    For each control, look up the framework mapping in a provided /home/analyst/MedDefense_Lab/capstone/framework_map.json shipped with the project. The map contains, per control ID, an array of {framework, control_id} entries (e.g. CIS Controls v8, 5.2 for account management)

    Emit capstone/compliance.json with:

        schema_version (capstone-compliance-v1)

        generated_at

        hostname

        site (hawthorne)

        overall_verdict (ready, not_ready) computed from the validation summary

        controls array with per-control entries containing:

            id

            description

            family

            severity

            source_project

            verdict (from validation)

            evidence_path

            framework_mapping (array from the map)

        summary block with totals by family and severity

        unmapped_controls (array of control IDs with no framework mapping, for traceability)

    Print a stdout summary showing per-family pass rate and the top 5 framework hits

    Exit 0 only if overall_verdict == "ready"

Note: this task does not evaluate controls. It consumes the verdicts from T8 and enriches them with framework mapping.

---
