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

# 
