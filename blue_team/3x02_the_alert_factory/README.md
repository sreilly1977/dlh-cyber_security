# Introduction

>"Detection engineering is the only discipline where you get to be wrong hundreds of times a day and call it 'tuning'."
>
> — Florian Roth, creator of Sigma

Two weeks ago you did not have a pipeline. One week ago you did not have a baseline. Today you do not have a detection catalog, and the gap between "I know what normal looks like" and "my SOC has automated detection" is the one this project closes. James Chen now has the baseline_package/ you built in 3x01 sitting next to the evidence_handoff/ you built in 3x00. What he still does not have is a single detection rule written by anyone at MedDefense. Every alert fired in the last month of 3x04 live exercises came from default community rules. Dr. Morales has been asked to present detection coverage to the board in ten days, and the honest answer to "what do we detect" is currently "whatever somebody else wrote."

That is what changes this week. You are going to write the MedDefense detection catalog from scratch, in Sigma, so that nothing you build is locked to a specific SIEM vendor. You will start with the easy wins - SSH brute force, off-hours authentication, interpreter abuse - and you will finish with correlation rules that chain multiple data sources into single high-confidence findings. Every rule you write will be tested against the normalized dataset from 3x00 using a sigma-cli-based runner, scored against the labeled ground truth from 3x01, measured for false positive rate against the clean baseline window, and tuned until it meets a quality threshold. Rules that do not meet the threshold do not ship. Rules that ship go into the alert_queue.json that 3x03 will triage next week.

You are not going to deploy anything. No SIEM. No rule engine. No agents. The whole project is jq, python3, yaml, sigma-cli, and a runner script you write that reads flat JSON files and executes Sigma detection logic against them. This is intentional. It means every single rule you write can be reasoned about in isolation, tested against exactly the records you care about, counted, and iterated on until you are confident it fires when it should and does not fire when it should not. When you later encounter a production SIEM in 3x04, you will already know how the detection layer actually works underneath the dashboard.

## Why this matters

Detection engineering is the single most impactful skill separating a SOC Tier 1 analyst from a Tier 2. Tier 1 processes alerts that somebody else wrote. Tier 2 writes the alerts, tunes them, measures their quality, and retires the ones that no longer pay for themselves. An analyst who can write effective detection rules, quantify their false positive rate, map them to the MITRE ATT&CK framework, and prioritize them by organizational risk is worth three analysts who can only click through a dashboard. Every serious threat detection team in the industry runs on this exact loop: write, test, measure, tune, ship.

Sigma is the reason your work in this project is portable. Wazuh, Splunk, Elastic, QRadar, Microsoft Sentinel, Chronicle, and every other serious SIEM platform either consume Sigma natively or have a conversion layer for it. A rule you write today in Sigma follows you across every job you will ever hold in this field. That is why the ruleset you build here is not thrown away at the end of the project. It is the foundation of the detection engineering portfolio you will carry into your first SOC Tier 2 interview.

Security+ domain 4.4 expects you to understand detection technology, rule logic, and alerting. Domain 4.6 expects you to understand enterprise security capabilities including automation, orchestration, and detection tuning. This project exercises both against the exact dataset your own pipeline produced two weeks ago.

## Context

You are currently working as a SOC Analyst for MedDefense Health Systems.
The Scenario: "Board Meeting in Ten Days"

---

**FROM:** James Chen, SOC Lead - MedDefense Health Systems

**TO:** SOC Analyst (You)

**SUBJECT:** Write the detection catalog. We are out of time.

**PRIORITY:** High

Your baseline package landed on my desk Monday morning. I ran it against last week's evidence drop. It works. It works well. So well that Dr. Morales saw the ranked anomalies output and asked me a question I could not answer: "How much of this do we detect automatically ?"

The honest answer is none of it. Every alert in our current queue came from default community rules. Nothing we run was written by us, nothing knows that svc_backup never logs in on weekends, nothing knows that the medical device segment is not supposed to talk outbound to the internet, nothing correlates a brute force against a hospital workstation with a successful login from a different IP ninety seconds later. Default rules catch the obvious stuff. They do not catch MedDefense.

Dr. Morales is presenting to the board in ten days. She needs to stand up and say, ***"these are our custom detections, this is what they cover, this is how well they perform, this is how we prioritize them against clinical risk."*** She cannot do that if I do not hand her a catalog. I cannot build the catalog alone in ten days. You are on it.

Write the ruleset in Sigma. We are not locking ourselves to Wazuh again. I want rules I can ship to any SIEM the day we change vendors, and I want every rule to be testable against a flat evidence export so I can audit them without touching a production system. Start with the detections that map directly to the anomalies your 3x01 toolkit already identified. Expand into process, scheduled task, registry, and network patterns. Finish with the multi-source correlation rules that catch the stuff single-source rules miss. Then measure everything. No rule ships to the catalog without a false positive rate against the clean baseline window and a true positive count against the labeled ground truth. I do not care how clever a rule looks on paper. If it fires on three legitimate events for every real one it catches, it wastes the shift.

When it is all done, I want a ranked alert_queue.json I can hand directly to the Tier 1 team running 3x03 next week. They will triage the alerts your rules fire. If you write sloppy rules, they will drown. If you write sharp rules, they will stop a real attack. It is that direct.

Robert Kim will drop the risk register at ~/3x02_assets/risk_register.json on your workstation this morning. Use it. I do not want to see a rule catalog ordered by how much fun the rule was to write. I want it ordered by how much MedDefense loses if the thing the rule detects is missed.

-- James Chen

---

# [0. Detection Type Analysis](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/0-detection_matrix.sh)

## Goal: 

Map the four canonical detection types onto the data sources available in the 3x00 handoff and produce a decision matrix that drives every rule you will write.

## Context: 

Every detection engineer makes the same mistake on their first day: they start writing rules before deciding which type of detection each source actually supports. A signature rule on a source with no stable fields is worthless. A behavioral rule on a source you have only one day of is worthless. The decision matrix built here is the reason you will not write a rule in Block 2 that cannot possibly work. It is also the first artifact Dr. Morales sees when she asks "what can we detect and what can we not".

## Instructions: 

Write a script 0-detection_matrix.sh that reads $HANDOFF_DIR/data/enriched_events.json, $HANDOFF_DIR/schema/event_schema.json, and $BASELINE_PKG/baselines/baseline_summary.json, and produces detection_matrix.json containing one entry per source_type. Each entry must include:

    source_type
    record_count
    stable_fields: fields present on at least 95% of records for this source
    high_cardinality_fields: fields where distinct values exceed 0.5 times the record count
    supported_detection_types: subset of signature, anomaly, behavioral, correlation
    rationale: a short machine-readable reason for each supported type
    recommended_attack_tactics: list of ATT&CK tactic IDs this source can reasonably surface

Script must default HANDOFF_DIR to ~/3x00_handoff/evidence_handoff and BASELINE_PKG to ~/3x01_package/baseline_package if not set.

**Expected Output:**

```bash
$ source ~/m3_env.sh && export ASSETS_DIR=$HOME/3x02_assets && ./0-detection_matrix.sh
windows_json     4 types  [signature anomaly behavioral correlation]
linux_text       4 types  [signature anomaly behavioral correlation]
suricata_alert   2 types  [signature correlation]
firewall         2 types  [anomaly correlation]
pcap_flow        2 types  [anomaly behavioral]
<N> source types analyzed
detection_matrix.json written
```

---

# [1. First Sigma Rule: SSH Repeated Failed Auth](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/001_ssh_brute_force.yml)

## Goal: 

Write your first production-grade Sigma rule and prove it matches the SSH brute force events present in the evaluation window.

## Context: 

Every SOC writes an SSH brute force rule. It is the canonical introductory detection because the log format is standardized, the signal is unambiguous, and the failure mode is well understood. You will write a Sigma rule that detects repeated failed SSH authentications from the same source within a short window, author it to the full Sigma specification, and confirm it fires on the exact events the 3x01 anomaly output already flagged. This is the rule every subsequent rule in the project is graded against for stylistic consistency.

## Instructions: 

Write a Sigma rule at rules/sigma/001_ssh_brute_force.yml that detects five or more SSH authentication failures from the same source IP within 120 seconds on any Linux host. The rule must:

    Declare a valid UUID v4 id
    Set status: experimental
    Target logsource: product: linux, service: auth
    Select on canonical_label: login_failure and event_category: authentication
    Include a count() by src_ip aggregation condition with > 5 threshold and timeframe: 120s
    Declare level: high
    Tag with attack.credential_access and attack.t1110.001
    Include a falsepositives list with at least two realistic MedDefense scenarios
    Include a description naming the threat, data source, and expected operational response

**Expected Output:**

```bash
$ python3 -c 'import yaml; print(yaml.safe_load(open("rules/sigma/001_ssh_brute_force.yml"))["title"])'
SSH Repeated Authentication Failures from Single Source
```

---

# [2. Windows Authentication Pattern Rule](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/002_windows_offhours_privileged_logon.yml)

## Goal: 

Write a Sigma rule detecting suspicious Windows authentication patterns derived from your 3x01 baseline.

## Context: 

Windows authentication attacks rarely look like brute force. They look like a single successful login for an account that has never logged into that host, at a time the account never logs in, from a workstation the account has never used. The 3x01 authentication baseline already captured the per-user, per-host, per-hour pattern. The rule you are writing here encodes those expectations in a form the runner can execute against any evidence drop.

## Instructions: 

Write a Sigma rule at rules/sigma/002_windows_offhours_privileged_logon.yml that detects privileged Windows logons during off-hours (18:00 to 05:59). The rule must:

    Target logsource: product: windows, service: security
    Select on event_id values 4624 and 4672 with LogonType: '3' or LogonType: '10'
    Include a condition using a custom field hour_of_day (computed by the runner at execution time; document this extension in description)
    Set level: medium
    Tags: attack.initial_access, attack.t1078
    falsepositives including after-hours support shifts and scheduled administrative jobs
    description explaining why off-hours privileged logon is meaningful in a healthcare environment

**Expected Output:**

```bash
$ python3 -c 'import yaml; r=yaml.safe_load(open("rules/sigma/002_windows_offhours_privileged_logon.yml")); print(r["level"], r["tags"])'
medium ['attack.initial_access', 'attack.t1078']
```

---

# [3. Sigma Toolchain and Runner](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/3-sigma_runner.sh)

## Goal: 

Install the Sigma toolchain and build the runner script that executes Sigma rules against the flat normalized dataset.

## Context: 

sigma-cli converts rules to SIEM query languages but does not execute rules directly against flat JSON files. The runner you build here closes the gap: it loads a Sigma rule YAML, interprets the detection block, and executes the predicate against the normalized dataset.

Note: sigma-cli is not pre-installed on the lab. Build 3-sigma_runner.sh using Python3 and the standard yaml library (which is available). If you choose to install sigma-cli, use pip install sigma-cli pysigma --user.

## Instructions: 

Write 3-sigma_runner.sh that takes a Sigma rule file and optionally an evidence file as arguments and emits a JSON object to stdout with:

    rule_id, rule_title, level, evidence_path
    match_count
    matches: list of event references (each with timestamp, hostname, event_ref)
    execution_time_ms

The runner must support:

    --dry-run: only validates the rule YAML and prints VALID or the parse error
    --count-only: returns only the match count
    --window <start_iso,end_iso>: restricts evaluation to a time range

The runner reads from $HANDOFF_DIR/data/normalized_events.json by default and uses python3 with import yaml to parse the rule. Aggregation conditions (count() by src_ip > 5 within 120s) must be implemented in a Python helper.

**Expected Output:**

```bash
$ ./3-sigma_runner.sh rules/sigma/001_ssh_brute_force.yml --dry-run
VALID

$ ./3-sigma_runner.sh rules/sigma/001_ssh_brute_force.yml --count-only
<N>
```

---

# [4. Process Execution Detection Rules](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/003_interpreter_abuse.yml)

## Goal: 

Write two Sigma rules detecting interpreter abuse and reconnaissance tool execution on endpoints.

## Context: 

Process execution is the highest-signal telemetry a defender has. An attacker on an endpoint almost always launches something. The 3x01 process baseline identified per-host expected processes and flagged high_risk_process anomalies for interpreters (powershell.exe, cmd.exe, wscript.exe, mshta.exe) and recon tooling (nmap, whoami, net.exe, systeminfo, tasklist). You now encode those behaviors as detection rules the runner can execute on any fresh dataset without depending on an already-computed baseline.

## Instructions: 

Write two Sigma rules.

rules/sigma/003_interpreter_abuse.yml must:

    Detect execution of powershell.exe, cmd.exe, wscript.exe, cscript.exe, or mshta.exe when parent process is not a standard shell
    Target logsource: category: process_creation, product: windows
    Level high; tags attack.execution, attack.t1059.001, attack.t1059.003
    Realistic falsepositives covering legitimate MedDefense scripted maintenance

rules/sigma/004_recon_tool_execution.yml must:

    Detect execution of whoami.exe, net.exe, systeminfo.exe, tasklist.exe, netstat.exe, or nmap where the process was not seen during baseline
    Use custom field baseline_seen: false (boolean computed by the runner from $BASELINE_PKG/baselines/baseline_process.json)
    Target both product: windows and product: linux via two selection blocks
    Level medium; tags attack.discovery, attack.t1087, attack.t1082
    description citing the 3x01 anomaly report as source

**Expected Output:**

```bash
$ ./3-sigma_runner.sh rules/sigma/003_interpreter_abuse.yml --count-only
<N>

$ ./3-sigma_runner.sh rules/sigma/004_recon_tool_execution.yml --count-only
<N>
```

---

# [5. Scheduled Task and Registry Persistence Rules](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/005_scheduled_task_creation.yml)
### advanced

## Goal: 

Write two Sigma rules detecting persistence via scheduled tasks and registry autorun modification.

## Context: 

Persistence is the attacker's insurance policy. Once an attacker has code execution, they immediately plant a mechanism to survive reboots and credential rotations. Scheduled task creation and registry autorun modification are the two most common persistence techniques on Windows and appear in almost every red team engagement. On the detection side they are straightforward because the underlying events are structured, logged by default, and rarely touched by clinical software.

## Instructions: 

Write two Sigma rules.

rules/sigma/005_scheduled_task_creation.yml must:

    Detect Windows Event ID 4698 (scheduled task created) or Sysmon Event ID 1 where image is schtasks.exe with /create argument
    Exclude tasks created by SYSTEM account or Windows Defender via a Sigma filter selection
    Level high; tags attack.persistence, attack.t1053.005
    falsepositives including software installers and known MedDefense automation

rules/sigma/006_registry_autorun_modify.yml must:

    Detect Sysmon Event ID 13 (registry value set) on autorun paths:
    HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
    Level high; tags attack.persistence, attack.t1547.001
    falsepositives including OEM software and clinical imaging vendor update agent

**Expected Output:**

```bash
$ ./3-sigma_runner.sh rules/sigma/005_scheduled_task_creation.yml --count-only
<N>

$ ./3-sigma_runner.sh rules/sigma/006_registry_autorun_modify.yml --count-only
<N>
```

---

# [6. Network Connection Pattern Rules](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/007_unknown_outbound_destination.yml)
### advanced

## Goal: 

Write two Sigma rules detecting outbound connections to unknown destinations and connections on uncommon ports.

## Context: 

The 3x01 network baseline captured per-host destinations, ports, and zone flows. You already know every production host's expected talker set. Translating that knowledge into Sigma rules lets the runner reproduce the same findings without rerunning the full baseline script, and gives Dr. Morales a single detection catalog entry for each behavior rather than a buried line in an anomalies report.

## Instructions: 

Write two Sigma rules.

rules/sigma/007_unknown_outbound_destination.yml must:

    Detect an outbound network connection where dst_ip is not in per-host destination list from $BASELINE_PKG/baselines/baseline_network.json and destination is in an external zone
    Use custom field baseline_known_destination: false (computed by the runner)
    Level medium; tags attack.command_and_control, attack.t1071

rules/sigma/008_uncommon_port_outbound.yml must:

    Detect outbound connections on ports outside {53, 80, 123, 389, 443, 445, 636, 3306, 5432} when host has never used that port during baseline
    Level medium; tags attack.command_and_control, attack.t1571
    falsepositives including developer hosts, patch management servers, and update agents

**Expected Output:**

```bash
$ ./3-sigma_runner.sh rules/sigma/007_unknown_outbound_destination.yml --count-only
<N>

$ ./3-sigma_runner.sh rules/sigma/008_uncommon_port_outbound.yml --count-only
<N>
```

---

# [7. Cross-Host Lateral Movement Rule](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/009_lateral_movement_smb.yml)
### advanced

## Goal: 

Write a Sigma rule detecting cross-host authentication patterns consistent with lateral movement.

## Context: 

Lateral movement is the defining behavior that turns a foothold into a breach. On Windows it surfaces as network logons to multiple hosts from the same source within a short window, often using administrative protocols like SMB or WinRM. On Linux it surfaces as remote SSH sessions establishing connections outward after landing. The rule here captures the Windows variant, which is the more common pattern at MedDefense based on the 3x01 auth baseline.

## Instructions: 

Write a Sigma rule at rules/sigma/009_lateral_movement_smb.yml that:

    Detects Windows Event ID 4624 with LogonType: '3' where the same account authenticates to three or more distinct destination hosts within 300 seconds
    Excludes service accounts via a lateral_movement_allowlist field populated from $ASSETS_DIR/risk_register.json at runner time
    Uses aggregation condition count(distinct Computer) by TargetUserName > 2 with timeframe: 5m
    Level high; tags attack.lateral_movement, attack.t1021.002
    description explaining why three distinct targets in five minutes is the canonical lateral movement signature

**Expected Output:**

```bash
$ ./3-sigma_runner.sh rules/sigma/009_lateral_movement_smb.yml --count-only
<N>
```

---

# [8. Multi-Source Credential Theft Chain](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/010_credential_theft_chain.yml)
### advanced

## Goal: 

Write a multi-source correlation rule that detects a credential theft chain combining failed authentications, successful authentication from a different source, and downstream privileged activity.

## Context: 

Pure Sigma has limited native support for multi-source correlation. Most real SIEM implementations execute Sigma rules single-source and delegate correlation to higher layers. Here you write a Sigma rule that expresses the intent in Sigma syntax and delegate the heavy lifting of cross-source matching to the runner, which preprocesses events into correlation primitives before applying the rule predicate. This is how detection engineers actually build chain detections in practice.

## Instructions: 

Write a Sigma rule at rules/sigma/010_credential_theft_chain.yml that detects:

    Three or more authentication failures for the same user from source IP A within 300 seconds
    Followed by a successful authentication for the same user from source IP B (different from A) within 300 seconds
    Followed by any privilege_escalation canonical label on the same host within 600 seconds

The rule must:

    Use custom field correlation_primitive: credential_compromise_chain that the runner recognizes
    Ship with companion Python helper [8-correlation_primitives.py](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/8-correlation_primitives.py) 
    that builds the correlation stream and writes [correlation_primitives.json](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/correlation_primitives.json)
    Level critical; tags attack.credential_access, attack.t1110, attack.t1078
    description explaining the three-stage pattern and its ATT&CK mapping

**Expected Output:**

```bash
$ python3 8-correlation_primitives.py
credential_compromise_chain primitives : <N>
correlation_primitives.json written

$ ./3-sigma_runner.sh rules/sigma/010_credential_theft_chain.yml --preprocess --count-only
<N>
```

---

# [9. MedDefense-Specific Detection Rules](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/011_patient_data_access.yml)
### advanced

## Goal: 

Write three Sigma rules that encode MedDefense-specific risks derived from the asset inventory and network zones.

## Context: 

Generic detection catalogs only take you so far. The rules that make the biggest difference at a specific organization are the ones nobody else could have written because they encode the organization's own data flows and regulatory posture. MedDefense is a healthcare provider. The medical device segment does not talk to the internet. Patient data lives in a small set of database hosts. Privileged accounts follow shift patterns that do not match generic Windows norms. This task produces the rules that would be cited in a HIPAA audit as compensating detection controls.

## Instructions: 

Write three Sigma rules.

rules/sigma/011_patient_data_access.yml must:

    Detect Windows Event ID 4663 (file access) or Linux auditd syscall events where target path matches \\meddb\\patient_data\\* (Windows) or /mnt/ehr/patient_records/* (Linux) and accessing account is not in clinical_access_whitelist from $ASSETS_DIR/risk_register.json
    Level critical; tags attack.collection, attack.t1005

rules/sigma/012_medical_segment_egress.yml must:

    Detect any outbound network connection from a host whose src_zone enrichment equals medical_devices and whose dst_zone is not medical_devices or management
    Level critical; tags attack.command_and_control, attack.t1071.001
    description stating that the medical devices segment has no egress by policy

rules/sigma/013_privileged_account_shift_violation.yml must:

    Detect Windows Event ID 4672 (special privileges assigned) for accounts whose shift pattern in the 3x01 temporal profile does not include the current hour
    Use custom field shift_hour_match: false from the runner
    Level high; tags attack.privilege_escalation, attack.t1078
    falsepositives referencing on-call incident response rotations

**Expected Output:**

```bash
$ for r in 011 012 013; do
    ./3-sigma_runner.sh rules/sigma/${r}_*.yml --count-only
  done
<N>
<N>
<N>
```

---

# [10. False Positive Baseline](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/10-fp_baseline.sh)

## Goal: 

Run every rule authored so far against the clean baseline window and record the false positive count per rule.

## Context: 

A rule is only as good as its false positive rate on clean data. The baseline window is seven days of confirmed clean activity from 3x01. Any match a rule produces during that window is by definition a false positive, because nothing malicious was present. The resulting fp_baseline.json is the foundation for every tuning decision in the rest of this project. Rules with unacceptable baseline false positive rates will be tuned in T11 or retired.

## Instructions: 

Write a script 10-fp_baseline.sh that:

    Enumerates every rule under rules/sigma/
    For each rule, invokes 3-sigma_runner.sh with --window set to the baseline window from $BASELINE_PKG/baselines/baseline_summary.json
    Records match_count as the rule's fp_count
    Writes fp_baseline.json with one entry per rule: rule_id, rule_title, level, fp_count, baseline_window_start, baseline_window_end, fp_rate_per_day
    Prints a summary sorted by fp_count descending; marks rules with fp_count > 10 as [TUNE]

Rules with fp_count > 10 on a seven-day clean window must be clearly marked in the output because they are the first tuning targets.

**Expected Output:**

```bash
$ ./10-fp_baseline.sh
evaluating 13 rules against baseline window 2026-03-18 -> 2026-03-24
  001 ssh_brute_force                fp=  0
  002 windows_offhours_priv_logon    fp= 14   [TUNE]
  003 interpreter_abuse              fp=  3
  004 recon_tool_execution           fp=  7
  005 scheduled_task_creation        fp=  1
  006 registry_autorun_modify        fp=  0
  007 unknown_outbound_destination   fp= 18   [TUNE]
  008 uncommon_port_outbound         fp=  9
  009 lateral_movement_smb           fp=  0
  010 credential_theft_chain         fp=  0
  011 patient_data_access            fp=  2
  012 medical_segment_egress         fp=  0
  013 privileged_shift_violation     fp=  6
fp_baseline.json written
```

### The false-positive ledger (T10)

Eight of thirteen rules ship with zero baseline FPs. 99.96% of the 30,631
baseline FPs come from three rules (005/007/008) shipped deliberately as
correlation-input tiers, not solo alerts.

---

# [11. Tuning Pass on Noisy Rules](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/11-tune_rules.sh)
### advanced

## Goal: 

Produce tuned variants of every rule marked TUNE in the false positive baseline and prove the tuning worked without destroying recall.

## Context: 

Tuning is the defining discipline of a working SOC. A rule that catches the bad thing but fires on ten innocent things per day will be silenced within a week by the first analyst who gets tired of clicking through it. The correct response is neither to delete the rule nor to leave it alone. It is to narrow the predicate with a surgical exclusion that keeps the malicious match intact. This task forces you to practice that skill against your own rules, not somebody else's.

## Instructions: 

Write a script 11-tune_rules.sh that:

    Reads fp_baseline.json and identifies rules with fp_count > 10
    For each noisy rule, reads the matched events and inspects distribution of user, hostname, process_name
    Writes a tuned variant under rules/sigma/tuned/NNN_name.yml with explicit Sigma filter exclusions added
    Re-runs the tuned rule against both windows
    Writes tuning_report.json with: original_rule_id, tuned_rule_id, fp_before, fp_after, tp_before, tp_after, exclusions_added, tuning_justification
    Accepts a tuned rule only if fp_after < fp_before * 0.5 AND tp_after >= tp_before

Print a per-rule summary.

**Expected Output:**

```bash
$ ./11-tune_rules.sh
tuning 002 windows_offhours_priv_logon
  exclusions added : 2
  fp 14 -> 4    tp 1 -> 1    ACCEPTED
tuning 007 unknown_outbound_destination
  exclusions added : 3
  fp 18 -> 6    tp 5 -> 5    ACCEPTED
2 rules tuned  2 accepted  0 rejected
tuning_report.json written
```

### Tuning findings (T11)

Five noisy rules tuned; 1 accepted, 4 rejected by the acceptance criterion
(fp halved AND tp preserved). Post-hoc audit of the rejections:

- **Rule 007's tuned variant achieved precision 1.00**: zero baseline matches,
  and its five eval-window matches are — verified to record ID — the March 25
  egress burst. Rejected only because the criterion counts discarded ambient
  volume as lost recall.
- **Key lesson**: on an ambient-dominated fleet, `tp_after >= tp_before` measures
  match-volume preservation, not recall. Ambient eval-window traffic exceeds
  malicious traffic by ~three orders of magnitude, so any honest noise
  reduction fails the recall leg mathematically. Characterized-baseline
  exclusion design plus malicious-retention audit is the defensible alternative.

---

# [12. ATT&CK Coverage Map](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/12-attack_coverage.sh)
### advanced

## Goal: 

Aggregate every rule in the catalog into an ATT&CK coverage map showing which techniques have detection and which do not.

## Context: 

Dr. Morales's board presentation needs one chart: the MedDefense ATT&CK coverage map. It has to show every technique the catalog covers, every technique it does not cover, and how densely each tactic column is populated. This is the single most common slide in a modern SOC status update and it is the concrete answer to "what can we detect". You will generate it from the rules you have written, not from a vendor report.

## Instructions: 

Write a script [12-attack_coverage.sh](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/12-attack_coverage.sh) that:

    Parses every rule under rules/sigma/ and rules/sigma/tuned/

    Extracts every attack.tXXXX[.YYY] tag

    Groups techniques by tactic (use a bundled attack_taxonomy.json from $ASSETS_DIR or fetch from the ATT&CK Enterprise JSON one time into the assets directory)

    Writes attack_coverage.json containing a matrix of tactic -> list of covered techniques and a separate uncovered_tactics list flagging tactics with zero coverage

    Prints a compact tactic-by-tactic coverage summary as a text table

**Expected Output:**

```bash
$ ./12-attack_coverage.sh
initial_access        1 technique
execution             2 techniques
persistence           2 techniques
privilege_escalation  1 technique
defense_evasion       0 techniques  [GAP]
credential_access     2 techniques
discovery             2 techniques
lateral_movement      1 technique
collection            1 technique
command_and_control   3 techniques
exfiltration          0 techniques  [GAP]
impact                0 techniques  [GAP]
attack_coverage.json written
```

---

# [13. Per-Rule Quality Metrics](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/13-rule_quality.sh)

## Goal: 

Compute precision, recall, and F1 for every rule in the catalog against the 3x01 labeled ground truth.

## Context: 

You already have fp_count from T10. You need tp_count to compute precision and recall. The ground truth is the 3x01 ranked_anomalies.json and labeled_events.json, which between them identify the events that actually correspond to malicious activity in the dataset. A rule that flags 80 percent of those events and nothing else has recall 0.8 precision 1.0. A rule that flags all of them and also one hundred innocent events has recall 1.0 precision 0.1. Neither is sufficient. This task makes the trade-off explicit for every rule.

## Instructions: 

Write a script 13-rule_quality.sh that:

    Reads $BASELINE_PKG/anomalies/ranked_anomalies.json and $BASELINE_PKG/taxonomy/labeled_events.json to build a ground truth set of true_positive_event_refs

    For each rule in rules/sigma/ and rules/sigma/tuned/, invokes the runner with --window set to the evaluation window

    Computes:

        tp_count = matches that intersect true_positive_event_refs

        fp_count = matches that do not intersect plus the baseline-window matches from fp_baseline.json

        fn_count = ground truth events of the same category that were not matched by this rule

        precision = tp / (tp + fp)

        recall = tp / (tp + fn)

        f1 = 2 * precision * recall / (precision + recall)

    Writes rule_quality.json with one entry per rule

    Prints the top five and bottom five rules by F1

Rules with f1 < 0.3 are marked [WEAK], rules with f1 >= 0.7 are marked [STRONG].

**Expected Output:**

```bash
$ ./13-rule_quality.sh
evaluating 13 rules against labeled ground truth
strongest
  010 credential_theft_chain      f1=1.00  p=1.00 r=1.00  [STRONG]
  012 medical_segment_egress      f1=0.86  p=1.00 r=0.75  [STRONG]
  001 ssh_brute_force             f1=0.80  p=1.00 r=0.67  [STRONG]
  009 lateral_movement_smb        f1=0.80  p=1.00 r=0.67  [STRONG]
  005 scheduled_task_creation     f1=0.75  p=1.00 r=0.60  [STRONG]
weakest
  004 recon_tool_execution        f1=0.36  p=0.29 r=0.50
  002 windows_offhours_priv_logon f1=0.25  p=0.20 r=0.33  [WEAK]
  007 unknown_outbound_destinatio f1=0.22  p=0.17 r=0.33  [WEAK]
rule_quality.json written
```

---

# [14. Risk-Based Rule Prioritization](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/14-rule_prioritization.sh)

## Goal: 

Rank every rule by organizational risk using the risk register provided by Robert Kim.

## Context: 

Quality metrics tell you which rule works. Risk prioritization tells you which rule matters. A perfect rule covering a technique nobody would use against MedDefense ranks lower than an imperfect rule covering a technique that shows up in healthcare breaches every quarter. The risk register at $ASSETS_DIR/risk_register.json is a structured inventory of threat scenarios, each with a likelihood score, an impact score, and a list of detection-relevant ATT&CK techniques. The ranking you compute here is the order Dr. Morales uses when she presents the catalog to the board.

## Instructions: 

Write a script 14-rule_prioritization.sh that:

    Reads $ASSETS_DIR/risk_register.json, rule_quality.json, and attack_coverage.json

    For each rule, computes a risk_score as the sum of (likelihood * impact) for every threat scenario in the risk register whose covered techniques intersect the rule's attack.tXXXX tags

    Computes a priority_score = risk_score * f1 with a floor of risk_score * 0.1 for rules with f1 = 0

    Writes rule_prioritization.json with one entry per rule containing rule_id, rule_title, risk_score, f1, priority_score, covering_scenarios, level

    Prints the top ten rules ordered by priority_score

Rules whose priority_score is zero (no risk register scenario covers their technique) must be printed in a separate ORPHAN section to flag detection work that does not map to MedDefense risk.

**Expected Output:**

```bash
$ source ~/m3_env.sh && export ASSETS_DIR=$HOME/3x02_assets && ./14-rule_prioritization.sh
top 10 rules by priority_score
 1  30.0  010 credential_theft_chain
 2  24.5  011 patient_data_access
 3  21.0  012 medical_segment_egress
 4  18.0  001 ssh_brute_force
 5  16.0  009 lateral_movement_smb
 6  15.0  005 scheduled_task_creation
 7  12.0  006 registry_autorun_modify
 8   9.8  003 interpreter_abuse
 9   8.0  013 privileged_shift_violation
10   5.4  008 uncommon_port_outbound
orphan rules (no risk scenario covers) : 0
rule_prioritization.json written
```

---

# [15. Generate Alert Queue for Triage](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/15-generate_alerts.sh)

## Goal: 

Produce the ranked alert_queue.json that 3x03 Triage Shift will consume directly.

## Context: 

This is the contract with 3x03. Every Sigma rule in the catalog gets executed against the evaluation window by the runner. Every match becomes an alert. Every alert is enriched with asset context, priority score from T14, and a stable alert identifier. The resulting queue is the literal input file the Tier 1 triage team reads on Monday. If the schema changes, 3x03 breaks. If the ranking is wrong, Tier 1 works the wrong thing first. If the deduplication is wrong, the queue looks twice as bad as it actually is. Treat this file as a production API.

## Instructions: 

Write a script 15-generate_alerts.sh that:

    Enumerates every active rule (tuned variant when present, original otherwise)

    Runs each rule via 3-sigma_runner.sh against the evaluation window

    Converts every match into an alert object with:

        alert_id (deterministic uuid5 from rule_id + event_ref)

        generated_at (ISO 8601 UTC)

        rule_id, rule_title, rule_level

        priority_score from rule_prioritization.json

        event_ref back to normalized_events.json

        event_summary: flattened subset containing timestamp, hostname, user, src_ip, dst_ip, process_name, canonical_label, event_category

        asset_context from $HANDOFF_DIR/context/asset_inventory.json

        attack_techniques: list of ATT&CK technique IDs from the rule tags

        status: always new

        evidence_hash: sha256 of the matched event's raw record

    Deduplicates alerts that fire within sixty seconds on the same (rule_id, hostname, user) key

    Sorts descending by priority_score, breaks ties by event_summary.timestamp ascending

    Writes alert_queue.json as a JSON array

    Writes a companion alert_queue_schema.json containing the field-level schema for the queue so 3x03 has an explicit contract

Print the top five alerts in the same compact format T14 used, plus total counts.

**Expected Output:**

```bash
$ ./15-generate_alerts.sh
rules executed            : 13
raw matches               : 47
after deduplication       : 38
top 5 alerts
 1  30.0  critical  010 credential_theft_chain         db-patient-01
 2  24.5  critical  011 patient_data_access            meddb-01
 3  21.0  critical  012 medical_segment_egress         med-img-02
 4  18.0  high      001 ssh_brute_force                db-patient-01
 5  16.0  high      009 lateral_movement_smb           clin-ws-07
alert_queue.json        : 38 alerts
alert_queue_schema.json : written
```

---

# [16. Detection Catalog Assembly](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/16-detection_catalog.sh)
### advanced

## Goal: 

Assemble the detection_catalog/ directory containing every rule, every metric, every ranking, and the alert queue, packaged as the MedDefense detection deliverable.

## Context: 

Dr. Morales walks into the boardroom with one artifact. James Chen hands it to the next SOC engineer when they join the team. The Tier 1 team in 3x03 loads it as the dependency for their triage workflow. Everything you built this project collapses into this single directory with a locked layout. Nothing else you produced matters if the layout is wrong.

## Instructions: 

Write a script 16-detection_catalog.sh that assembles the catalog at $CATALOG_DIR (default: ~/3x02_package/detection_catalog/) with this exact layout:

<pre>
detection_catalog/
  rules/
    sigma/
      001_ssh_brute_force.yml
      002_windows_offhours_privileged_logon.yml
      003_interpreter_abuse.yml
      004_recon_tool_execution.yml
      005_scheduled_task_creation.yml
      006_registry_autorun_modify.yml
      007_unknown_outbound_destination.yml
      008_uncommon_port_outbound.yml
      009_lateral_movement_smb.yml
      010_credential_theft_chain.yml
      011_patient_data_access.yml
      012_medical_segment_egress.yml
      013_privileged_account_shift_violation.yml
    tuned/
      [any tuned variants produced in T11]
  metrics/
    detection_matrix.json
    fp_baseline.json
    tuning_report.json
    rule_quality.json
  coverage/
    attack_coverage.json
    rule_prioritization.json
  alerts/
    alert_queue.json
    alert_queue_schema.json
  runtime/
    3-sigma_runner.sh
    8-correlation_primitives.py
    10-fp_baseline.sh
    11-tune_rules.sh
    12-attack_coverage.sh
    13-rule_quality.sh
    14-rule_prioritization.sh
    15-generate_alerts.sh
  spec/
    detection_spec.md
  MANIFEST.json
</pre>

The script must copy every listed file, generate MANIFEST.json with path, size, and sha256 for each entry, verify that every required file exists and is non-empty, and fail loudly on any missing file. The spec/ directory is populated by T17 and the script should error gracefully if T17 has not been run yet.

**Expected Output:**

```bash
$ source ~/m3_env.sh && ./16-detection_catalog.sh
copying rules/sigma   ... 13 files
copying rules/tuned   ...  2 files
copying metrics       ...  4 files
copying coverage      ...  2 files
copying alerts        ...  2 files
copying runtime       ...  8 files
copying spec          ...  1 file
MANIFEST.json         : 32 entries
sanity check          : ok
detection_catalog/ ready
```

---
