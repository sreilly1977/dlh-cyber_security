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

rules/sigma/[003_interpreter_abuse.yml](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/003_interpreter_abuse.yml) must:

    Detect execution of powershell.exe, cmd.exe, wscript.exe, cscript.exe, or mshta.exe when parent process is not a standard shell
    Target logsource: category: process_creation, product: windows
    Level high; tags attack.execution, attack.t1059.001, attack.t1059.003
    Realistic falsepositives covering legitimate MedDefense scripted maintenance

rules/sigma/[004_recon_tool_execution.yml](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/004_recon_tool_execution.yml) must:

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

rules/sigma/[005_scheduled_task_creation.yml](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/005_scheduled_task_creation.yml) must:

    Detect Windows Event ID 4698 (scheduled task created) or Sysmon Event ID 1 where image is schtasks.exe with /create argument
    Exclude tasks created by SYSTEM account or Windows Defender via a Sigma filter selection
    Level high; tags attack.persistence, attack.t1053.005
    falsepositives including software installers and known MedDefense automation

rules/sigma/[006_registry_autorun_modify.yml](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory/005_scheduled_task_creation.yml006_registry_autorun_modify.yml) must:

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
