# Introduction

> "The absence of evidence is not the evidence of absence."
> 
> — Donald Rumsfeld

You have built a detection stack. YARA rules, SIEM alerts, IOC databases, Suricata signatures. You can detect the HEALTHBANE dropper when it lands. You can detect the RAT when it beacons. You can detect the exfiltrator when it tunnels data through DNS. Your ATT&CK coverage sits at 55% and your detection posture has improved significantly since the beginning of Module 4.

And none of it caught Stage 4.

Because Stage 4 does not depend on custom malware. It does not require a new executable. It does not require attacker-controlled internet infrastructure. It does not trigger YARA, file-hash IOCs or blocklists. Stage 4 uses PsExec, WMI, PowerShell Remoting and stolen service account credentials. These are legitimate administration tools. They become malicious only when the context is wrong: the wrong user, the wrong source host, the wrong time, the wrong target and the wrong sequence of actions.

This is Living Off The Land. This is why detection alone is not enough.

## Why This Matters

Threat hunting is the proactive search for activity that bypassed automated detection. Detection waits for a rule to fire. Hunting starts with a hypothesis and searches the data directly.

A detection engineer writes:

    alert when PsExec runs

A threat hunter asks:

    Has PsExec ever run from a non-admin workstation between midnight and 5 AM targeting a database server?

That difference matters. Sophisticated attackers deliberately choose techniques that fall outside your detection perimeter. They use tools that administrators also use. They blend into normal operations until you compare behavior against a baseline.

In this project, you will hunt for HEALTHBANE Stage 4 using only the provided SIEM exports, references and baseline files. No live SIEM is required. No external infrastructure is required. The full project is self-contained inside the 4x04 material folder.

## Context

Week sixteen at MedDefense Health Systems. Monday morning.

Sarah Park drops a classified advisory on James Chen's desk.

"HC3 just issued HEALTHBANE-ADV-2026-004. It is bad news, James."

The advisory says that the two healthcare organizations fully compromised by HEALTHBANE showed a fourth stage of activity. Before the exfiltrator ran, and in some cases before Stage 2 malware was fully deployed, the attacker moved laterally through the network using legitimate Windows administration tools.

PsExec. WMI. PowerShell Remoting. Stolen service account credentials.

No custom malware. No custom C2. No new infrastructure.

James reads the advisory silently.

"They used a compromised workstation as a pivot point. From there they used PsExec to reach the database servers, WMI to enumerate systems, PowerShell Remoting to stage files and service account credentials to move laterally. The activity happened between 1 AM and 5 AM. The SOC never saw it because every tool the attacker used is a tool IT uses for maintenance."

Robert Kim, the IT administrator, looks uncomfortable.

"Those are my tools. I use PsExec for deployment. I use WMI for inventory. I use PowerShell Remoting for patch management. Our SIEM logs that as normal activity."

James nods.

"Exactly. So now the question is not whether the tool is suspicious. The question is whether the context is suspicious. Did this happen to us? We need a threat hunt, not a detection review."

Dr. Morales adds:

"The board heard that our detection posture reached 55% ATT&CK coverage. If Stage 4 happened in the uncovered 45%, I need to explain why the percentage created a false sense of security and what we are doing to close the gap."

Your job is to hunt the last 14 days of MedDefense SIEM data and answer the question:

    Did HEALTHBANE Stage 4 happen in the MedDefense environment?

---

# [0. The Hunt Brief](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/0-hunt_brief.sh)

## Goal: 

Analyze the HC3 advisory on HEALTHBANE Stage 4, document the threat model for LOLBin-based lateral movement, and identify which ATT&CK techniques in MedDefense's current gap would be exploited by Stage 4.

## Context: 

Before you hunt, you must understand what you are hunting for. The HC3 advisory describes the attacker's Stage 4 methodology. Your 4x03 ATT&CK mapping shows which techniques you can detect and which techniques remain uncovered. The gap between those two is your hunting target.

This is how professional threat hunters scope their work: start with intelligence, map it to your detection posture, and hunt the gaps.

Materials:

    Use reference/hc3_advisory_004.txt
    Use reference/4x03_attack_mapping.json
    Use reference/admin_schedule.txt
    Use reference/service_accounts.txt
    Use reference/network_topology.txt

## Instructions: 

Write a script 0-hunt_brief.sh that:

1. Parses reference/hc3_advisory_004.txt and extracts the Stage 4 TTP summary:

    PsExec
    WMI
    PowerShell Remoting
    LSASS credential access
    service account abuse
    off-hours operations

2. Loads reference/4x03_attack_mapping.json and lists lateral movement and credential access techniques by current state:

    OBSERVED
    INFERRED
    NOT COVERED

3. Identifies advisory techniques that fall into the NOT COVERED category

4. Produces a structured hunt brief:

    scope
    data sources
    14-day time window
    hunt targets
    priority ranking

5. Includes the false-positive control references:

    Robert Kim schedule
    service account matrix
    network topology

**Expected Output:**

```bash
$ ./0-hunt_brief.sh

================================================================
   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)
   Classification: TLP:AMBER
================================================================

HC3 ADVISORY SUMMARY:
  Stage 4 TTPs:
    [*] PsExec for remote command execution on servers
    [*] WMI for remote process creation and enumeration
    [*] PowerShell Remoting for interactive access and staging
    [*] Credential dumping via LSASS memory access
    [*] Service account abuse for lateral authentication
    [*] Off-hours operations to avoid detection

ATT&CK COVERAGE GAP ANALYSIS:
  Current coverage: 16/29 techniques (55%)
  Stage 4 techniques in gap:
    T1021.002  SMB/Windows Admin Shares      NOT COVERED
    T1047      WMI                           NOT COVERED
    T1021.006  Windows Remote Management     NOT COVERED
    T1003.001  LSASS Memory                  NOT COVERED
    T1078.002  Domain Accounts               NOT COVERED

HUNT PRIORITY RANKING:
  P1: T1021.002 PsExec
  P2: T1003.001 LSASS
  P3: T1047 WMI
  P4: T1021.006 PSRemoting
  P5: T1078.002 Domain Accounts

DATA SOURCES:
  Primary: siem_export/wazuh_alerts_14d.json
  Secondary: siem_export/wazuh_raw_sysmon_14d.json
  Baseline: baseline/robert_kim_activity.json
  Reference: admin_schedule.txt, service_accounts.txt

TIME WINDOW: 14 days

================================================================
```

---

# [1. Hypothesis Generation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/1-hunt_hypotheses.sh)
### advanced

## Goal: 

Formulate five structured hunt hypotheses derived from the ATT&CK gap analysis, each specifying a technique to hunt, the data source to query, the expected observable pattern, and the criteria for a positive finding.

## Context: 

Hunting without hypotheses is log browsing. A hypothesis is a testable prediction:

    IF the attacker used PsExec for lateral movement, THEN I should see PsExec execution events from non-admin workstations targeting server assets outside maintenance windows.

This structure ensures every search has a defined success/failure criterion before the query starts.

Materials:

    Use reference/hc3_advisory_004.txt
    Use reference/4x03_attack_mapping.json
    Use baseline/robert_kim_activity.json

## Instructions: 

Write a script 1-hunt_hypotheses.sh that produces five hunt hypotheses.

Each hypothesis must include:

1. Hypothesis ID and ATT&CK technique

2. Statement:

    IF [adversary action], THEN [expected observable in SIEM data]

3. Data source

4. Search strategy using jq-style filter logic

5. Positive finding criteria

6. False positive exclusion

7. Expected baseline rate

Required hypotheses:

    H1: PsExec lateral movement
    H2: LSASS credential access
    H3: WMI remote execution
    H4: PowerShell Remoting
    H5: Service account abuse

**Expected Output:**

```bash
$ ./1-hunt_hypotheses.sh

================================================================
   HUNT HYPOTHESES - HEALTHBANE Stage 4
================================================================

HYPOTHESIS H1: Lateral Movement via PsExec
  Technique: T1021.002 SMB/Windows Admin Shares
  Statement: IF the attacker used PsExec for lateral movement, THEN
             process creation events will show PsExec execution from a
             non-admin workstation or outside maintenance windows.
  Data Source: siem_export/wazuh_alerts_14d.json
  Search: Image or CommandLine contains PsExec/psexec
  Positive: PsExec from host other than WS-ADMIN-01, or off-hours activity
  FP Exclusion: Robert Kim legitimate deployments from WS-ADMIN-01
  Baseline Rate: Robert Kim maintenance only

[H2 through H5 follow the same structure]

================================================================
```

---

# [2. Know Your Baseline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/2-baseline_profile.sh)

## Goal: 

Profile Robert Kim's legitimate administrative activity from the baseline dataset, establishing the normal pattern for PsExec, WMI, PowerShell Remoting and service account usage that will serve as the false positive filter for all subsequent hunts.

## Context: 

You cannot find anomalies without knowing what normal looks like. Robert Kim is the only IT administrator at MedDefense. Every PsExec, every WMI query, every PowerShell Remoting session in the environment should trace back to him during documented maintenance windows. Any deviation from this baseline is either undocumented administrative work or threat activity. Building this profile BEFORE hunting prevents the most common hunting mistake: flagging legitimate admin work as malicious.

Materials:

    Use baseline/robert_kim_activity.json
    Use reference/admin_schedule.txt

## Instructions: 

Write a script 2-baseline_profile.sh that parses baseline/robert_kim_activity.json and produces a structured profile of legitimate administrative activity.

Your profile must include:

1. Total events by tool (PsExec, WMI, PSRemoting)

2. Source host analysis: which hosts Robert Kim uses (should be ONLY WS-ADMIN-01)

3. Time-of-day distribution: when does he work (should be 08:00-18:00)

4. Day-of-week distribution: which days are maintenance days

5. Target host analysis: which servers he connects to and how often

6. User account analysis: which accounts he uses (should be his named account, not service accounts)

7. Baseline summary:

    normal source host
    normal time window
    normal account
    normal tools
    normal targets

8. Anomaly detection criteria for later tasks

**Expected Output:**

```bash
$ ./2-baseline_profile.sh

================================================================
   BASELINE PROFILE - Robert Kim (IT Administrator)
   Source: baseline/robert_kim_activity.json
================================================================

TOOL USAGE SUMMARY:
  PsExec events:          [count]
  WMI events:             [count]
  PSRemoting events:      [count]
  Total admin events:     [count]

SOURCE HOST:
  WS-ADMIN-01: [count]
  Other hosts: 0
  -> BASELINE: All admin activity originates from WS-ADMIN-01

TIME DISTRIBUTION:
  08:00-18:00: [count]
  18:00-08:00: 0
  -> BASELINE: Zero admin activity outside business hours

USER ACCOUNTS:
  MEDDEFENSE\robert.kim: [count]
  Service accounts: 0
  -> BASELINE: Never uses service accounts interactively

ANOMALY DETECTION CRITERIA:
  [!] Admin tool from any host other than WS-ADMIN-01
  [!] Admin tool usage outside business hours
  [!] Service account used interactively from workstation
  [!] WMI targeting unusual hosts

================================================================
```

---
