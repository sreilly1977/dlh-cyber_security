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

# [3. Data Reconnaissance](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/3-data_recon.sh)

## Goal: 

Profile the full 14-day SIEM dataset: time range, event volume, top event types, top source hosts, alert severity distribution and data source availability, mapping which hunting hypotheses can be tested with the available data.

## Context: 

Before executing hunt queries, understand the data terrain. How many events exist? What time range is covered? Which event types are present? A hunt hypothesis fails if the dataset does not contain the required event type.

This reconnaissance phase ensures that your hunt is testable and evidence-based.

Materials:

    Use siem_export/wazuh_alerts_14d.json
    Use siem_export/wazuh_raw_sysmon_14d.json

## Instructions: 

Write a script 3-data_recon.sh that profiles the complete SIEM export.

Your reconnaissance must include:

1. Dataset metadata:

    total events
    first event
    last event
    duration
    format

2. Event type distribution:

    top 10 event types by count

3. Source host distribution:

    events per agent

4. Severity distribution:

    events by rule.level

5. Hourly distribution:

    24-hour histogram

6. Hypothesis coverage matrix:

    H1 PsExec
    H2 LSASS
    H3 WMI
    H4 PSRemoting
    H5 service accounts

**Expected Output:**

```bash
$ ./3-data_recon.sh

================================================================
   DATA RECONNAISSANCE - MedDefense SIEM Export
================================================================

DATASET METADATA:
  Total events:   [count]
  Time range:     [first timestamp] to [last timestamp]
  Duration:       14 days
  Format:         JSON / JSON Lines

TOP 10 EVENT TYPES:
  61603  Sysmon: Process Create
  61612  Sysmon: Registry Modify
  61605  Sysmon: Network Connection
  60106  Windows: Logon Success
  61610  Sysmon: DNS Query
  ...

SOURCE HOST DISTRIBUTION:
  WS-ADMIN-01:    [count]
  WS-RECV-03:     [count]
  SRV-HEALTH-DB:  [count]
  SRV-INS-DB:     [count]
  SRV-DC-01:      [count]

HYPOTHESIS COVERAGE MATRIX:
  H1 (PsExec):       [OK]
  H2 (LSASS):        [OK]
  H3 (WMI):          [OK]
  H4 (PSRemoting):   [OK]
  H5 (Svc Accounts): [OK]

================================================================
```

---

# [4. Hunt: Lateral Movement (PsExec)](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/4-hunt_psexec.sh)

## Goal: 

Execute hypothesis H1 by searching for anomalous PsExec usage in the SIEM data, filtering against Robert Kim's baseline, and documenting all findings with specific evidence.

## Context: 

PsExec is a legitimate Sysinternals tool that attackers frequently abuse for lateral movement. It is not suspicious by name alone. It becomes suspicious when the source host, user, time or target does not match the administrative baseline.

Materials:

    Use siem_export/wazuh_alerts_14d.json
    Use siem_export/wazuh_raw_sysmon_14d.json
    Use baseline/robert_kim_activity.json
    Use reference/admin_schedule.txt

## Instructions: 

Write a script 4-hunt_psexec.sh that:

1. Extracts all PsExec-related events:

    Image contains PsExec
    CommandLine contains PsExec or psexec

2. Compares each event against Robert Kim's baseline:

    source host
    time of day
    day of week
    user account

3. Classifies events as:

    BASELINE
    ANOMALOUS

4. For each anomalous event, extracts:

    timestamp
    source host
    user
    command line
    target host
    PID if available
    anomaly flags

5. Produces a hunt finding with confidence assessment

**Expected Output:**

```bash
$ ./4-hunt_psexec.sh

================================================================
   HUNT EXECUTION - H1: Lateral Movement via PsExec
   Technique: T1021.002 SMB/Windows Admin Shares
================================================================

QUERY RESULTS:
  Total PsExec events in 14 days: [count]
  Baseline: [count]
  ANOMALOUS: [count]

ANOMALOUS EVENTS:
  [A1] [timestamp]
    Source: WS-RECV-03
    User: MEDDEFENSE\svc_healthsync
    Command: PsExec.exe \\SRV-HEALTH-DB -s cmd.exe
    Target: SRV-HEALTH-DB
    ANOMALY FLAGS:
      [!] Source host is NOT WS-ADMIN-01
      [!] Time is outside business hours
      [!] User is a service account
      [!] Target is a database server

FINDING:
  Status: POSITIVE - HIGH CONFIDENCE
  Evidence: PsExec executions from non-admin workstation using service account
  Recommendation: ESCALATE

================================================================
```

---

# [5. Hunt: Lateral Movement (WMI)](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/5-hunt_wmi.sh)
### advanced

## Goal: 

Execute hypothesis H3 by searching for anomalous WMI remote execution in the SIEM data, distinguishing attacker WMI abuse from legitimate inventory scans.

## Context: 

WMI is powerful and common. Legitimate administrators use it for inventory and configuration checks. Attackers use it for remote execution, enumeration and command staging. Context separates the two.

Materials:

    Use siem_export/wazuh_alerts_14d.json
    Use siem_export/wazuh_raw_sysmon_14d.json
    Use baseline/robert_kim_activity.json

## Instructions: 

Write a script 5-hunt_wmi.sh that:

1. Extracts all WMI-related events:

    wmiprvse.exe
    wmic.exe
    Invoke-WmiMethod
    WMI remote execution patterns

2. Separates baseline Robert Kim inventory scans from anomalous events

3. For anomalous events:

    timestamp
    source
    target
    user
    process
    command line
    child process if available

4. Documents false-positive analysis:

    why each anomalous event is not legitimate WMI usage

5. Correlates findings with PsExec events when possible

**Expected Output:**

```bash
$ ./5-hunt_wmi.sh

================================================================
   HUNT EXECUTION - H3: Lateral Movement via WMI
   Technique: T1047 Windows Management Instrumentation
================================================================

QUERY RESULTS:
  Total WMI-related events: [count]
  Baseline: [count]
  ANOMALOUS: [count]

ANOMALOUS EVENTS:
  [A1] [timestamp] WS-RECV-03 -> SRV-HEALTH-DB
       wmiprvse.exe spawned cmd.exe
  [A2] [timestamp] WS-RECV-03 -> SRV-INS-DB
       wmiprvse.exe spawned cmd.exe

FALSE POSITIVE ANALYSIS:
  Events originate from non-admin workstation
  Events occur off-hours
  Events use service account or non-baseline user
  Robert Kims WMI baseline is from WS-ADMIN-01 during business hours

FINDING:
  Status: POSITIVE - HIGH CONFIDENCE
  Pattern: PsExec establishes access, WMI enumerates the target

================================================================
```

---

# [6. Hunt: Credential Access](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/6-hunt_credentials.sh)

## Goal: 

Execute hypothesis H2 by searching for credential dumping indicators and correlating LSASS memory access with subsequent authentication events.

## Context: 

Before the attacker could use a service account for lateral movement, they needed credentials. HC3 describes LSASS memory access as a Stage 4 credential access method. This hunt looks for the how behind the stolen credentials.

Materials:

    Use siem_export/wazuh_alerts_14d.json
    Use siem_export/wazuh_raw_sysmon_14d.json
    Use reference/service_accounts.txt

## Instructions: 

Write a script 6-hunt_credentials.sh that:

1. Searches for LSASS access events:

    target image contains lsass.exe
    source process is unusual
    access mask indicates memory read if available

2. Separates legitimate/system LSASS access from anomalous access

3. Searches for later authentication events using svc_healthsync

4. Correlates:

    LSASS access
    service account use
    PsExec/WMI/PSRemoting activity

5. Documents the credential theft timeline

**Expected Output:**

```bash
$ ./6-hunt_credentials.sh

================================================================
   HUNT EXECUTION - H2: Credential Access (LSASS)
   Technique: T1003.001 LSASS Memory
================================================================

LSASS ACCESS EVENTS:
  Total LSASS access events: [count]
  System/legitimate: [count]
  ANOMALOUS: [count]

  [A1] [timestamp]
    Host: WS-RECV-03
    Source Process: C:\Windows\Temp\debug_tool.exe
    Target: lsass.exe
    Access Mask: 0x1010
    -> Consistent with memory dumping

CREDENTIAL USAGE CORRELATION:
  svc_healthsync authentication from workstations:
    [timestamp] WS-RECV-03 -> SRV-HEALTH-DB
    [timestamp] WS-RECV-03 -> SRV-INS-DB

FINDING:
  Status: POSITIVE - HIGH CONFIDENCE
  The attacker likely dumped credentials and later used svc_healthsync
  for lateral movement.

================================================================
```

---

# [7. Hunt: PowerShell Remoting](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x04_threat_hunting/7-hunt_psremoting.sh)
### advanced

## Goal: 

Execute hypothesis H4 by searching for anomalous PowerShell Remoting sessions, distinguishing attacker remote access from Robert Kim's patch management sessions.

## Context: 

PowerShell Remoting enables remote shell and command execution. Robert Kim uses it legitimately during maintenance. The attacker uses it to stage files and move laterally. The tool is the same. The context is different.

Materials:

    Use siem_export/wazuh_alerts_14d.json
    Use siem_export/wazuh_raw_sysmon_14d.json
    Use baseline/robert_kim_activity.json
    Use reference/admin_schedule.txt

## Instructions: 

Write a script 7-hunt_psremoting.sh that:

1. Extracts PowerShell Remoting events:

    Enter-PSSession
    Invoke-Command
    New-PSSession
    wsmprovhost.exe
    Copy-Item to remote session

2. Classifies events against baseline:

    source host
    time
    user account
    target host

3. Documents anomalous events with full context

4. Correlates with previous findings:

    PsExec
    WMI
    credential access
    exfiltrator staging possibility from 4x03

**Expected Output:**

```bash
$ ./7-hunt_psremoting.sh

================================================================
   HUNT EXECUTION - H4: PowerShell Remoting
   Technique: T1021.006 Windows Remote Management
================================================================

QUERY RESULTS:
  Total PSRemoting events: [count]
  Baseline: [count]
  ANOMALOUS: [count]

ANOMALOUS EVENTS:
  [A1] [timestamp] WS-RECV-03 -> SRV-HEALTH-DB
       Enter-PSSession -ComputerName SRV-HEALTH-DB
       User: MEDDEFENSE\svc_healthsync
  [A2] [timestamp] SRV-HEALTH-DB
       Copy-Item invoked

CROSS-REFERENCE WITH 4x03:
  Copy-Item events transfer files to database servers.
  The HEALTHBANE exfiltrator from 4x03 was staged on servers with
  access to health records.

FINDING:
  Status: POSITIVE - HIGH CONFIDENCE
  PSRemoting from non-admin host using service account is consistent
  with attacker staging activity.

================================================================
```

---
