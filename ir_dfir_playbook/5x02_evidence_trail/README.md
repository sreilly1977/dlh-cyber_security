# Introduction

> "Every contact leaves a trace."
>
> — Edmond Locard

Containment answered whether the threat was stopped. Forensics answers what actually happened: how the attacker got in, what they did, what they accessed, and how to prove it.

Helena Reyes, MedDefense's General Counsel, has placed a litigation hold on all evidence from the incident. Dr. Patricia Morales needs a report she can present to the board. The findings will drive the HIPAA breach notification assessment. Depending on what you uncover, this report may end up cited in a regulatory proceeding.

From this point forward, every artifact you analyze must be verified before you touch it, every action recorded in the chain of custody, and every conclusion tied to a specific evidence reference. The standard is not "probably happened." The standard is "supported by documented evidence."

In this project you work through a full forensic investigation: you verify artifact integrity, hunt the filesystem for attacker footprints, extract persistence mechanisms from the registry, analyze memory with Volatility 3, correlate the full attack timeline, assess the regulatory impact, and deliver a forensic report with two audiences — technical and executive.

## Why this matters

Digital forensics is the bridge between "the incident happened" and "we can prove exactly what happened." In healthcare, finance, legal, and regulated industries, the forensic report is what drives breach notifications, insurance claims, regulatory responses, and sometimes criminal referrals. Getting it wrong has direct consequences: facts asserted without evidence, chains of custody that cannot be defended, breach scope underestimated, all of these create organizational and legal exposure far beyond the incident itself.

Analysts who can read a disk image, extract and interpret memory artifacts, correlate a multi-source timeline, and write a report that survives external scrutiny are rare. Most security teams can detect. Fewer can prove. This capability leads to senior IR positions, forensic specialist roles, and the kind of trust that comes with being the person leadership calls when something serious has happened.

It is also the skill that keeps well-meaning analysts from becoming the problem by touching evidence without a plan, losing chain of custody, or drawing conclusions the evidence cannot support.

## Context

The incident on WST-WS-031 is contained. The active threat has been remediated. Now the harder question begins: what exactly happened, and how far did it go?

Helena Reyes has issued a formal litigation hold referencing case number LH-2026-0414-01. James Chen has authorized the forensic phase and assigned it to you. Three artifacts were acquired during the response: a disk image from WST-WS-031 and memory dumps from WST-WS-031 and WST-WS-017. All three are waiting in the evidence store, unanalyzed.

Dr. Morales's deadline for the board briefing is 72 hours. The forensic report must be complete, referenced, and defensible. If you cannot tie a finding to an artifact, it does not go in the report.

---

# 0. Quiz

---

# [1. Open the Chain of Custody Log](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x02_evidence_trail/chain_of_custody.md)

## Goal: 

Create the evidence spine of the investigation before touching any artifact.

## Context: 

Chain of custody is continuous. It does not begin when you open the first artifact. It began at acquisition.

## Instructions: 

Create chain_of_custody.md. This document is append-only for the duration of the investigation. Every artifact and every access event is logged here.

    Review acquisition_notes.md before creating the artifact registry. Use acquisition timestamps, tools, and handling notes from the acquisition record when populating chain-of-custody details.

Required structure:

    Case header: case number (LH-2026-0414-01), incident ID (IR-2026-0414-01), lead investigator, date opened, litigation hold reference.

    Artifact registry table with columns: Artifact ID, Artifact Name, Format, Acquired By, Acquisition Timestamp (UTC), Acquisition Tool, SHA-256 at Acquisition, Storage Path, Access Controls.

    Access log table with columns: Timestamp (UTC), Actor, Artifact ID, Action (e.g., hash_verify, read_only_mount, export_section), Tool Used, Hash Verified (yes/no), Notes.

Rules:

    Compute and record SHA-256 for each artifact before the first analysis access.

    Every subsequent access adds a new access log row, regardless of how brief.

    Deviations from the expected hash value at any access event are flagged immediately and appended as a DEVIATION note.

**Expected output**

<pre>
# Chain of Custody: `<case_number>`

## Case Header

- **Case number:** `<case_number>`
- **Incident ID:** `<incident_id>`
- **Lead investigator:** `<your_name>`
- **Date opened:** `<YYYY-MM-DD>`
- **Litigation hold reference:** `Memo from Helena Reyes, 2026-04-14T07:30Z`

## Artifact Registry
</pre>

| Artifact ID | Name | Format | Acquired By | Acquired At (UTC) | Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW | Mike Torres | 2026-04-14T04:51Z (start) – 06:14Z (complete) | FTK Imager | **NOT COMPUTED AT ACQUISITION** — baseline to be established at first forensic access | `\\evidence\share\IR-2026-0414-01\wst-ws-031.dd` | read-only, IR team only |
| ART-002 | wst-ws-031.mem | RAW | Mike Torres | 2026-04-14T03:02Z | WinPmem v3.3-rc3 | **NOT COMPUTED AT ACQUISITION** — baseline to be established at first forensic access | `\\evidence\share\IR-2026-0414-01\wst-ws-031.mem` | read-only, IR team only |
| ART-003 | wst-ws-017.mem | RAW | Mike Torres | 2026-04-14T03:38Z | WinPmem v3.3-rc3 | **NOT COMPUTED AT ACQUISITION** — baseline to be established at first forensic access | `\\evidence\share\IR-2026-0414-01\wst-ws-017.mem` | read-only, IR team only |

<pre>
## Access Log
</pre>

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| <timestamp> | <your_name> | <ART-ID> | <action> | <tool> | <yes/no> | Baseline established; hash stored in <file> |
| ... | ... | ... | ... | ... | ... | ... |

---

# [2. Verify All Artifacts](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x02_evidence_trail/verify_artifacts.sh)

## Goal: 

Establish a cryptographic baseline for every artifact before any analysis begins.

## Context: 

Every analysis session starts with a hash check. If the hash does not match, the session does not start.

## Instructions: 

Write verify_artifacts.sh. The script runs before every analysis session.

It must:

    Compute SHA-256 for each of the three provided artifacts

    Compare each computed hash against the corresponding baseline value stored in hashes.txt

    Print [PASS] or [FAIL] with the artifact name and both hash values (expected and computed)

    Append a verification event to verification_log.txt with the timestamp, actor, artifact ID, result, and both hash values

    Exit 0 only if all three artifacts pass; exit non-zero on any failure

On first run (baseline establishment), the script detects that hashes.txt does not yet exist, computes hashes for all three artifacts, writes hashes.txt, and sets all artifacts to BASELINE_SET status instead of PASS or FAIL.

    Before beginning disk analysis, review siem_alert_export.json. Treat it as the original SOC detection context only. Use findings from disk artifacts to confirm or refute SIEM indicators rather than assuming they are correct.

**Expected output**

```bash
$ ./verify_artifacts.sh
[BASELINE_SET] ART-001 wst-ws-031.dd  sha256=a8f2c49d...
[BASELINE_SET] ART-002 wst-ws-031.mem sha256=3bc19f7e...
[BASELINE_SET] ART-003 wst-ws-017.mem sha256=90e7d14c...
Baseline written to hashes.txt. Run again to verify.

$ ./verify_artifacts.sh
[PASS] ART-001 wst-ws-031.dd  expected=a8f2c49d... computed=a8f2c49d...
[PASS] ART-002 wst-ws-031.mem expected=3bc19f7e... computed=3bc19f7e...
[PASS] ART-003 wst-ws-017.mem expected=90e7d14c... computed=90e7d14c...
ALL ARTIFACTS VERIFIED
```

---

# [3. Filesystem Timeline Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x02_evidence_trail/filesystem_analysis.md)

## Goal: 

Reconstruct the sequence of attacker activity from disk artifacts.

## Context: 

The filesystem records when files were created, modified, and accessed. That sequence is the attacker's footprint.

## Instructions: 

Create filesystem_analysis.md documenting a complete TSK-based analysis of wst-ws-031.dd.

Mount the image read-only before any analysis. Run at minimum the following commands and document the output:

    mmls wst-ws-031.dd:: identify partition layout and sector offset for the main NTFS volume

    fsstat -o <offset> wst-ws-031.dd: filesystem metadata, volume serial number, last mount time

    fls -r -o <offset> wst-ws-031.dd > fls_output.txt: recursive file listing with inode numbers and flags

    mactime -b fls_output.txt -d > mac_timeline.csv: MAC time body converted to a sortable timeline

    icat -o <offset> wst-ws-031.dd <inode>: extract individual files of interest for further analysis

Examine and document these paths specifically:

    C:\Users\dmarsh\AppData\Local\Temp\: staging and execution artifacts

    C:\Windows\System32\Tasks\: scheduled task XML files

    C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\: LNK files showing accessed items

    C:\Users\dmarsh\AppData\Local\Microsoft\Windows\History\: browser history

For each suspicious file or artifact found: full path, MAC times, size in bytes, SHA-256 hash, forensic significance.

**Expected output**

<pre>
# Filesystem Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification

- Hash at analysis start: a8f2c49d... (matches baseline in hashes.txt)
- Mounted read-only: <yes/no>
- CoC entry updated: <yes/no>, <ART-ID> access logged at <timestamp>

## Partition layout

$ mmls wst-ws-031.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0125827071   0125825024   NTFS / exFAT (0x07)

Offset used for NTFS analysis: 2048

## Filesystem metadata

$ fsstat -o 2048 wst-ws-031.dd
FILE SYSTEM INFORMATION
...

## Key findings

### ART-001-F01: Malicious MSBuild staging file

- Path: C:\path\to\update.xml
- Created: <timestamp>
- Modified: <timestamp>
- Accessed: <timestamp>
- Size: <size> bytes
- SHA-256: <hash>
- Significance: MSBuild inline task XML; contains Base64-encoded C# shellcode loader; correlates with msbuild.exe execution at <time_zulu>

### ART-001-F02: Second-stage dropped payload
...

### ART-001-F03: Scheduled task persistence
...
</pre>

---

# [4. Registry and Persistence Artifact Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x02_evidence_trail/persistence_analysis.md)

## Goal: 

Find every mechanism the attacker installed to survive reboots.

## Context: 

Persistence is the attacker's insurance policy. Every mechanism found is a gap in the eradication checklist.

## Instructions: 

Create persistence_analysis.md. Extract and mount the registry hives from wst-ws-031.dd and examine the following:

    HKCU\Software\Microsoft\Windows\CurrentVersion\Run and RunOnce: startup entries for the dmarsh user profile

    C:\Windows\System32\Tasks\: scheduled task XML files; parse each XML for triggers, actions, and principal

    NTUSER.DAT UserAssist key: decoded execution evidence for the dmarsh user profile; note run counts and last execution times

    AppCompatCache / ShimCache from SYSTEM hive: ordered list of executables observed on the system, useful for confirming execution without log evidence

    Amcache.hve from C:\Windows\AppCompat\Programs\Amcache.hve: first execution timestamps for binaries, keyed by SHA-1 hash

    C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\: LNK file targets showing what dmarsh opened before and during the compromise

For each finding: registry key or file path, value name, value data, last write timestamp, forensic significance, evidence ID.

**Expected output**

<pre>
# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification

- Hash at analysis start: a8f2c49d... (matches baseline)
- CoC entry updated: yes, ART-001 access logged at 2026-04-14T09:05Z

## Registry persistence

### ART-001-R01: Run key

- Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Value name: WindowsUpdateSvc
- Value data: C:\Users\path\toupdate.exe
- Last write: <timestamp>
- Significance: ...

### ART-001-R02: Scheduled task
...

## Execution evidence

### ART-001-E01: UserAssist - msbuild.exe

- Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\...
- Value: MSBuild.exe
- Run count: 1
- Last executed: <timestamp>
- Significance: Confirms user-session execution of MSBuild.exe consistent with alert time

### ART-001-E02: Amcache first execution
...
</pre>

---

# [5. Memory Analysis with Volatility 3](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x02_evidence_trail/memory_analysis.md)

## Goal: 

Extract the attacker's in-memory activity at the moment of acquisition.

## Context: 

Some evidence exists only in memory. The process that ran, the connection it held, the credential it touched, these do not survive on disk.

## Instructions: 

Create memory_analysis.md. Using wst-ws-031.mem, run each Volatility 3 plugin below and document: the exact command, the relevant portion of the output, and what the output means for the incident.

Run all plugins on wst-ws-031.mem. For wst-ws-017.mem, run windows.pslist, windows.netscan, and windows.cmdline at minimum and document any additional findings.

    The same process-chain evidence may appear in siem_alert_export.json. Use SIEM evidence only as investigative context; conclusions must come from Volatility findings.

Plugins required for wst-ws-031.mem:

    vol -f wst-ws-031.mem windows.pslist.PsList: full process list with PID, PPID, create time

    vol -f wst-ws-031.mem windows.pstree.PsTree: process parent-child tree

    vol -f wst-ws-031.mem windows.cmdline.CmdLine: command line arguments for each process

    vol -f wst-ws-031.mem windows.netscan.NetScan: active and recently closed network connections with owning PID

    vol -f wst-ws-031.mem windows.dlllist.DllList --pid <msbuild_pid>: DLLs loaded by msbuild.exe

    vol -f wst-ws-031.mem windows.malfind.Malfind: executable memory regions with suspicious properties; note any matching msbuild.exe PID

    vol -f wst-ws-031.mem windows.handles.Handles --pid <lsass_pid>: handles held by lsass.exe during capture

    vol -f wst-ws-031.mem windows.hashdump.Hashdump: NTLM hashes from SAM and LSA secrets

For each plugin: note the finding, the PID(s) involved, and the forensic conclusion. Tag each finding with a certainty level (confirmed, probable, possible) and an ATT&CK technique where applicable.

**Expected output**

<pre>
# Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)

## Artifact verification

- ART-002 hash: 3bc19f7e... (matches baseline)
- ART-003 hash: 90e7d14c... (matches baseline)
- CoC entries updated: yes

## wst-ws-031.mem findings

### ART-002-M01: Suspicious process tree

$ vol -f wst-ws-031.mem windows.pstree.PsTree
...
* 7812  powershell.exe   PPID=<explorer_ppid>  Start: <timestamp>
** 8104  MSBuild.exe      PPID=7812             Start: <timestamp>

Significance: Confirms alert; powershell.exe is direct parent of MSBuild.exe
ATT&CK: T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild)
Certainty: confirmed

### ART-002-M02: Live C2 connection at time of capture

$ vol -f wst-ws-031.mem windows.netscan.NetScan
...
TCP  10.14.22.31:49832  185.220.101.47:443  ESTABLISHED  PID 8104  MSBuild.exe

Significance: Active C2 connection to known Tor exit relay in-memory at acquisition time
ATT&CK: T1071.001
Certainty: confirmed

### ART-002-M03: Injected executable memory in msbuild.exe

$ vol -f wst-ws-031.mem windows.malfind.Malfind
...
PID 8104  MSBuild.exe  Start: 0x1f0000  End: 0x1f4fff  Tag: VadS  Protection: PAGE_EXECUTE_READWRITE
Hexdump: 4d 5a 90 00 03 00 00 00 ... (MZ header present in anonymous region)

Significance: MZ/PE header in an executable anonymous memory region within MSBuild.exe confirms code injection
ATT&CK: T1055 (Process Injection)
Certainty: confirmed

### ART-002-M04: NTLM hash exposure
...

## wst-ws-017.mem findings
...
</pre>

---

# [6. Correlated Incident Timeline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x02_evidence_trail/correlated_timeline.md)

## Goal: 

Assemble all evidence sources into one timeline that no single source could produce alone.

## Context: 

Disk evidence, memory evidence, authentication logs, and proxy logs each tell part of the story. The correlation is the investigation.

## Instructions: 

Create correlated_timeline.md. Draw from all findings in Tasks 3, 4, and 5 plus the provided supplementary logs (proxy log and AD authentication log).

    Use proxy_log.jsonl, ad_auth_log.jsonl, and siem_alert_export.json as supplementary evidence sources during correlation. Timeline entries should reference findings from prior tasks whenever possible rather than relying solely on raw logs.

For each event in the timeline, record:

    timestamp (UTC, ISO 8601)

    source (artifact ID and log type)

    event (one-line description)

    att_ck_technique (T-number if applicable)

    certainty (one of confirmed, probable, possible)

    evidence_ref (the artifact ID and finding ID that supports this event)

Minimum events to include:

    Credential phishing link clicked (proxy log)

    Credentials submitted to typosquat domain

    Attacker VPN access using dmarsh credentials

    powershell.exe execution with encoded payload

    msbuild.exe spawned by PowerShell (C2 beacon starts)

    Malicious files dropped to AppData\Local\Temp

    Scheduled task and Run key persistence installed

    NTLM hash and Kerberos ticket material accessible in lsass.exe

    Kerberos TGS request for cifs/WST-WS-017

    Lateral movement logon to WST-WS-017

    Second C2 beacon from WST-WS-017

    Kerberos TGS request for cifs/LIS-WSIDE-01

    Logon to LIS-WSIDE-01

    14 patient lab report PDFs read on LIS-WSIDE-01

**Expected output**

<pre>
# Correlated Incident Timeline: LH-2026-0414-01
</pre>

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
| --- | --- | --- | --- | --- | --- |
| <timestamp> | <source> | <description> | <T_number> | <confirmed/probable/possible> | <ID> line <number> |
| <timestamp> | <source> | <description> | <T_number> | <confirmed/probable/possible> | <ID> line <number> |
| <timestamp> | <source> | <description> | <T_number> | <confirmed/probable/possible> | <ID> line <number> |
| <timestamp> | <source> | <description> | <T_number> | <confirmed/probable/possible> | <ID> line <number> |
| <timestamp> | <source> | <description> | <T_number> | <confirmed/probable/possible> | <ID> line <number> |
| … | … | … | … | … | … |

---
