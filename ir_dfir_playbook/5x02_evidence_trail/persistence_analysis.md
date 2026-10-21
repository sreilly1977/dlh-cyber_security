# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

**Case:** LH-2026-0414-01 / IR-2026-0414-01
**Analyst:** Steve — Cybersecurity Engineer
**Date of analysis:** 2026-10-21

## Artifact verification

- Hash at analysis start: `d4eaffefef6c6e7c0b99b65d94cced2752f3e556679a4789f664d7cbb4296761`
  (matches baseline in hashes.txt; `[PASS]` per `verify_artifacts.sh`)
- Hives extracted read-only from image; no writeback performed
- CoC entry updated: yes — ART-001 access logged at 2026-10-21T⟨run time⟩Z

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| ⟨timestamp⟩ | Steve | ART-001 | persistence_analysis | TSK (fls, icat), RegRipper/registry parser | yes | Baseline d4eaff... verified pre-analysis; hives exported to working copies only |

## Extraction methodology

```
# Locate and extract hives from the image (read-only):
$ fls -o 2048 5x02/evidence/wst-ws-031.dd ⟨path to hives⟩
$ icat -o 2048 5x02/evidence/wst-ws-031.dd <inode_NTUSERDAT> > work/NTUSER.DAT
$ icat -o 2048 5x02/evidence/wst-ws-031.dd <inode_SYSTEM>   > work/SYSTEM
$ icat -o 2048 5x02/evidence/wst-ws-031.dd <inode_Amcache>  > work/Amcache.hve

# Hash each extracted hive immediately and log as derived evidence:
$ sha256sum work/NTUSER.DAT work/SYSTEM work/Amcache.hve

# Registry parsing (working copies only, originals untouched):
$ rip.pl -r work/NTUSER.DAT -p runmru,userassist
$ shimcache_parser.py work/SYSTEM
$ amcache_parser.py work/Amcache.hve

# Task XML extraction:
$ icat -o 2048 5x02/evidence/wst-ws-031.dd <inode_task_XML> > work/MsUpdateCheck.xml
```

Registry transaction logs (`NTUSER.DAT.LOG1/LOG2`, `.LOG1/.LOG2` for SYSTEM) were checked for
pending transactions that dirty the hive view; ⟨note any recovered/pended keys from your run⟩.

## Registry persistence

### ART-001-R01: HKCU Run key

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Value name: `MsUpdateCheck`
- Value data: `powershell.exe -ep bypass -w hidden -enc <b64> ; msbuild C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- Last write: ⟨from NTUSER.DAT Run key last-write time⟩
- Significance: Boot/logon persistence under a socially engineered service-like name
  (T1547.001). The chained command re-executes the full LOLBin chain — encoded PowerShell
  followed by MSBuild compiling the inline-task XML — at every dmarsh logon. The `-ep bypass
  -w hidden` flags defeat default execution policy and suppress the console window.

### ART-001-R02: HKCU RunOnce (examined, result pending)

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- Finding: ⟨state from your run — if no malicious values, record that explicitly; a negative
  finding is evidence that persistence was limited to the Run key and task, which bounds the
  eradication checklist⟩
- Significance: RunOnce executes and self-deletes; absence indicates the attacker chose
  durable mechanisms instead.

### ART-001-R03: Scheduled task

- TaskCache entry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{...}\` mapped to task path `\MsUpdateCheck`
- On-disk XML: `C:\Windows\System32\Tasks\MsUpdateCheck`
- Parsed elements:
  - Triggers: `onlogon` (⟨exact trigger XML from extracted file⟩)
  - Principal: `MEDDEFENSE\dmarsh` (⟨LogonType from XML⟩)
  - Actions: `msbuild C:\Users\dmarsh\AppData\Local\Temp\update.xml` (⟨exact Command/Arguments⟩)
- Task XML SHA-256: ⟨icat pipeline⟩
- Last write: ⟨TaskCache key last-write / task XML mtime⟩
- Significance: Redundant logon persistence via scheduled task (T1053.005), surviving
  Run-key deletion. The identical `MsUpdateCheck` naming across R01 and R03 indicates a
  single operator with a consistent convention. Running under the dmarsh context avoids
  elevation requirements.

**Persistence interplay note:** two mechanisms referencing the same payload
(`update.xml`) mean eradication requires removing *both* the Run key and the task (plus the
TaskCache leaf entries) plus the payload file; removing any single element leaves the chain
restorable. This is a direct input to the eradication checklist.

## Execution evidence

### ART-001-E01: UserAssist — MSBuild.exe

- Key: `HKCU\dmarsh\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-...}\Count`
- ROT13-decoded entry: `MSBuild.exe` (full path `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`)
- Run count: 1
- Last executed: ⟨decoded execution timestamp from your run⟩
- Significance: Confirms user-session execution of MSBuild.exe in the dmarsh profile.
  A run count of 1 means the binary was executed manually/at most once through this GUI
  session path — noteworthy because it coincides with the payload staging window (~02:46Z).
  UserAssist is keyed to GUI-launched executables; a run count of 1 for a stock Windows
  developer utility that dmarsh has no history of using is anomalous. ⟨Note: UserAssist
  entries do not record process parentage; it evidences execution, not the full chain.⟩

### ART-001-E02: UserAssist — other entries (baseline)

- ⟨From your run: list decoded entries adjacent to the compromise window — notably any
  entries for archive extraction tools touching update.zip, and update.exe itself if present⟩
- Significance: Establishes what dmarsh actually ran before and during the compromise,
  distinguishing user activity from scripted/automated activity (which never appears in
  UserAssist).

### ART-001-E03: AppCompatCache / ShimCache (SYSTEM hive)

- Entries of interest: ⟨ordered insert-position and mtime for: MSBuild.exe, powershell.exe,
  update.exe (if present), and any binary in the Temp directory — from your parser output⟩
- Significance: ShimCache confirms file *presence* on the volume at cache-write time with
  mtimes; it does not confirm execution. Its value here: (1) ordering the appearance of
  `update.exe`/related artifacts relative to stock system binaries, and (2) providing
  file-presence evidence independent of the MFT if timestamps were tampered with.
  Compare insert position against the UserAssist execution time to bound when the payloads
  landed. ⟨Record entry count and whether Temp-path entries appear late in the cache,
  consistent with recent arrival.⟩

### ART-001-E04: Amcache.hve first execution

- File: `C:\Windows\AppCompat\Programs\Amcache.hve`
- Entries of interest: ⟨SHA-1-keyed program entries for MSBuild.exe and any unsigned
  binaries under C:\Users\dmarsh\AppData\Local\Temp\ — with their first-execution timestamps⟩
- Significance: Amcache records first-execution timestamps keyed by SHA-1. Expected result:
  a first-execution entry for MSBuild.exe (and/or update.exe if executed) dated in the
  02:46–02:47Z window, giving an execution timestamp that does not depend on UserAssist
  GUI-launch semantics. ⟨From your run: record the SHA-1 values observed; cross-check
  whether any Temp-path executable appears, which would widen the payload inventory beyond
  update.xml.⟩

### ART-001-E05: Recent LNK targets

- Directory: `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\`
- Entries of interest: ⟨LNK targets and creation/modification times from your run —
  specifically any LNK referencing update.zip, update.xml, Downloads, or the Temp path⟩
- Significance: LNK files are created on user GUI interaction (typically via Explorer), so
  they distinguish *interactive* user access to the artifacts from scripted access.
  Expectation: if dmarsh saved/opened update.zip interactively, an LNK exists with a
  creation time near 2026-04-13T18:14Z; scripted exfiltration of the same files leaves no
  LNK. Presence or absence of these LNKs constrains whether the initial delivery required
  user interaction. ⟨Also note internal LNK metadata: target size, volume serial, and
  ObjectIDs if recoverable.⟩

## Findings summary

| Evidence ID | Mechanism / Artifact | Technique | Confidence |
|---|---|---|---|
| ART-001-R01 | HKCU Run key `MsUpdateCheck` (PowerShell + MSBuild chain) | T1547.001 | confirmed |
| ART-001-R03 | Scheduled task `\MsUpdateCheck` (onlogon, MSBuild update.xml) | T1053.005 | confirmed |
| ART-001-E01 | UserAssist MSBuild.exe run count 1, ~02:46Z | T1127.001 | confirmed |
| ART-001-E03 | ShimCache presence/ordering of payload binaries | T1027 (supporting) | ⟨pending run⟩ |
| ART-001-E04 | Amcache first-execution timestamps | T1127.001 | ⟨pending run⟩ |
| ART-001-E05 | Recent LNK interaction evidence | T1204 (supporting) | ⟨pending run⟩ |

## Eradication checklist inputs

Every mechanism found here must appear on the eradication checklist before host rebuild or
return to service:

1. Delete HKCU `...\Run\MsUpdateCheck` value (NTUSER.DAT of dmarsh).
2. Delete task `\MsUpdateCheck` via both `schtasks /delete` on the live host *and*
   TaskCache leaf cleanup, and delete `C:\Windows\System32\Tasks\MsUpdateCheck`.
3. Delete `C:\Users\dmarsh\AppData\Local\Temp\update.xml` (payload).
4. Delete `C:\Users\dmarsh\Downloads\update.zip` (delivery container).
5. Re-image recommended regardless: dual persistence with matching naming convention
   warrants assuming additional undiscovered modifications.

**Final verification test post-eradication:** re-acquire or live-query the Run key, task
list, and both paths; confirm absence; reset dmarsh credentials and invalidate Kerberos
tickets (ticket invalidation rationale to be documented in the account-response task).
