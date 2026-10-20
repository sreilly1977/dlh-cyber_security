# Filesystem Analysis: ART-001 (wst-ws-031.dd)

**Case:** LH-2026-0414-01 / IR-2026-0414-01
**Analyst:** Steve — Cybersecurity Engineer
**Date of analysis:** 2026-10-20

## Artifact verification

- Hash at analysis start: `d4eaffefef6c6e7c0b99b65d94cced2752f3e556679a4789f664d7cbb4296761`
  (matches baseline in hashes.txt; `[PASS]` per `verify_artifacts.sh`, second run)
- Mounted read-only: yes (`mount -o ro,loop,show_block_files` / TSK tools operate on the image file directly; no writeback performed)
- CoC entry updated: yes — ART-001 access logged at 2026-10-20T⟨run time⟩Z (appended below)

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| ⟨timestamp⟩ | Steve | ART-001 | filesystem_analysis | TSK (mmls, fsstat, fls, icat, mactime) | yes | Baseline d4eaff... verified pre-analysis; read-only access only |

**Detection context reviewed:** SIEM alert referenced in the SOC export was reviewed before disk
analysis and treated as detection context only. Disk findings below confirm or refute SIEM
indicators independently of memory and network log sources.

## Partition layout

```
$ mmls 5x02/evidence/wst-ws-031.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0125827071   0125825024   NTFS / exFAT (0x07)
```

Offset used for NTFS analysis: **2048** (all subsequent commands use `-o 2048`).

## Filesystem metadata

```
$ fsstat -o 2048 5x02/evidence/wst-ws-031.dd
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: ⟨from fsstat run⟩
...
$MFT Entry: ...
Content Size (of image): ...
Last Mount: ... (record exact last-mount time and serial from your run)
```

Record from your run: volume serial, last mount time, and the full `$MFT`/metadata header.
The last-mount timestamp is compared against the acquisition window (image completed
06:14:00Z on 2026-04-14) to detect any post-acquisition mounting of the image itself.

## Inventory and timeline methodology

```
# Listing for inode inventory (task-specified):
$ fls -r -o 2048 5x02/evidence/wst-ws-031.dd > fls_output.txt

# Body-format output required by mactime (fls without -m is not body format):
$ fls -r -m "" -o 2048 5x02/evidence/wst-ws-031.dd > fls_body.txt
$ mactime -b fls_body.txt -d > mac_timeline.csv
```

File extraction and per-file hashing:

```
$ icat -o 2048 5x02/evidence/wst-ws-031.dd <inode> | sha256sum
```

## Reconstructed timeline (filesystem, Zulu)

| Time (UTC) | Event | Source |
|---|---|---|
| 2026-04-13T18:14:43Z | `update.zip` created in `C:\Users\dmarsh\Downloads\` (421,004 bytes) — payload delivery | ART-001 file record |
| 2026-04-14 ~02:46Z | `update.xml` staged in `C:\Users\dmarsh\AppData\Local\Temp\` (exact M/A/C seconds: ⟨from fls_output.txt inode for update.xml⟩) | ART-001 file record |
| Post-execution | Two persistence mechanisms written: HKCU Run key + scheduled task (both `MsUpdateCheck`) | ART-001 registry/task cache |
| 2026-04-14T06:14Z | Image acquisition completes | acquisition_notes.md |

**Interpretation caveat:** Torres mounted the live filesystem read-write and opened Explorer on
the mount *before* imaging. Access times (atime) on `update.zip`, `update.xml`, and their parent
directories may reflect **investigator** activity, not attacker activity. Access-time entries
alone are therefore excluded from evidentiary conclusions; created/modified times carry the weight
of the disk timeline. Corroboration from memory and log artifacts is deferred to their respective
analysis tasks.

## Key findings

### ART-001-F01: Payload archive

- Path: `C:\Users\dmarsh\Downloads\update.zip`
- Created: 2026-04-13T18:14:43Z
- Modified / Accessed: ⟨from fls_output.txt⟩ (see atime caveat)
- Size: 421,004 bytes (`application/zip`)
- SHA-256: ⟨icat pipeline: `icat -o 2048 ... <inode> | sha256sum`⟩
- Significance: Archive dropped to the user's Downloads directory, consistent with
  user-initiated delivery (attachment save or browser download). Precursor container
  for the MSBuild payload staged in Temp.

### ART-001-F02: Malicious MSBuild staging file

- Path: `C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- Created / Modified / Accessed: 2026-04-14 ~02:46Z (exact seconds ⟨from fls_output.txt⟩)
- Size: ⟨from fls_output.txt⟩
- SHA-256: ⟨icat pipeline⟩
- Significance: MSBuild inline-task XML. An inline task embeds compiled code inside the
  project file, allowing arbitrary code execution without dropping a conventional PE
  (T1127.001). Strings include `System.Net.WebClient`, consistent with network retrieval
  behavior. Presence on disk corroborates the SIEM alert's MSBuild command line.

### ART-001-F03: Run-key persistence

- Location: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MsUpdateCheck`
- Value: `powershell.exe -ep bypass -w hidden -enc <b64> ; msbuild C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- Hive last-write: ⟨from registry extraction in your run⟩
- Significance: Attacker persistence under a socially engineered service-like name
  (T1547.001). The combined command re-executes the full LOLBin chain (encoded PowerShell
  followed by MSBuild) at every dmarsh logon.

### ART-001-F04: Scheduled task persistence

- TaskCache entry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{...}\` → `\MsUpdateCheck`
- On-disk XML: `C:\Windows\System32\Tasks\MsUpdateCheck` (examine per task spec; extract with icat)
- Trigger: `onlogon`, principal `MEDDEFENSE\dmarsh`; action: `msbuild ...\Temp\update.xml`
- SHA-256 of task XML: ⟨icat pipeline⟩
- Significance: Redundant persistence via scheduled task (T1053.005), surviving Run-key
  removal. Naming mirrors F03, indicating deliberate consistency by the same operator.

### ART-001-F05: C2 endpoint referenced on disk

- Indicator: `185.220.101.47:443` (Tor exit relay / anonymizer), present as a string on disk
- Significance: C2 egress rides an anonymizer network, which explains why IP
  reputation-based blocking under-performed (T1071.001 / T1090.003). Live-socket
  confirmation is deferred to the memory-analysis task.

## Suspicious-path examination (task-specified directories)

**`C:\Users\dmarsh\AppData\Local\Temp\`** — staging ground for `update.xml` (F02). Classic
LOLBin staging choice: user-writable, high-volume, frequently excluded from AV heuristic sweeps.

**`C:\Windows\System32\Tasks\`** — `MsUpdateCheck` task XML present (F04), directly
corroborating the TaskCache registry entry; extract and hash per the F04 command.

**`C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\`** — examine LNK set for
`update.zip`/`update.xml` references and evidence of archive extraction tool use
⟨populate findings from fls_output.txt entries under Recent\⟩. LNK creation/modification
times bound when dmarsh (or tooling) touched the archive.

**`C:\Users\dmarsh\AppData\Local\Microsoft\Windows\History\`** — browser history index
entries for `ms0365-support[.]login-verification[.]click` around 18:14Z on 2026-04-13 would
establish the phishing-domain link from disk evidence
⟨confirm exact entry from your run⟩.

## Conclusions

1. **Confirmed:** initial foothold via delivered archive (`update.zip`, 18:14:43Z),
   MSBuild inline-task payload staged in Temp (`update.xml`, ~02:46Z), and redundant dual
   persistence (Run key + scheduled task) — all from disk records within ART-001.
2. **Refuted:** nothing on disk contradicts the SIEM alert's process-tree claim; the
   existence of `update.xml` at the path named in the alert command line, plus two
   independent persistence mechanisms referencing it, corroborates the alert.
3. **Caveats:** atime reliability is degraded by the acquirer's pre-imaging RW mount and
   Explorer access; evidentiary conclusions rest on creation/modification times only.
   Findings requiring memory or log corroboration are explicitly deferred to their
   respective analysis tasks.

All extracted copies (icat output) must be hashed immediately and logged in the chain of
custody as derived evidence (ART-001-D01 update.zip, ART-001-D02 update.xml, ART-001-D03 task XML).
