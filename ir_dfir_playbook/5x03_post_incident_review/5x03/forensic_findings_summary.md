# Forensic Findings Summary — IR-2026-0414-01 / LH-2026-0414-01

**Condensed output from 5x02 investigation. Hand-off artifact for 5x03 lessons-learned work.**

- Case: LH-2026-0414-01
- Incident: IR-2026-0414-01
- Window: 2026-04-13T18:14Z (credential phishing) through 2026-04-14T03:58Z (containment)
- Analyst: 5x02 forensic investigator
- Date of summary: 2026-04-14T09:45Z

---

## Evidence artifacts

| ID | Artifact | Format | SHA-256 (baseline) | Notes |
|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW disk image | a8f2c49d... (see CoC) | Disk, WST-WS-031 |
| ART-002 | wst-ws-031.mem | RAW memory dump | 3bc19f7e... | Memory, WST-WS-031, captured 03:02Z |
| ART-003 | wst-ws-017.mem | RAW memory dump | 90e7d14c... | Memory, WST-WS-017, captured 03:38Z |

---

## Confirmed findings (by evidence ID)

| Evidence ID | Description | ATT&CK | Certainty |
|---|---|---|---|
| ART-001-F01 | `update.xml` MSBuild inline task XML dropped to `C:\Users\dmarsh\AppData\Local\Temp\` at 2026-04-14T02:46:51Z | T1027 | confirmed |
| ART-001-F02 | `update.exe` PE dropped to same path at 02:46:53Z | T1105 | confirmed |
| ART-001-R01 | Run key `HKCU\...\Run\WindowsUpdateSvc` pointing to `update.exe`, last write 02:46:55Z | T1547.001 | confirmed |
| ART-001-R02 | Scheduled task `{7B4F2D81-...}` executing `update.exe` at user logon | T1053.005 | confirmed |
| ART-001-E01 | UserAssist for `MSBuild.exe` run count 1, last executed 2026-04-14T02:47:00Z | T1127.001 | confirmed |
| ART-002-M01 | `powershell.exe` PID 7812 direct parent of `MSBuild.exe` PID 8104, start 02:46:58Z | T1127.001 | confirmed |
| ART-002-M02 | ESTABLISHED TCP from PID 8104 to 185.220.101.47:443 (Tor exit) at capture time | T1071.001 / T1090.003 | confirmed |
| ART-002-M03 | Executable anonymous VadS region in `MSBuild.exe` PID 8104 with MZ header | T1055 | confirmed |
| ART-002-M04 | NTLM hash material for `dmarsh` present in lsass at capture | T1003.001 | confirmed |
| ART-003-M01 | `MSBuild.exe` beaconing 91.234.99.107:443 on WST-WS-017, launched via Kerberos logon from WST-WS-031 | T1550.003 | confirmed |
| AD-LOG-01 | 14 PDF reads on LIS-WSIDE-01 by `dmarsh` at 03:43:30Z, share `LIS_REPORTS$` | T1083 / T1005 | confirmed |

---

## Consolidated IOC list

| Type | Value | Context |
|---|---|---|
| IPv4 | 185.220.101.47 | Primary C2 (Tor exit, DE) |
| IPv4 | 91.234.99.107 | Secondary C2 (UA, Cobalt Strike infrastructure cluster) |
| Domain | ms0365-support.login-verification.click | Phishing typosquat, first visit 2026-04-13T18:14:02Z |
| SHA-256 | a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3 | `update.xml` MSBuild loader |
| SHA-256 | 5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b | `update.exe` PE |
| SHA-256 | 3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a | `update.zip` download from phishing site |
| Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateSvc | Persistence |
| Scheduled task | `{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}` | Persistence |

---

## ATT&CK techniques observed

Initial Access: T1566.002
Execution: T1059.001, T1127.001
Persistence: T1547.001, T1053.005
Defense Evasion: T1027, T1055
Credential Access: T1003.001, T1558.003
Lateral Movement: T1550.003
Collection: T1005
Command and Control: T1071.001, T1090.003
Discovery: T1083

---

## Scope

- Compromised account: `MEDDEFENSE\dmarsh` (Daniel Marsh)
- Compromised hosts: `WST-WS-031`, `WST-WS-017`, `LIS-WSIDE-01`
- Data categories accessed: laboratory report PDFs containing PHI (14 patients)
- No confirmed exfiltration to external C2 based on egress flow volumes — data access is confirmed, data transfer is not

---

## Open investigative items

- Origin of the compromised Office 365 session on 2026-04-13T18:14:41Z (IP 45.63.9.88, RU) — credential pair verified as phished but the session after submission not yet traced
- Review of Azure AD risk signals that were suppressed by conditional access "compliant device" rule
- Confirmation of whether any of the 14 PDFs left the network (requires DLP log review outside this engagement)

---

## Hand-off note

This summary is the authoritative input for the 5x03 lessons-learned phase. All IOCs, ATT&CK mappings, and control-effectiveness evidence should be derived from these findings and their backing artifacts in `/evidence/LH-2026-0414-01/`.
