#!/bin/bash
# Name: 0-evidence_index.sh
# Purpose: Catalog every evidence source in the 4x05 HEALTHBANE reconstruction
#          package (previous_findings/, ir_evidence/, reference/): assess
#          reliability, temporal coverage and key content per source; render
#          an evidence-type vs time-period coverage matrix; identify temporal
#          gaps, domain gaps and cross-source discrepancies; derive the
#          critical questions the reconstruction must answer.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

ROOT="${1:-.}"
ROOT="${ROOT%/}"
ANALYST=Steve
TODAY="$(date +%Y-%m-%d)"
MISSING=0

printf '================================================================\n'
printf '   EVIDENCE INVENTORY - HEALTHBANE Reconstruction\n'
printf '   Analyst: %s    Date: %s\n' "$ANALYST" "$TODAY"
printf '================================================================\n\n'

# ---------------------------------------------------------------------------
# Package structure check
# ---------------------------------------------------------------------------
for d in previous_findings ir_evidence reference; do
  if [[ ! -d "$ROOT/$d" ]]; then
    printf 'WARNING: expected directory missing: %s/%s\n\n' "$ROOT" "$d"
    MISSING=$((MISSING + 1))
  fi
done

# ---------------------------------------------------------------------------
# Evidence catalog.
# All KEY strings are single-quoted on purpose: content includes dollar signs
# (RC4 key, mutex) and backslashes (registry paths) that must not expand.
# ---------------------------------------------------------------------------
declare -A PHASE TYPE COVER RELI KEY

FILES=(
  'previous_findings/4x00_phishing_summary.txt'
  'previous_findings/4x01_network_timeline.txt'
  'previous_findings/4x02_attack_mapping.json'
  'previous_findings/4x03_malware_summary.txt'
  'previous_findings/4x04_hunting_report.txt'
  'ir_evidence/memory_artifacts.txt'
  'ir_evidence/disk_forensics_report.txt'
  'ir_evidence/firewall_sessions_ws_recv_03.json'
  'ir_evidence/ir_team_notes.txt'
  'reference/attck_navigator_80pct.json'
  'reference/healthbane_ioc_master.json'
  'reference/meddefense_asset_inventory.txt'
  'reference/network_topology.txt'
)

PHASE['previous_findings/4x00_phishing_summary.txt']='4x00 (Phishing Dissection)'
TYPE['previous_findings/4x00_phishing_summary.txt']='Email analysis findings (derived)'
COVER['previous_findings/4x00_phishing_summary.txt']='2026-04-14 to 2026-04-21 (Week 11 campaign window)'
RELI['previous_findings/4x00_phishing_summary.txt']='MEDIUM (derived summary, not raw evidence)'
KEY['previous_findings/4x00_phishing_summary.txt']='8 emails analyzed, 3 confirmed malicious (portal password reset, HR benefits, M365 quota); lookalike domains with SPF hardfail / DKIM missing / DMARC fail; dmarsh credential submission 2026-04-14T13:18:42Z, AD rotation 13:20Z (17-min window); cautions that Stage 2 dropper delivery via the same recipient pool was invisible to 4x00 evidence.'

PHASE['previous_findings/4x01_network_timeline.txt']='4x01 (Network Forensics)'
TYPE['previous_findings/4x01_network_timeline.txt']='PCAP-derived network timeline'
COVER['previous_findings/4x01_network_timeline.txt']='2026-04-14T00:00Z to 2026-04-16T00:00Z (48h PCAP window)'
RELI['previous_findings/4x01_network_timeline.txt']='MEDIUM (derived timeline, raw PCAPs not in package)'
KEY['previous_findings/4x01_network_timeline.txt']='Dropper email 2026-04-15T08:43:18Z (E1B invoice docm released from quarantine); RAT download from update.healthbane-c2.net 08:51:11Z; first C2 beacon 08:51:38Z; 5-min beacon cadence, JA3 72a589da586844d7f0818ce684948eea; DNS exfil test pings T-150/T-151 to 185.220.101.46; documents 4-second PCAP-vs-firewall skew and the Apr 16 - May 02 collection gap.'

PHASE['previous_findings/4x02_attack_mapping.json']='4x02 (Intelligence Analysis)'
TYPE['previous_findings/4x02_attack_mapping.json']='Intelligence / ATT&CK mapping (Navigator layer 4.2)'
COVER['previous_findings/4x02_attack_mapping.json']='Threat-model wide; MedDefense observations through 2026-04-21'
RELI['previous_findings/4x02_attack_mapping.json']='MEDIUM (advisory + feed synthesis, consolidated layer)'
KEY['previous_findings/4x02_attack_mapping.json']='29-technique HEALTHBANE threat model: 11 OBSERVED / 5 INFERRED / 13 NOT COVERED (38 percent observed, 55 percent mapped); HC3-2026-HEALTHBANE-001/002 mapping; baseline against which 4x03/4x04 upgrades are measured.'

PHASE['previous_findings/4x03_malware_summary.txt']='4x03 (Malware Triage)'
TYPE['previous_findings/4x03_malware_summary.txt']='Malware capability / behavioral analysis'
COVER['previous_findings/4x03_malware_summary.txt']='2026-04-22 to 2026-05-02 (triage period)'
RELI['previous_findings/4x03_malware_summary.txt']='MEDIUM (derived from sandbox triage of three samples)'
KEY['previous_findings/4x03_malware_summary.txt']='Capability matrix for S1 dropper (XOR-0x37 + base64 chain, gated PersistViaTask branch), S2 RAT (RC4 key, checkin verbs ps/fs/cmd/drop/noop, mutex HealthSyncSingleton-h$lthb4n3, gated keylogger and cookie harvest NOT used), S3 exfiltrator (SQL template tailored to SRV-HEALTH-DB schema, c2_post and dns_chunk channels); YARA rules plus Wazuh 100090/100091 deployed; marks dropper task branch and S3 usage as UNCONFIRMED pending 4x05.'

PHASE['previous_findings/4x04_hunting_report.txt']='4x04 (Proactive Threat Hunt)'
TYPE['previous_findings/4x04_hunting_report.txt']='SIEM hunt findings (Wazuh / Sysmon derived)'
COVER['previous_findings/4x04_hunting_report.txt']='2026-05-04 to 2026-05-18 (14-day hunt window)'
RELI['previous_findings/4x04_hunting_report.txt']='MEDIUM (derived from primary Sysmon/4624 telemetry, not the raw JSONL)'
KEY['previous_findings/4x04_hunting_report.txt']='Hunt H1-H5 confirmed Stage 4: 6 PsExec + 5 WMI + 4 PSRemoting events, sole source WS-RECV-03 against SRV-HEALTH-DB / SRV-INS-DB / SRV-DC-01; 2 LSASS dumps by debug_tool.exe (2026-05-05, 2026-05-12, access 0x1010); 6 NTLM svc_healthsync auth events violating the Kerberos-only service-account matrix; Robert Kim baseline comparison; detection rules wlb_ntlm_offhours, wlb_psexec_nonadmin_source, wlb_lsass_nonsystem, wlb_svc_workstation; deliberately excluded persistence, staging, anti-forensics and firewall views.'

PHASE['ir_evidence/memory_artifacts.txt']='4x05-IR (Memory Forensics)'
TYPE['ir_evidence/memory_artifacts.txt']='Volatile memory analysis (WinPmem / Volatility)'
COVER['ir_evidence/memory_artifacts.txt']='Capture 2026-05-15 14:18:42 CDT; retrospective lookback to boot 2026-04-22T06:14:17Z (23 days)'
RELI['ir_evidence/memory_artifacts.txt']='HIGH (primary forensic capture, chain of custody MD-IR-2026-05-15-001, peer-reviewed)'
KEY['ir_evidence/memory_artifacts.txt']='PID 3712 svchost_update.exe with forged PPID and RWX PE region, in-memory hash matches 4x03 S2; ESTABLISHED connections to 185.220.101.45:443 and NEW secondary C2 203.0.113.47:8443 (HB-IOC-NEW-001, PROBABLE); Run-key K1 (2026-04-22 06:14:47Z), TaskCache entry K2 for scheduled task created 2026-05-07 01:47:33 CDT, Defender exclusion K5 for C:\Windows\Temp (2026-05-04 18:11 CDT, records03 SID); recovered exfiltrator config fragment with clear_logs:true and channel c2_post; stale debug_tool.exe LSASS handles (0x1010); ws-RECV-03 isolation state at capture.'

PHASE['ir_evidence/disk_forensics_report.txt']='4x05-IR (Disk Forensics)'
TYPE['ir_evidence/disk_forensics_report.txt']='Disk image analysis (FTK / Autopsy, E01 verified)'
COVER['ir_evidence/disk_forensics_report.txt']='Image 2026-05-15 19:45 CDT; USN journal range 2026-04-22T06:14:18Z to 2026-05-15T19:45:11Z'
RELI['ir_evidence/disk_forensics_report.txt']='HIGH (primary forensic image, chain of custody MD-IR-2026-05-15-002, hash-verified E01, peer-reviewed)'
KEY['ir_evidence/disk_forensics_report.txt']='Allocated artifacts F1-F5 (RAT at APPDATA HealthSync, debug_tool.exe in C:\Windows\Temp, scheduled-task XML, signed PsExec64.exe in C:\Users\Public\Tmp, sync_healthdata.ps1); deleted artifacts D1-D5 carved from $MFT residue: staging_export_001.zip (47 138 patient records), staging_export_002.zip (51 002 insurance records), query_results.csv (1 184 AD users), partial LSASS dump out.dat (svc_healthsync strings), exfiltrator config hb_cfg.json (clear_logs:true, c2_post); scheduled task hidden=true created 2026-05-07 01:47:33 CDT via schtasks (single run), encoded PowerShell action; prefetch run-times for PsExec64 / WMIC / debug_tool / schtasks; $MFT timeline including Defender exclusion 2026-05-04 and the 12-minute Security.evtx gap 2026-05-09 03:00-03:12 CDT; anti-forensics assessment (basic deletion/log-clear, no VSS/USN/prefetch deletion); new IOCs HB-IOC-NEW-002 through NEW-005; open items OPEN-A/B/C.'

PHASE['ir_evidence/firewall_sessions_ws_recv_03.json']='4x05-IR (Network / Firewall Evidence)'
TYPE['ir_evidence/firewall_sessions_ws_recv_03.json']='Perimeter firewall session logs (PAN-OS export, abridged)'
COVER['ir_evidence/firewall_sessions_ws_recv_03.json']='2026-05-02T00:00Z to 2026-05-15T19:42Z (14 days, host 10.10.3.21)'
RELI['ir_evidence/firewall_sessions_ws_recv_03.json']='HIGH (primary session telemetry; abridged export of 39 412 sessions, full 1.8 GB export preserved)'
KEY['ir_evidence/firewall_sessions_ws_recv_03.json']='Continuous KNOWN_C2 beaconing to 185.220.101.45:443 (3 958 sessions, 5-min interval, JA3 match to 4x01); secondary C2 203.0.113.47:8443 first seen 2026-05-07T06:48:11Z, 38 seconds after scheduled-task registration, low-volume standby channel (HB-IOC-NEW-006, PROBABLE); three exfil bursts (14 219 484 B on 05-08, 11 802 944 B on 05-11, 8 419 232 B on 05-13) matching disk artifacts D1/D2/D3 to the byte; elevated C2 bytes on 05-05 and 05-12 (~ 23 MB each) consistent with LSASS dump exfiltration; three lateral-movement SMB/RPC session sets to server VLAN; Security-log gap correlation note; isolation denies from 18:42Z 05-15; notes 4-second firewall-vs-PCAP/Wazuh skew and names firewall timestamps authoritative for connection initiation.'

PHASE['ir_evidence/ir_team_notes.txt']='4x05-IR (Incident Response Working Notes)'
TYPE['ir_evidence/ir_team_notes.txt']='Chronological IR working file (mixed confidence)'
COVER['ir_evidence/ir_team_notes.txt']='2026-05-15 (isolation) through 2026-05-18 (handoff)'
RELI['ir_evidence/ir_team_notes.txt']='LOW (working file; HIGH/MED/LOW/DISPUTED tags per entry; claims require cross-validation)'
KEY['ir_evidence/ir_team_notes.txt']='Isolation decision and timeline (13:42 CDT); memory acquisition 14:18 CDT before shutdown (preserving netscan state); near-miss evidence destruction by Robert Kim (failed del of debug_tool.exe); disputed claims: debug_tool.exe on WS-RECV-04 / WS-RECV-07 (unsupported by hunt H4), Defender exclusion added by Robert (contradicted by records03 SID and schedule); dwell-time estimate 31 days; HIPAA notification deadline 2026-07-14 with 98 140-record working figure; de-duped cohort estimate 78-82 thousand pending Legal; five named items to prove-or-disprove (A through E); full-chain hypothesis from Apr 14 to May 15 requiring confidence marking.'

PHASE['reference/attck_navigator_80pct.json']='4x04 output (Reference Baseline)'
TYPE['reference/attck_navigator_80pct.json']='ATT&CK Navigator layer 4.6'
COVER['reference/attck_navigator_80pct.json']='Campaign-wide; MedDefense observations through 2026-05-14 approval date'
RELI['reference/attck_navigator_80pct.json']='MEDIUM (synthesis layer, technique-level scoring; not primary evidence)'
KEY['reference/attck_navigator_80pct.json']='29-technique model at 23 OBSERVED / 3 INFERRED / 3 NOT COVERED (80 percent observed, 90 percent mapped); open hypotheses for 4x05: T1053.005 Scheduled Task, T1074.001 Local Data Staging, T1560.001 Archive Collected Data, T1070.001 Clear Event Logs; the baseline the 4x05 layer must upgrade from IR evidence.'

PHASE['reference/healthbane_ioc_master.json']='4x00-4x04 output (Reference Baseline)'
TYPE['reference/healthbane_ioc_master.json']='Master IOC database (31 entries)'
COVER['reference/healthbane_ioc_master.json']='2026-04-14 through 2026-05-13 across all five investigations'
RELI['reference/healthbane_ioc_master.json']='MEDIUM (consolidated derived indicators; 30 HIGH / 1 MEDIUM confidence)'
KEY['reference/healthbane_ioc_master.json']='Domains, URLs, IPs, file hashes, registry keys, accounts (dmarsh, svc_healthsync), hosts (WS-RECV-03 pivot; SRV-HEALTH-DB / SRV-INS-DB / SRV-DC-01 targets), behavioral TTP and detection-rule IOCs; known gaps section anticipates secondary C2, scheduled task, staging artifacts and anti-forensics surfacing in 4x05; the KNOWN/NEW/MODIFIED classification baseline for newly discovered indicators.'

PHASE['reference/meddefense_asset_inventory.txt']='Reference (Pre-incident Baseline)'
TYPE['reference/meddefense_asset_inventory.txt']='Asset inventory and data sensitivity matrix (AST-INV-2026-Q2)'
COVER['reference/meddefense_asset_inventory.txt']='Effective 2026-04-01 (pre-incident baseline, next review 2026-07-01)'
RELI['reference/meddefense_asset_inventory.txt']='HIGH for holdings (authoritative signed inventory) — but contains internal inconsistencies vs topology (see DISCREPANCIES)'
KEY['reference/meddefense_asset_inventory.txt']='PHI/PII mapping: SRV-HEALTH-DB CRITICAL (~ 47 000 patient records), SRV-INS-DB HIGH (~ 51 000 member records, PHI via coded claims), SRV-FILE-01 imaging share (~ 8 400), SRV-DC-01 HIGH (NTDS); critical access paths (svc_healthsync => SRV-HEALTH-DB flagged as the stolen-credential-to-PHI route); HIPAA trigger analysis under 45 CFR 164.402; deduped cohort estimate 50 000 - 55 000 if all three sources confirmed; VLAN-3 workstation misconfiguration noted (local admin on records workstations).'

PHASE['reference/network_topology.txt']='Reference (Pre-incident Baseline)'
TYPE['reference/network_topology.txt']='Network topology and authorization matrix (NET-TOPO-2026-05 rev 12)'
COVER['reference/network_topology.txt']='Effective 2026-05-01 (pre-dates hunt window)'
RELI['reference/network_topology.txt']='HIGH for authorization rules, MEDIUM for host attributes (see DISCREPANCIES on IPs and Diane Marsh entry)'
KEY['reference/network_topology.txt']='VLAN segmentation 10.10.x; administrative authorization matrix: WS-ADMIN-01 / robert.kim is the ONLY authorized source of PsExec / WMIC remote / PSRemoting / remote schtasks / remote service creation; service accounts never authorized to log on from workstations; maintenance-window rule (any admin tooling outside published windows is a candidate indicator); emergency contacts.'

# ---------------------------------------------------------------------------
# Print source catalog with existence/content sanity check
# ---------------------------------------------------------------------------
printf 'SOURCE CATALOG:\n'
idx=1
for f in "${FILES[@]}"; do
  path="$ROOT/$f"
  if [[ ! -f "$path" ]]; then
    printf '  [%02d] %s\n       *** MISSING FROM PACKAGE ***\n\n' "$idx" "$f"
    idx=$((idx + 1))
    MISSING=$((MISSING + 1))
    continue
  fi
  LC=$(wc -l < "$path")
  printf '  [%02d] %s\n' "$idx" "$(basename "$f")"
  printf '       Phase: %s\n' "${PHASE[$f]}"
  printf '       Type: %s\n' "${TYPE[$f]}"
  printf '       Coverage: %s\n' "${COVER[$f]}"
  printf '       Reliability: %s\n' "${RELI[$f]}"
  printf '       Package file verified: %s (%s lines)\n' "$f" "$LC"
  fold -s -w 66 <<< "${KEY[$f]}" | sed 's/^/                    /'
  printf '\n'
  idx=$((idx + 1))
done

# ---------------------------------------------------------------------------
# Temporal coverage matrix
# (E = email, N = network, I = intel, M = malware, S = SIEM, R = IR forensic)
# ---------------------------------------------------------------------------
printf 'TEMPORAL COVERAGE MATRIX:\n'
printf '  (E=email  N=network  I=intel  M=malware-triage  S=SIEM/hunt  R=IR forensics)\n\n'
printf '  Week 11  Apr 13-19   [E-4x00 ][N-4x01 ][------- ][------- ][------- ][------- ]\n'
printf '  Week 12  Apr 20-26   [--------][N-4x01 ][I-4x02 ][M-4x03 ][------- ][R-retro]\n'
printf '  Week 13  Apr 27-May3 [--------][--------][--------][M-4x03 ][------- ][R-retro]\n'
printf '  Week 14  May 04-10   [--------][R-fw-14d][--------][------- ][S-4x04 ][R-live ]\n'
printf '  Week 15  May 11-17   [--------][R-fw-14d][--------][------- ][S-4x04 ][R-live ]\n'
printf '  Week 16  May 18+     [--------][--------][--------][--------][S-arch ][R-handoff]\n'
printf '\n'

printf 'GAP: No network capture of any kind between 2026-04-16T00:00Z (PCAP end)\n'
printf '      and 2026-05-02T00:00Z (firewall export start) -- a 16-day window\n'
printf '      spanning RAT first execution (2026-04-22) and exfiltrator staging\n'
printf '      (sync_healthdata.ps1 delivery, 2026-04-30 per 4x03/IOC master).\n'
printf 'GAP: No endpoint telemetry (Sysmon/SIEM) before 2026-05-04; the 4x04 hunt\n'
printf '      window starts three days after the first LSASS dump preparation\n'
printf '      (Defender exclusion 2026-05-04 18:11 CDT) and eight days after\n'
printf '      RAT installation (2026-04-22).\n'
printf 'GAP: Memory and disk evidence exist for WS-RECV-03 ONLY. No forensic images\n'
printf '      of SRV-HEALTH-DB, SRV-INS-DB or SRV-DC-01 (database-side query\n'
printf '      auditing was NOT enabled), and no imaging of WS-RECV-04/05.\n'
printf 'GAP: 12-minute host Security-event-log gap 2026-05-09 03:00-03:12 CDT\n'
printf '      (attacker wevtutil clear) destroys host auth telemetry; firewall\n'
printf '      sessions during the gap survive and partially compensate.\n'
printf 'GAP: 4x04 hunt deliberately excluded persistence, staging, anti-forensics\n'
printf '      and port-level egress; these phases were single-source until IR.\n'
printf 'GAP: Firewall export is ABRIDGED (168 of 39 412 sessions; aggregates only\n'
printf '      for the rest) -- full 1.8 GB export not in this package.\n'
printf 'GAP: PCAP covers VLAN-3 SPAN only; cross-VLAN (server segment) traffic\n'
printf '      invisible to 4x01 -- lateral movement was unobservable until the\n'
printf '      firewall export and SIEM hunt.\n\n'

# ---------------------------------------------------------------------------
# Domain gaps: attack phases relying on a single evidence source
# ---------------------------------------------------------------------------
printf 'DOMAIN GAPS (attack phase with effectively one evidence source):\n'
printf '  - Initial access / credential submission: 4x00 + 4x01 PCAP only;\n'
printf '    no mail-server raw evidence in package.\n'
printf '  - Stage 2 execution chain (VBA -> download -> first run): 4x01 PCAP +\n'
printf '    4x03 capability analysis; no host telemetry from 2026-04-15.\n'
printf '  - LSASS dump CONTENT exfiltration: single-source inference\n'
printf '    (elevated C2 bytes 05-05 and 05-12 sum to ~ 23 MB per firewall\n'
printf '    aggregate); no direct content proof (OPEN in IR notes Entry #008).\n'
printf '  - svc_healthsync initial compromise vector: inferred from out.dat\n'
printf '    residue only; no SRV-HEALTH-DB-side evidence available.\n'
printf '  - Any attacker activity on hosts other than WS-RECV-03: NO evidence\n'
printf '    either way (Robert Kim WS-RECV-04/07 claim is disputed, unverified).\n\n'

# ---------------------------------------------------------------------------
# Cross-source discrepancies the inventory surfaces
# ---------------------------------------------------------------------------
printf 'CROSS-SOURCE DISCREPANCIES (resolve in reconstruction, do not ignore):\n'
printf '  [D1] Server IP mappings conflict across three documents:\n'
printf '       firewall metadata: SRV-HEALTH-DB=10.10.20.30, SRV-INS-DB=10.10.20.31,\n'
printf '                        SRV-DC-01=10.10.20.10, SRV-FILE-01=10.10.20.40\n'
printf '       asset inventory:  SRV-HEALTH-DB=10.10.20.15, SRV-INS-DB=10.10.20.25,\n'
printf '                        SRV-DC-01=10.10.20.10, SRV-FILE-01=10.10.20.30\n'
printf '       topology:         SRV-HEALTH-DB=10.10.20.15, SRV-INS-DB=10.10.20.25,\n'
printf '                        SRV-DC-01=10.10.20.5,  SRV-FILE-01=10.10.20.50\n'
printf '       Resolution rule: firewall export IPs describe ACTUAL observed traffic\n'
printf '       (authoritative for the sessions logged); inventory/topology describe\n'
printf '       intended design. Treat hostname-based correlation, not IP, as primary.\n'
printf '  [D2] Diane Marsh click location and time: 4x00 + 4x01 + IOC master say\n'
printf '       click at 2026-04-14T13:18Z (08:18 CDT) on WS-RECV-03; topology lists\n'
printf '       dmarsh on WS-NURSE-04 (10.10.2.15) with a click at 15:02:33 CDT.\n'
printf '       PCAP and browser-history triangulation outweigh the topology note.\n'
printf '  [D3] Clock-skew sign is stated oppositely: 4x01 says PCAP ~ 4s AHEAD of\n'
printf '       firewall; firewall metadata says firewall 4s AHEAD of PCAP/Wazuh.\n'
printf '       Both agree the magnitude is ~ 4s and that firewall SYN time is\n'
printf '       authoritative for connection initiation; the sign conflict must be\n'
printf '       normalized before the unified timeline is built.\n'
printf '  [D4] Breach-notification cohort estimates diverge: firewall F5 states\n'
printf '       98 140 records; asset inventory estimates 50 000 - 55 000 deduped;\n'
printf '       IR notes (Sarah Park) estimate 78-82 thousand pending Legal dedup.\n'
printf '       The 98 140 figure counts raw rows across two overlapping cohorts;\n'
printf '       the deduped number drives the HIPAA notification letter count.\n'
printf '  [D5] Perimeter device: topology documents a FortiGate-EDGE (FortiOS 7.4);\n'
printf '       the firewall export is from a Palo Alto PA-3220 (PAN-OS).\n'
printf '       No traffic consequence for the reconstruction, but cite the export,\n'
printf '       not the topology, when describing session logging.\n'
printf '  [D6] Hunt-initiation chronology is internally inconsistent: the 4x04 report\n'
printf '       header states hunt initiated 2026-05-18 yet R1-R3 (isolation) were\n'
printf '       executed 2026-05-15, and Entry #009 confirms the 05-18 date while\n'
printf '       placing the hunt the day before isolation. Document both readings;\n'
printf '       the 05-15 isolation timestamp itself is corroborated by three sources.\n\n'

# ---------------------------------------------------------------------------
# Critical questions for the reconstruction
# ---------------------------------------------------------------------------
printf 'CRITICAL QUESTIONS FOR RECONSTRUCTION:\n'
printf '  [Q1] Does the firewall evidence confirm or contradict the 4x01 network\n'
printf '       timeline for WS-RECV-03 ?\n'
printf '  [Q2] What is 203.0.113.47:8443 -- secondary C2 or unrelated traffic?\n'
printf '  [Q3] Did the staged archives leave the network (burst-by-burst match\n'
printf '       says YES) and did the LSASS dumps leave too (inferred only)?\n'
printf '  [Q4] Are there persistence mechanisms beyond Run-key plus the\n'
printf '       scheduled task, and are other hosts compromised (Robert claim)?\n'
printf '  [Q5] Which ATT&CK techniques upgrade after IR integration, and which\n'
printf '       remain unmapped or collection-blind?\n'
printf '  [Q6] Who created the Defender exclusion (records03 SID evidence vs\n'
printf '       Robert claim) and did the missed 2026-04-22 Run-key alert fire?\n'
printf '  [Q7] Was dmarsh used in the 17-minute pre-rotation window (Entry #010 E)?\n'
printf '  [Q8] What is the final HIPAA notification cohort after dedup, and what\n'
printf '       is the authoritative discovery date (2026-05-15)?\n\n'

printf '================================================================\n'
printf '  %s package issue(s) detected above. Run with repo root as argument.\n' "$MISSING"
printf '================================================================\n'
