<!-- Name: implementation_package.md -->
<!-- Purpose: Assemble all improvements from Tasks 3-9 into a single executable -->
<!--          package with owners, deadlines, and validation methods for handoff -->
<!--          by James Chen to the MedDefense IR team. -->
<!-- Author: Steve - Cybersecurity Engineer -->
<!-- Date: 19 October 2026 -->

# Improvement Implementation Package: IR-2026-0414-01

Owner roles reference `ir_team_structure.yaml` (5x00_incident_response). Deadlines
are in days from 2026-10-19 (package date). Package prepared for James Chen, SOC
Lead / IR Commander, per his directive: deployable artifacts, not slides.

## Implementation Table

| ID | Type | Title | Source | Owner Role | Deadline (days) | Success Criterion | Validation Method | Status |
|---|---|---|---|---|---|---|---|---|
| IMP-001 | detection | Deploy `sigma_powershell_msbuild_lolbin.yml` (validated, untuned) | Task 3; GAP-004, GAP-005 | SOC Lead | 7 | Rule active in SIEM; fires on synthetic EID 1 event; no FPs on 7-day baseline | Synthetic Sysmon EID 1 injection; 7-day alert queue review (re-run `validate_rules.sh` monthly) | pending |
| IMP-002 | detection | Deploy `sigma_msbuild_network_connection.yml` (validated, tuned) | Task 4; GAP-007, GAP-008 | SOC Lead | 7 | Rule active; FP rate below 0.1% on 7-day baseline | `rule_validation_report.md` post-tuning PASS; 7-day alert queue review | pending |
| IMP-003 | hardening | PowerShell Constrained Language Mode for non-admin users | HRD-001; GAP-004, GAP-005 | IT Director | 14 | CLM enforced on WST host class; `$ExecutionContext.SessionState.LanguageMode` returns `ConstrainedLanguage` as standard user | GPO compliance report plus spot-check on 5% sample of hosts | pending |
| IMP-004 | hardening | AppLocker rule restricting MSBuild.exe to admins and CI accounts | HRD-002; GAP-004, GAP-006 | IT Director | 21 | Standard-user MSBuild execution blocked; AppLocker EID 8004 logged; CI builds unaffected | Test execution as standard user; CI/CD pipeline regression run | pending |
| IMP-005 | hardening | Conditional access restructure: risk-aware MFA, geo-conditioned | HRD-003; GAP-002, GAP-003 | Infrastructure Lead | 14 | Sign-in from untrusted geography or medium+ risk requires MFA even on compliant device | Entra sign-in log test: policy applied with MFA required; simulate foreign-IP login | pending |
| IMP-006 | hardening | Enable Credential Guard and RunAsPPL | HRD-004; GAP-009, GAP-010 | IT Director | 30 | Credential Guard running on supported hosts (fleet audit first: Enterprise/Education editions) | `Win32_DeviceGuard` CIM query returns service 1 running; msinfo32 check | pending |
| IMP-007 | hardening | Workstation egress enforcement through secure web gateway | HRD-005; GAP-007, GAP-008 | Network Engineer | 30 | Raw-IP egress blocked; Tor exit and AbuseIPDB feeds loaded | Attempt raw-IP connection from test workstation; gateway feed status page | pending |
| IMP-008 | hardening | LIS segment isolation and LIS_REPORTS$ ACL tightening | HRD-006; GAP-011, GAP-012 | Infrastructure Lead | 21 | SMB to LIS segment permitted only from jump host; share access denied from workstation VLANs | Attempted `dir \\LIS-WSIDE-01\LIS_REPORTS$` from standard workstation fails; auditpol shows File System success auditing | pending |
| IMP-009 | hardening | DNS and web filtering with Spamhaus DBL, SURBL, URLhaus feeds | HRD-007; GAP-001 | Network Engineer | 14 | Blocklist feeds refreshing at 60-minute interval; listed domains return NXDOMAIN/block page | Resolver log query showing feed-attributed block; feed status page | pending |
| IMP-010 | hardening | Sysmon persistence telemetry deployment | HRD-008; GAP-013 | IT Director | 14 | EID 11, 12/13, 1 captured on WST host class; Run key write generates EID 13 alert | `sysmon64 -c` shows active config; controlled test write triggers detection | pending |
| IMP-011 | playbook | Apply PB-UPD-001 through PB-UPD-004 to `playbook_credential_exposure.yaml` | Task 9; GAP-002, GAP-003, GAP-009, GAP-010, GAP-011, GAP-012 | SOC Lead | 7 | Updated playbook merged and signed off; analysts trained within 2 weeks | Sign-off table complete; tabletop exercise per validation checklist | pending |
| IMP-012 | risk | Publish `risk_register_updates.yaml` entries RSK-2026-031 to 038 | Task 7 | IR Commander | 14 | Register entries accepted; owners confirmed; review dates scheduled | Risk review meeting minutes; register updated in GRC tool | pending |
| IMP-013 | detection | Execute five proactive hunting queries (threat intel brief) | Task 8 hunting section | SOC Lead | 10 | All five hunts executed estate-wide; results documented; anomalies triaged | Hunt completion log; incident tickets for any confirmed findings | pending |
| IMP-014 | risk | Complete DLP log review for exfil determination (RSK-2026-038, open item 3) | Task 7; forensic open item 3 | Legal Liaison | 7 | Written determination whether any of the 14 PDFs left the network; if confirmed, breach notification clock starts | DLP review memorandum signed by General Counsel | pending |

## Deployment Sequence

1. **IMP-014 (DLP exfil determination)** — first because its outcome drives the HIPAA notification clock and raises or lowers RSK-2026-038; everything else proceeds in parallel regardless of the answer.
2. **IMP-001 and IMP-002 (detection rules)** — deploy before any hardening so the rules baseline against current, unmodified telemetry; validated rules exist and need no further testing.
3. **IMP-009 (DNS/web blocklists) and IMP-005 (conditional access)** — choke initial access immediately; both are server-side changes with no endpoint dependency and stop the intrusion at step one on replay.
4. **IMP-003 (PowerShell CLM)** — after rules are baselined, since CLM changes PowerShell event patterns and would confound the baseline if deployed first.
5. **IMP-004 (AppLocker for MSBuild)** — after CLM is confirmed stable on the pilot group; both change execution behavior and sequencing them avoids attributing breakage to the wrong control.
6. **IMP-010 (Sysmon persistence telemetry)** — after AppLocker, so the persistence detection tunes against the post-hardening environment rather than a fleet in transition.
7. **IMP-006 (Credential Guard)** and **IMP-007 (egress enforcement)** — parallel tracks, both requiring fleet audits or gateway change windows; sequence within the 30-day window per infrastructure capacity.
8. **IMP-008 (LIS segmentation and ACLs)** — requires clinical coordination and a downtime window agreed with the lab; schedule the change window early but execute after egress enforcement is proven, so no C2 path survives into the segmented zone.
9. **IMP-011 (playbook updates)** — published as soon as approved; it trains behavior while technical controls roll out.
10. **IMP-013 (proactive hunting)** — run immediately after rules deploy but before hardening completes, to catch any dormant second-stage tooling that the hardening would otherwise displace without detection.
11. **IMP-012 (risk register publication)** — last formally, at the 14-day review meeting, when deployment status of all other items can be recorded against each risk entry.

## Notes

- IMP-006 requires a fleet edition audit before any deployment: Credential Guard is unsupported on Windows Home/Pro, and any non-compliant hosts must be tracked as exceptions in the register.
- IMP-014 is the only item with a fixed regulatory consequence: if exfiltration is confirmed, the 60-day HHS OCR notification clock runs from the determination date, so it must not slip.
- No improvements beyond Tasks 3-9 outputs are included, per package constraints.
