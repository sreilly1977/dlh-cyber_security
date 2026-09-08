# MedDefense SOC Shift Report 2026-03-26

## Shift Identification

- Analyst: Steve - Cybersecurity Engineer
- Shift window: 2026-03-24T00:02:48Z to 2026-03-26T00:56:30Z (queue event span)
- Queue received: 653 alerts. Queue handed off: 0 unclassified; every alert resolved, packaged into 467 incident records.

## Summary Numbers

- Tickets total: 845 (instances across batches 1–7)
- True positive: 845; false positive: 0; benign: 0
- Escalated to Tier 2: 144 ticket instances (ratio 0.170); 70 escalated incident records after correlation deduplication
- FP rate: 0.000
- MTTD: 57:57:58 median, event-to-generation (queue arrived with a two-day detection backlog, generation stamped 2026-03-27)
- MTTR: 00:00:00 (zero by construction: created_at equals generated_at under the determinism contract; no analyst wall clocks exist in this dataset)
- SLA compliance: 100.0% (measured on fixed per-band estimates, not live analyst effort)

## Escalated Incidents

Aggregated from incidents.json; one line per distinct target and rule, counts in parentheses.

1. db-patient-01 — SSH Repeated Authentication Failures, PHI database (campaign of 20 alerts, 1 correlated incident) — containment: block_source_ip at perimeter for 203.0.113.41–44
2. med-mri-02 — Medical Segment Egress Policy Violation / Outbound Connection to Unknown Destination (10) — containment: block_ip_at_egress (C2 beacon cluster)
3. Correlated incidents on unattributed critical assets, tuned-rule privileged logons (46) — containment: isolate_host
4. srv-ehr-01, Windows Privileged Logon During Deep Night Hours (Tuned) (7) — containment: disable_account x5, isolate_host x2
5. srv-dc-02, correlated incident of 5 alerts (3) — containment: isolate_host
6. srv-dc-01, correlated incident of 3 alerts (2) — containment: disable_account x1, isolate_host x1
7. pharm-app-01, correlated incident of 3 alerts (1) — containment: disable_account

Marquee detail:

- The brute-force campaign against db-patient-01 from 203.0.113.41–44 never progressed to successful authentication (correlation_primitives.json holds zero chains); block_source_ip at the perimeter covers the full /24 cluster.
- Beaconing from med-mri-02 to 198.51.100.73:443 was feed-categorized c2/beacon/https_tunnel and was ALLOWed by the MEDICAL_IOT-to-INTERNET policy despite its BLOCK rule; block_ip_at_egress is issued on all 10 records.

## False Positive Highlights

This shift produced zero false-positive tickets, so the FP channel offers no predicate changes this week. Highest-volume rules, all with FP count 0: scheduled-task creation f8c2e5a0 (416 alerts, all score 0), off-hours privileged logon b5d29e18 (205), SSH brute force 7f3c1a2e (20). The effective tuning signal is elsewhere: 99 batch-7 priority overrides document that rule scoring underweights asset data classification, repeatedly promoting low/medium-band alerts on PHI assets to tier 2.

## Open Items for the Next Shift

- Attribute source 10.2.3.2 behind the 10 C2 beacon alerts to 198.51.100.73 (hostname join was null; zone evidence points to MEDICAL_IOT). Highest-priority open question.
- Review the clin-ws-07 and clin-ws-12 interpreter-execution records first among the 395 enhanced-monitoring records: ExecutionPolicy Bypass PowerShell from C:\Temp with baseline deviation and no IOC confirmation.
- 15 escalated correlated incidents sit on identity and clinical infrastructure (srv-dc-01/02, srv-ehr-01, pharm-app-01); treat identity assets first.
- All 279 grouped alerts resolve cleanly into 93 correlated incidents; no deduplication work is outstanding.

## Notable Patterns

Scheduled-task creation noise dominated volume (416 alerts at score 0) while both genuine threats arrived through separate channels: an SSH brute-force cluster from one /24 and HTTPS beacon egress from the medical-device segment, the first queue appearance of the c2/beacon/https_tunnel category combination this week. Asset criticality and data classification, not rule priority scores, drove every consequential escalation decision this shift. Rule-side fixes for recurring noise should be prioritized ahead of the score-0 farm's planned review.

## Signature

- Analyst: Steve - Cybersecurity Engineer
- Reported: 2026-03-26 (shift close, deterministic)
