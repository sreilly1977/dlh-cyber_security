# HIPAA Breach Risk Assessment: IR-2026-0420-01

- Assessment date: 2026-04-20 (completed 23:00Z Sunday)
- Conducted by: Steve, on-call IR
- Reviewed by: Helena Reyes, General Counsel (pending — review scheduled before 07:00 Monday)
- PHI involved: 1,847 patient files — lab results and clinical notes —
  accessed on FILE-SVR-01 between 2026-04-19T02:14:01Z and 02:41:12Z
- Regulatory basis: 45 CFR §164.402 — breach presumption and four-factor
  risk assessment; presumption of breach applies unless a demonstrated low
  probability of compromise is established

## Factor 1: Nature and extent of the PHI involved

Evidence: FS-001 — all 1,847 accessed files are PDF-format clinical content
(.pdf 1847; .docx 0; .xlsx 0) drawn exclusively from \clinical\labs\ (lab
results) and \clinical\notes\ (clinical progress notes, including ER admission
and floor notes per the sampled object names). Lab results and progress notes
carry direct patient identifiers by nature (name, DOB, MRN, diagnoses,
results). MEM-005 and SYS evidence further shows the intruder harvested
stored user credentials from the workstation that initiated the access,
meaning identifier-rich context surrounded the file access.
Conclusion: Highly sensitive, directly identifying PHI. This factor weighs
strongly AGAINST low probability of compromise.
Confidence: HIGH

## Factor 2: The unauthorized person who used the PHI

Evidence: FS-002 — every one of the 1,847 accesses was performed under a
single logon session (logon_id 0xAF12C4B8) of MEDDEFENSE\jdoe, initiated
remotely from CS-WS-101 (10.30.12.101), the intruder-controlled patient-zero
workstation. FS-003 — jdoe holds a scheduling-coordinator role with no
legitimate clinical need to read either share. PRX-002/SYS-001 — the same
intrusion operated from a known criminal command-and-control infrastructure
(45.152.66.114, reputation tag cobalt_strike_team_server_known) and installed
commodity intrusion software on five systems.
Conclusion: The recipient is a deliberate, skilled criminal actor, not an
accidental insider disclosure. Criminal motive plus demonstrated intent to
monetize (ransomware staging per SYS-003) weigh heavily AGAINST low
probability of compromise.
Confidence: HIGH

## Factor 3: Whether the PHI was actually acquired or viewed

Evidence: FS-001 — access mask 0x1 (ReadData) on all sampled events; 1,847
reads in a 27-minute automated sweep performed by svchost32.exe on the server
(SYS-001, first spawn 02:14:01Z). PRX-003 — at 02:14:22Z, 21 seconds into that
window, 2,404,412 bytes were transmitted from FILE-SVR-01 to the intruder's
infrastructure (stage-12 finding), consistent with a bulk compressed archive
of the accessed content. PRX-002 — the C2 channel sustained regular large
payload exchanges throughout the dwell period.
Conclusion: The files were not merely exposed to risk of viewing; they were
systematically read AND a large transfer consistent with bulk copying left
the environment during the access window. Actual acquisition is evidenced,
not inferred.
Confidence: HIGH for systematic reading; MODERATE-HIGH that the 2.4 MB
transfer constitutes the copied file set (proxy metadata proves the transfer
occurred and its timing; content cannot be confirmed from metadata alone —
forensic_findings.md stage 12).

## Factor 4: Extent to which the risk to the PHI has been mitigated

Evidence: containment_execution.md STEPs 01–09 — all five affected systems
plus SCHED-SVR-01 are network-isolated with evidence preserved; the intruder's
communication channel is confirmed severed (zero C2 connectivity post-block,
hourly monitoring through 06:00Z); jdoe's credential is reset and all sessions
terminated (STEP-08); forensic images and chain of custody secured
(evidence_preservation.md ART-001 through ART-010).
Conclusion: Mitigation is substantially complete against FUTURE harm. However,
mitigation cannot undo an exfiltration that already occurred on 2026-04-19.
This factor limits ongoing exposure but does not reduce the probability that
compromise ALREADY occurred during the access window.
Confidence: HIGH

## Determination

The four-factor assessment DOES NOT support a conclusion of low probability
of compromise. Factors 1, 2, and 3 each independently defeat the low-
probability standard: highly identifiable clinical PHI (Factor 1), deliberate
criminal recipient (Factor 2), and affirmative evidence of bulk acquisition
(Factor 3). Under 45 CFR §164.402, the presumption of breach stands.

RECOMMENDATION TO COUNSEL: Treat as a reportable breach. Notification
obligations: individual notice to affected patients without unreasonable
delay and no later than 60 days from discovery (2026-04-20), plus HHS OCR
notification (breach affecting 500+ individuals triggers contemporaneous
media notice and OCR report per §164.406–408). Exact affected-patient census
to be derived from the full 1,847 object names during eradication phase.

Final determination: Helena Reyes, General Counsel, upon her review of this
assessment, no later than 2026-04-20T09:00Z Monday. Per the privacy officer
role, this document supplies the forensic basis; the legal determination is
hers to make, supported by the patient census.
