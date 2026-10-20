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
