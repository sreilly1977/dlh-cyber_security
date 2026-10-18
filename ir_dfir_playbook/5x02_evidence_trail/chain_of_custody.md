# Chain of Custody: LH-2026-0414-01

## Case Header

- **Case number:** `LH-2026-0414-01`
- **Incident ID:** `IR-2026-0414-01`
- **Lead investigator:** Steve, Cybersecurity Engineer
- **Date opened:** 2026-04-14
- **Litigation hold reference:** `Memo from Helena Reyes, 2026-04-14T07:30Z`

> **Document rule:** This log is append-only for the duration of the investigation. No entry may
> be amended or deleted; corrections are made by appending a new entry that references the
> original. Known acquisition-period deviations (documented by the acquirer on
> 2026-04-14T07:42Z) are carried as DEVIATION notes below.

## Artifact Registry

| Artifact ID | Name | Format | Acquired By | Acquired At (UTC) | Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW (dd) | Mike Torres | 2026-04-14T04:51Z (start) – 06:14Z (complete) | FTK Imager | **NOT COMPUTED AT ACQUISITION** — baseline to be established at first forensic access | `\\evidence\share\IR-2026-0414-01\wst-ws-031.dd` | read-only, IR team only |
| ART-002 | wst-ws-031.mem | RAW (memory dump) | Mike Torres | 2026-04-14T03:02Z | WinPmem v3.3-rc3 (run from USB) | **NOT COMPUTED AT ACQUISITION** — baseline to be established at first forensic access | `\\evidence\share\IR-2026-0414-01\wst-ws-031.mem` | read-only, IR team only |
| ART-003 | wst-ws-017.mem | RAW (memory dump) | Mike Torres | 2026-04-14T03:38Z | WinPmem v3.3-rc3 (run from console, West Campus) | **NOT COMPUTED AT ACQUISITION** — baseline to be established at first forensic access | `\\evidence\share\IR-2026-0414-01\wst-ws-017.mem` | read-only, IR team only |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| 2026-04-14T03:02Z | Mike Torres | ART-002 | acquire_memory_dump | WinPmem v3.3-rc3 | no | Host still live at capture. Copied via USB3/NVMe enclosure to evidence share. **DEVIATION:** No SHA-256 computed at acquisition. |
| 2026-04-14T03:38Z | Mike Torres | ART-003 | acquire_memory_dump | WinPmem v3.3-rc3 | no | Captured from console at West Campus. **DEVIATION:** No SHA-256 computed at acquisition. |
| ~2026-04-14T04:51Z–06:14Z | Mike Torres | ART-001 | acquire_disk_image | FTK Imager (raw/dd) | no | Host live; already VLAN-isolated to 999 by James Chen. Disk was mounted read-write on the live filesystem prior to imaging; Explorer was opened on the mount, potentially updating access times. Imaged over that mount without remounting read-only. **DEVIATION:** No SHA-256 computed at acquisition. **DEVIATION:** Artifact predecessor (live filesystem) accessed read-write by acquirer prior to imaging. |
| 2026-04-14T07:30Z | Helena Reyes | (all) | litigation_hold_issued | — | n/a | Formal litigation hold ref LH-2026-0414-01. All related data subject to preservation. |
| 2026-04-14T07:42Z | Mike Torres | (all) | handoff_to_forensics | — | no | Handoff of ART-001, ART-002, ART-003 to forensic analyst (Steve). **DEVIATION:** No chain-of-custody form maintained between acquisition and handoff; individuals with physical/network access to artifacts in that window are unrecorded. |

<!-- APPEND-ONLY: Subsequent access events below. First forensic access for each artifact
     must compute and record SHA-256 (baseline), stored in hashes/<ART-ID>.sha256, before any
     analysis action. Any mismatch against the baseline is flagged immediately as a DEVIATION
     note in this log. -->
