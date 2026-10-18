# Learning Objectives

---

## The Evidence Trail

---

### Technical

**Q: How do you verify forensic artifact integrity before and after analysis?**

**A:** Record MD5/SHA-256 hashes of the source image at acquisition, then re-hash the image and any working copies before and after analysis so matching values demonstrate nothing changed.

**Q: How do you perform filesystem timeline analysis using The Sleuth Kit?**

**A:** Run `fls -r -m <mount-point> image.dd > bodyfile` to extract MAC times recursively, convert with `mactime -b bodyfile -d` into a sortable timeline, and pivot on suspect timestamps.

**Q: How do you extract and interpret Windows persistence artifacts from a disk image?**

**A:** Pull the registry hives and parse Run/RunOnce keys, Services, Scheduled Tasks, Startup folders, and WMI event subscriptions, then validate each entry against file and process evidence.

**Q: How do you analyze a Windows memory dump using Volatility 3?**

**A:** Identify the profile, then run plugins such as `windows.pslist`, `windows.psscan`, `windows.cmdline`, `windows.netscan`, `windows.dlllist`, and `windows.malfind` to recover processes, network state, and injected code.

**Q: How do you correlate evidence across artifact types into a single incident timeline?**

**A:** Normalise every timestamp to UTC, merge file system, registry, event log, and memory artifacts into one super-timeline, and anchor it around pivot events such as initial execution.

---

### Conceptual

**Q: Why is chain of custody a continuous discipline rather than a one-time form?**

**A:** Because admissibility depends on an unbroken, contemporaneous record of every transfer, access, and storage condition from seizure through testimony, not a single signed sheet.

**Q: How does order of volatility affect what evidence survives?**

**A:** Collection must proceed from most to least volatile (CPU registers and cache, RAM, network state, temporary files, disk, archival media) because each layer degrades faster than the one below it.

**Q: What distinguishes confirmed, probable, and possible findings?**

**A:** Confirmed findings are directly supported by corroborated artifacts, probable findings rest on strong consistent inference without direct proof, and possible findings merely remain consistent with the evidence while alternatives are not excluded.

**Q: How is HIPAA breach scope determined from forensic evidence?**

**A:** Map which systems, data sets, and individuals had protected health information accessed or acquired, then apply the four-factor risk assessment (nature and extent of PHI, the unauthorised recipient, whether PHI was actually viewed, and mitigation) to decide notification duties.

---

### Transversal

**Q: How do you write for two audiences in the same document?**

**A:** Lead with a plain-language executive summary for decision makers, follow with a technical annex carrying artifact-level detail, and keep the conclusions identical in both sections.

**Q: How do you tie every assertion to an evidence reference?**

**A:** Attach an exhibit identifier to each claim, typically hash, artifact path, timestamp, and offset, so any reader can independently reproduce the observation.

**Q: How do you bound conclusions to what the evidence supports?**

**A:** State only what the artifacts show, label each finding as confirmed, probable, or possible, and name the additional evidence that would raise or lower that confidence.

---
