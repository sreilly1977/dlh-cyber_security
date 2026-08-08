# Eyes on the Endpoint

## Endpoint Telemetry Engineering

**How Sysmon Event IDs map to attacker behavior:**
Each Sysmon Event ID corresponds to a specific activity type — Event ID 1 is process creation, 3 is network connections, 7 is image loads, 10 is process access, 11 is file creation, 13 is registry modification, and 22 is DNS queries, enabling you to trace attacker techniques to discrete log events.

**How PowerShell Script Block Logging captures decoded command content, why Module Logging and Transcription complement it, and what each reveals:**
Script Block Logging (Event ID 4104) records fully decoded PowerShell commands as executed, Module Logging (4103) captures pipeline execution details, and Transcription saves full input/output sessions — three complementary layers of visibility.

**How auditd rules generate kernel-level audit records for file access, privilege escalation, process execution and network socket creation:**
auditd uses kernel-level rules (syscall-based, file/path watches, and key-tagged filters) to generate structured audit records for security-relevant events such as file access, privilege escalation, process execution, and network socket creation.

**How to validate telemetry coverage by running controlled simulations and measuring detection completeness:**
Execute known attacker-like actions in a controlled environment, compare the ground truth of what was done against what the telemetry actually captured, and calculate detection completeness as the percentage of simulated actions that produced observable events.

**The difference between visibility and protection, and why both are necessary:**
Visibility (telemetry/logging) tells you what happened after the fact, while protection (controls like EDR, firewalls, patching) prevents or blocks attacks — you need both because you cannot protect what you cannot see, and visibility alone does not stop the attack.

---

## Telemetry Quality and Export

**How to assess telemetry quality: event type distribution, time coverage, field completeness, gap detection:**
Evaluate whether the right mix of event types is being collected, whether logging is continuous or has time gaps, whether critical fields (user, process, command line, hash) are populated, and whether expected events are missing entirely.

**How to export Windows events and Linux logs to structured JSON with normalized timestamps and consistent fields:**
Use tools like `wevtutil` or PowerShell's `Get-WinEvent` on Windows and `ausearch`/`aureport` or `journalctl --output=json` on Linux, normalizing all timestamps to ISO 8601 (UTC) and mapping fields to a consistent schema across platforms.

**How to produce a telemetry handoff package suitable for analyst consumption:**
Deliver a structured, documented dataset containing normalized JSON logs, a schema/data dictionary explaining each field, metadata describing the collection environment and time window, and a coverage summary highlighting what is and is not captured.

---

## Attack Simulation and Validation

**How to run controlled attacker-like actions (process creation, network connections, file operations, registry modifications, privilege escalation) safely against a hardened endpoint:**
Execute predefined, documented simulation scripts (e.g., Atomic Red Team tests or custom reproducible commands) on an isolated test endpoint, logging a ground truth record of every action taken for later correlation.

**How to correlate a ground truth attack log against captured telemetry to produce a detection matrix:**
Map each simulated action from your ground truth log to the corresponding telemetry events captured during execution, then build a matrix showing which actions were detected, partially detected, or missed entirely.

**How to identify and document coverage gaps using MITRE ATT&CK technique mapping:**
Map each simulated action to its corresponding MITRE ATT&CK technique ID, compare against what the telemetry successfully captured, and document any technique that produced no observable events as a formal coverage gap for prioritized remediation.
