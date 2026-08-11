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

---

# The Patch Equation

## Vulnerability Management

**Q: How to enumerate installed packages and cross-reference them against known CVE sources using apt, dpkg and apt-get changelog?**
A: Use `dpkg -l` to list installed packages, `apt-get changelog <package>` to retrieve vulnerability history, and cross-reference against the NVD/Ubuntu CVE feeds using `ubuntu-security-status` or `apt list --upgradable` filtered by security origin.

**Q: How to prioritize patches using CVSS, exploit availability, asset criticality and exposure, and why raw CVSS alone is an incomplete signal?**
A: Prioritize by combining CVSS base score with active exploit availability (exploit-db, CISA KEV catalog), asset criticality tier, and network exposure, because raw CVSS only measures theoretical severity and ignores whether a vulnerability is practically exploitable or relevant to your environment.

**Q: How to validate that a patch actually resolved the vulnerability it was intended to fix, not just that the command succeeded?**
A: Re-run the original vulnerability scanner or PoC exploit against the patched target and confirm the finding is eliminated, rather than relying solely on the package version reported by `dpkg -l`.

**Q: What is the difference between security patches, feature updates, kernel updates and library updates, and why does each have a different deployment and rollback profile?**
A: Security patches fix vulnerabilities with minimal code change and low risk, feature updates introduce new functionality with higher regression risk, kernel updates require reboot and can affect hardware compatibility, and library updates carry transitive dependency risk where one change can break multiple consumers.

---

## Change Management

**Q: How to produce a structured change log from package operations, capturing what was modified, when, by whom and with what outcome?**
A: Wrap all package operations in a script that logs `whoami`, timestamps, package names, old/new versions, and exit codes into a structured JSON artifact using `dpkg-query` snapshots taken before and after.

**Q: How does maintenance window enforcement work as code, not policy?**
A: A script that checks the current time against a defined window in code and exits with an error if the current time falls outside the allowed range, refusing to execute any changes.

**Q: How to track configuration drift introduced by patch operations, distinguishing expected changes from unexpected ones?**
A: Take a baseline snapshot of config files (`debsums`, `sha256sum`) before patching, then compare after patching, flagging changes to files owned by the patched package as expected and any other changes as unexpected drift.

**Q: How to build an end-to-end patch pipeline that is idempotent, auditable and safe to re-run?**
A: Structure the pipeline as discrete stages (snapshot, assess, apply, verify, report) where each stage checks whether its goal is already achieved before acting and writes a structured log artifact, making the entire sequence safe to re-run from any point.

---

## Operational Skills

**Q: How to diagnose and repair a broken apt/dpkg state: stale locks, half-configured packages, interrupted transactions, unmet dependencies?**
A: Remove stale locks with `lsof` and `rm`, repair half-configured packages with `dpkg --configure -a`, resolve interrupted transactions with `apt --fix-broken install`, and trace unmet dependencies using `apt-cache policy` and `aptitude why`.

**Q: How to configure unattended-upgrades for security-only patching with blacklists for critical packages and suppressed automatic reboots?**
A: Set `Unattended-Upgrade::Allowed-Origins` to security origins only, add critical packages to `Unattended-Upgrade::Package-Blacklist`, and set `Automatic-Reboot "false"` in `/etc/apt/apt.conf.d/50unattended-upgrades`.

**Q: How to implement rollback via apt version downgrade, apt-mark hold and preference pinning?**
A: Use `apt-get install <package>=<version>` to downgrade, `apt-mark hold <package>` to prevent re-upgrade during subsequent patch cycles, and `/etc/apt/preferences.d/` pinning to lock priority to a specific repository version.

**Q: How to write idempotent bash scripts that measure system state before and after every change and emit structured JSON artifacts?**
A: Capture state with `dpkg-query` and config checksums before each operation, skip the operation if the desired state is already present, capture state again after, and diff the results into a JSON report with `jq`.

---
