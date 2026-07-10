# Incident Analysis: billing-srv-01 — The Symptom Trap

## Executive Summary

The sysadmin diagnosed a hardware capacity problem. The evidence in the diagnostic
report tells a completely different story. billing-srv-01 is actively compromised
by a cryptocurrency miner that has been running undetected for approximately 14 days.
The root cause is not undersized hardware — it is an unresolved vulnerability in
Apache 2.4.29 that was exploited at least twice: first delivering ransomware in
January, and now delivering a Monero cryptominer. The server was rebuilt after the
ransomware attack without addressing the underlying entry point, allowing immediate
re-exploitation.

---

## 1. Process Identification: What is "kworker"?

### What it is masquerading as

The legitimate Linux `kworker` is a kernel thread that handles deferred kernel
work (interrupt processing, I/O operations, timer tasks). Real kworker processes:

- Appear in `top` output with bracketed names like `[kworker/0:1H]`
- Run as **root** (PID typically < 100)
- Reside in kernel space — they have no filesystem path
- Consume minimal CPU under normal conditions

### What this process actually is

The process at PID 8834 is **none of those things**:

| Attribute | Legitimate kworker | PID 8834 (observed) |
|-----------|--------------------|---------------------|
| Display name | `[kworker/...]` (bracketed) | `./kworker` (no brackets) |
| User context | root | **www-data** |
| Binary path | Kernel space (no file) | `/var/www/html/.cache/kworker` |
| Network activity | None | **3 outbound connections** to mining pools |
| CPU usage | Minimal | **94.2% sustained** |

### What the connections tell us

Three persistent TCP connections are established from PID 8834:

| Foreign Address | Port | Protocol | Purpose |
|-----------------|------|----------|---------|
| 185.243.115.89 | 4443 | stratum+tcp | Monero mining pool #1 |
| 91.121.87.10 | 8080 | stratum+tcp | Monero mining pool #2 (fallback) |
| 104.238.140.32 | 3333 | stratum+tcp | Monero mining pool #3 (fallback) |

The `stratum` protocol is the standard communication layer used by cryptocurrency
mining software to communicate with mining pools. The wallet address in `config.json`
(`48Bv3...Kj2`) is a Monero (XMR) wallet format.

### Conclusion

**This is a XMRig (or similar) cryptocurrency miner disguised as a kernel worker
process.** It was placed in `/var/www/html/.cache/` — the Apache web root — and is
running under the `www-data` account, which is the Apache service user. This strongly
indicates the attacker gained initial access through an Apache vulnerability and
dropped the miner payload into the web server's writable directory.

The `config.json` reveals deliberate configuration:
- `donate-level: 0` — the attacker disabled XMRig's built-in developer donation
- `background: true` — runs silently without a terminal
- `cpu-priority: 5` and `threads: 4` — maximizes CPU utilization on this 4-vCPU host
- Three pool entries — redundancy ensures mining continues if one pool goes offline

This is not opportunistic. This is a configured, persistent, purpose-built
cryptomining operation.

---

## 2. Real Compromise Classification: Beyond the Visible Symptom

The visible symptom — CPU saturation causing billing application slowdown — is an
**Availability** impact. But it is the *last* domino to fall. Two CIA pillars were
violated before availability was ever affected:

### Primary Violation: Integrity

The server's filesystem and execution state were modified without authorization.

| Evidence | Integrity Impact |
|----------|------------------|
| Binary dropped at `/var/www/html/.cache/kworker` | Unauthorized file written to web root |
| Process executing as `www-data` (not a legitimate admin action) | Unauthorized code execution on the system |
| `config.json` created in `.cache/` directory | Configuration persistence mechanism |
| Hidden in `.cache` subdirectory of Apache web root | Deliberate concealment of attacker presence |
| Masquerading as kernel thread `kworker` | Deception — process naming designed to evade casual observation |

The attacker didn't just "use resources." They **modified the system**, placed
malicious binaries on disk, and altered the server's runtime state. The integrity
of billing-srv-01 as a trusted computing platform was compromised from the moment
the binary was written to disk.

### Secondary Violation: Confidentiality

The attacker has an active foothold running as `www-data`, the Apache service account.
This account has access to:

| Asset | Exposure |
|-------|----------|
| Apache web root (`/var/www/html/`) | Potential PHI served through billing web application |
| MySQL database on localhost:3306 | Billing/claims data, potentially including patient identifiers |
| Internal network segment (10.10.0.0/16) | Flat network means lateral access to EHR, PACS, AD, and other critical systems |
| SSH service reachable from 10.10.1.50 | Active SSH session suggests further access is possible |

Additionally, the established SSH session from `10.10.1.50` (an internal address)
raises the question: is that the attacker connecting back in, or is it a legitimate
admin session? Either way, the compromised `www-data` account has visibility into
internal services that an external attacker should never possess.

The flat network architecture documented by Marcus amplifies this risk exponentially.
A foothold on billing-srv-01 is a foothold on the same network as:

- EHR servers (ehr-srv-01, ehr-db-01)
- PACS imaging server (pacs-srv-01)
- Domain controllers (ad-dc-01, ad-dc-02)
- File shares containing mixed internal/PHI data (file-srv-01)
- Network-connected medical devices (infusion pumps, patient monitors)

### Summary Classification

| CIA Pillar | Status | When It Was Compromised | Severity |
|------------|--------|------------------------|----------|
| **Integrity** | ✗ COMPROMISED | At exploit/payload delivery (~14 days ago) | Critical — unauthorized code execution |
| **Confidentiality** | ✗ COMPROMISED | From moment of foothold establishment | High — potential for data exfiltration and lateral movement |
| **Availability** | ✗ COMPROMISED | Secondary effect of sustained mining | Medium — billing slowdown (the visible symptom) |

The availability impact — the only thing the IT team noticed — is the **least
significant** security violation on this system. It is the smoke; integrity and
confidentiality failures are the fire.

---

## 3. Why the Sysadmin's Solution Fails

### The proposed fix

> *"Server is 4 years old with 8GB RAM and 4 vCPUs. Probably undersized for the
> billing workload. Recommend migration to a new VM with 16GB RAM and 8 vCPUs."*
> — Tom Reeves, Sysadmin (Ticket #4471)

### Why it would not resolve the security problem

| Scenario | Outcome |
|----------|---------|
| **Hardware upgrade on same server** | Miner gets more CPU threads to consume (config allows upscaling). Problem persists or worsens. |
| **Migration to new VM (same OS image)** | If migrated via snapshot/clone, the miner binary, persistence mechanism, and Apache vulnerability travel to the new VM intact. Fresh hardware, same compromise. |
| **Migration to new VM (clean install, unpatched Apache)** | Attacker re-exploits the same Apache RCE vulnerability and reinfects. Fresh hardware, new compromise, same root cause. |
| **Migration to new VM (clean install, patched Apache)** | This *might* work — but only because it inadvertently removes both the vulnerability AND the payload. However, if the attacker established other persistence mechanisms (cron jobs, SSH keys, systemd services) that the diagnostics didn't capture, the compromise could survive even a "clean" migration. |

### The fundamental error

The sysadmin is treating a **security incident** as an **infrastructure capacity
issue**. This is dangerous for several reasons:

1. **Symptom masking:** Upgrading hardware gives the miner more resources. It may
   stop triggering CPU alerts (because there's enough CPU for both the miner and
   the billing app), making the compromise harder to detect while it continues
   indefinitely.

2. **Root cause survives:** The Apache vulnerability (likely CVE-2021-41773,
   CVE-2021-42013, or similar path traversal/RCE affecting Apache 2.4.29) remains
   unpatched. The server remains exploitable.

3. **Attacker retains access:** Even with upgraded hardware, the attacker maintains
   their foothold. They can escalate to additional malware, exfiltrate data, or
   deploy ransomware again at any time.

4. **False resolution:** The ticket gets closed. The problem looks solved. No
   security investigation occurs. No incident response is triggered. No forensics
   are performed. No containment, eradication, or lessons learned occur.

5. **Wasted budget:** Money spent on hardware does not address a security breach.
   The organization pays for a bigger server that is still compromised.

### What the correct response should be

1. **CONTAIN:** Immediately isolate billing-srv-01 from the network (not just shut down — disconnect network cable/vNIC). Preserving volatile evidence requires the system to remain powered on but isolated.

2. **INVESTIGATE:** Capture forensic evidence:
   - Memory dump (the running process and its environment)
   - Disk image (binary, config, Apache logs, auth logs, cron jobs)
   - Network traffic captures (identify all C2 connections and data movement)
   - Apache access logs (identify the exploit attempt)

3. **ERADICATE:** Rebuild from a known-good image, NOT from the current server's backup. Patch Apache to current version. Apply all OS patches (Ubuntu 18.04 is approaching EOL — migrate to Ubuntu 22.04 or 24.04 LTS).

4. **REMEDIATE:** Fix the Apache vulnerability that allowed initial access. Audit all other servers running Apache for the same vulnerability. Review whether the January ransomware used the same entry point.

5. **RECOVER:** Restore billing data from verified-clean backup. Validate data integrity before returning to production.

6. **DETECT:** Deploy monitoring for:
   - Unexpected outbound connections from servers
   - Processes masquerading as system threads
   - Files written to web directories
   - CPU patterns inconsistent with application baselines

7. **DOCUMENT:** Formal incident report. This is a confirmed compromise, not a performance issue.

---

## 4. Connection to the January Ransomware Incident

### Timeline Reconstruction

| Date | Event | Evidence |
|------|-------|----------|
| Pre-January | Performance issues begin on billing-srv-01 | Marcus's note: "performance issues started before the ransomware and have returned after the rebuild" |
| ~Jan 12–13 | Ransomware payload deployed | Incident A (January 15) — ransomware encrypts billing server over the weekend |
| ~Jan 14–15 | Discovery and response | Finance team finds billing inaccessible; 4-day recovery; 3-week-old backup used |
| Post-January | Server rebuilt | Marcus's note: "This server was rebuilt after the January ransomware" |
| ~14 days ago (relative to diagnostics) | Cryptominer deployed to rebuilt server | File timestamps: `/var/www/html/.cache/kworker` created 14 days ago |
| Present | Recurring "performance degradation" reported | Third ticket this month; sysadmin recommends hardware upgrade |

### What This Pattern Reveals

Two completely different malware payloads — ransomware and a cryptominer — hit the same server within months. This is not coincidence. It indicates an **unresolved, externally exploitable vulnerability** that serves as a persistent open door.

Specifically, Marcus identified the likely culprit: **Apache 2.4.29** running on the server. This version is vulnerable to multiple known CVEs:

- **CVE-2021-41773** — Path traversal leading to remote code execution
- **CVE-2021-42013** — Extension of the above (the initial fix was incomplete)

Both allow an unauthenticated remote attacker to execute arbitrary code on the server through crafted HTTP requests. The miner binary resides in `/var/www/html/.cache/`, which is within the Apache web root — exactly where a path traversal exploit would write a payload.

### The Critical Question

**Was the Apache vulnerability patched when the server was rebuilt after the January ransomware attack?**

If the answer is no — and the evidence strongly suggests it is — then the rebuild was treating a symptom (ransomware payload) without addressing the root cause (exploitable Apache vulnerability). The server was handed back to IT, reconnected to the network, and the attacker (or a different attacker, or an automated bot) simply walked through the same open door and installed a different payload.

This is the definition of the **symptom trap**: responding to security incidents by removing the malware without fixing how it got in. It guarantees recurrence.

### Broader Implications for the Assessment

This finding should immediately trigger a review of every server in the environment:

| Server | Same Risk? | Action Needed |
|--------|-----------|---------------|
| web-srv-01 | **Yes** — public-facing, likely same Apache version | Urgent patch audit |
| ehr-srv-01 | Possibly — if Apache-backed | Patch audit |
| All Central servers | Unknown — OS versions vary | Comprehensive vulnerability scan |

If billing-srv-01 was compromised twice through the same vulnerability, the same vulnerability may exist on other servers that simply haven't been targeted yet (or haven't been noticed yet).

---

## Recommendations for James Chen

### Immediate (Today)

1. **Isolate billing-srv-01** from the network — this is an active, ongoing compromise
2. **Preserve evidence** — do not wipe the server; capture forensic image first
3. **Check web-srv-01** — it is the other public-facing Apache server and the most likely candidate for identical compromise
4. **Notify leadership** — this is not a performance ticket; it is a confirmed security breach with potential PHI exposure

### Short-Term (This Week)

5. **Scan all servers** for the same Apache vulnerability (version 2.4.29 or older)
6. **Review Apache access logs** on billing-srv-01 for exploit traces
7. **Audit network traffic** from billing-srv-01 for signs of lateral movement or data exfiltration during the 14-day compromise window
8. **Patch or decommission** all vulnerable Apache instances

### Structural (For the Board Report)

9. **Implement server hardening standards** — no system should reach production with known-unpatched vulnerabilities
10. **Deploy EDR/XDR** — Sophos endpoint protection should have caught a cryptominer; investigate why it didn't (is it even installed on Linux servers?)
11. **Establish rebuild procedures** that mandate vulnerability remediation, not just malware removal
12. **Create incident response playbook** — the sysadmin should never independently "resolve" what is actually a security incident without security team involvement
