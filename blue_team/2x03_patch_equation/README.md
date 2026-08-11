# Introduction

>    "The window between disclosure and exploitation is measured in hours. The window between patch availability and deployment is measured in months." 
>
> — Mandiant M-Trends, 2024

You hardened billing-srv-01. You instrumented every endpoint. Sysmon, auditd, Script Block Logging: the defensive layer is in place. Then, at 08:14 this morning, Dr. Morales forwards you a CISA advisory. Three critical CVEs landed overnight: a kernel privilege escalation in linux-image (CISA KEV, active exploitation), an openssh-server pre-authentication RCE and a TLS parsing bug in libssl3. Every server you hardened is on the affected list.

Hardening decays. sysctl values, AppArmor profiles, PAM policies do not change by themselves, but the software they protect does. Every week, new CVEs are published. Every month, vendors ship patches. And every quarter, some hospital somewhere gets breached through a vulnerability that had a fix available for 180 days. The advisory was explicit: in 4 of 5 hospital breaches, the compromised software had a patch sitting in the repository the whole time.

This project treats patching as engineering, not housekeeping. You will build a pipeline that measures vulnerability exposure, maps which services a patch can break, snapshots state before touching anything, applies patches safely, validates the outcome, detects configuration drift, recovers a broken apt state, rolls back when a patch regresses and tracks every change as structured data. No policy writing. No change request templates. No maintenance window calendars. Only scripts and JSON. The organizational process sits on top of this later, but the engine underneath has to work first.
Why this matters

Patching is the most boring and most dangerous operation in endpoint security. Boring because nothing visibly changes when it works. Dangerous because one unattended apt upgrade -y can brick a billing server at 02:00 on a Sunday. The engineers who get this right build the inventory, the snapshot, the validation, the rollback and the compliance artifact as code. Everything in this project is deterministic, measurable and replayable. When Dr. Morales asks "are we vulnerable to CVE-2024-1086 right now ?", the answer is not an opinion. It is a JSON file produced by a script you wrote.
Context

## Week eight at MedDefense Health Systems. Thursday morning.

Dr. Patricia Morales drops a printed CISA advisory on your desk. The email chain above it is three hours old.

"Three CVEs. All critical. All affect packages running on our Linux fleet. The kernel one is in CISA KEV with active exploitation. The OpenSSH one dropped yesterday and there are already proof-of-concepts on GitHub. And libssl3 affects every TLS connection on every server. I need to know three things by tonight: which of our systems are exposed, what a patch to each of those systems would break and how fast we can safely roll them out."

She turns to the whiteboard and writes the CVEs.

"And I do not want a Word document. I want a pipeline. If I get another one of these advisories next week, I do not want to redo this work. I want to run one script, hand me a JSON report and know in five minutes which of our servers is a risk."

James Chen arrives with additional context:

"One more thing. billing-srv-01 has a broken apt state from an interrupted upgrade last week. Mike Torres ran apt upgrade -y without a maintenance window, the session died halfway through, and nobody fixed it. dpkg is locked, apache2 is half-configured. Add that to your list. I want the broken state recovered by the same pipeline that handles the new advisory."

Sarah Park adds the constraint that matters most:

"Whatever you build, it runs against production. No staging environment. No lab doubles. So the pipeline has to be safe by default: measure first, then change, then validate and always keep the rollback path open."

---

# [0. The Vulnerability Inventory](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/0-vuln_inventory.sh)

## Goal: 

Enumerate every installed package on the hardened endpoint and produce a structured inventory of known vulnerabilities, using only native distribution tooling and a provided CVE feed.

## Context: 

Dr. Morales asked "which of our systems are exposed". You cannot answer that question without first knowing exactly which packages are installed and which of those have outstanding security updates. This is the measurement step that every other task in the project depends on.

## Instructions: 

Write a script 0-vuln_inventory.sh that produces a complete vulnerability inventory for the current system. The script must:

    Enumerate all installed packages using dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n'

    Cross-reference the installed set against apt list --upgradable to identify packages with available security updates

    For each upgradable package, extract the source pocket (security, updates, backports) from apt-cache policy

    For each security-pocket upgrade, extract CVE identifiers from the changelog entries via apt-get changelog when reachable, falling back to the locally cached Ubuntu Security Notice (USN) mapping shipped in /usr/share/ubuntu-advantage-tools when present

    Classify each vulnerable package by severity using CVSS base scores provided in a companion JSON feed cve_feed.json (supplied in the project directory)

    Emit a structured vulnerability_inventory.json with one entry per vulnerable package containing: package, installed_version, candidate_version, source_pocket, cves (array), max_cvss, severity, in_cisa_kev (boolean)

Note: the cve_feed.json is a snapshot for the exercise. Your script must not fail if a CVE is missing from it.

**Expected Output:**

```bash
$ sudo ./0-vuln_inventory.sh

$ jq '.packages[] | select(.in_cisa_kev==true)' vulnerability_inventory.json
{
  "package": "linux-image-generic",
  "installed_version": "5.15.0-91.101",
  "candidate_version": "5.15.0-97.107",
  "source_pocket": "jammy-security",
  "cves": ["CVE-2024-1086"],
  "max_cvss": 7.8,
  "severity": "high",
  "in_cisa_kev": true
}
```

---

# [1. The Service Dependency Map](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/1-service_deps.sh)

## Goal: 

Map each installed package to the services that depend on it, so that a patch to a library tells you which services will need a restart or a regression test.

## Context: 

A patch to libssl3 does not touch libssl3 in isolation. It touches every service that links against it: openssh-server, apache2, postgresql, curl. Before you plan a patch rollout, you need to know which services each package update will disturb. This task produces that map.

## Instructions: 

Write a script 1-service_deps.sh that builds a service-to-package dependency map for the current host. The script must:

    List every active systemd unit of type service using systemct

    For each service, resolve the executable path from the unit file (ExecStart=) or from systemctl show -p MainPID plus readlink /proc/<pid>/exe

    For each executable, resolve the owning package via dpkg -S

    For each executable, list its dynamic library dependencies with ldd and resolve each library to its owning package via dpkg -S

    Tag each service with a criticality label driven by a provided service_criticality.json file (values: critical, high, medium, low). Services not listed default to low.

    Emit service_dependency_map.json with one entry per service containing: service, exec_path, owning_package, linked_packages (array), criticality, restart_required_on_patch (boolean). Parse it with jq

Hint: needrestart -b can cross-check your result.

**Expected Output:**

```bash
$ sudo ./1-service_deps.sh

$ cat service_dependency_map.json
{
  "service": "apache2.service",
  "linked_packages": ["apache2", "libc6", "libssl3"]
}
{
  "service": "ssh.service",
  "linked_packages": ["openssh-server", "libc6", "libssl3"]
}
```

---

# [2. The Pre-Patch Snapshot](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/2-pre_patch_snapshot.sh)

## Goal: 

Capture the full state of the system before any patch operation, so that every subsequent change can be measured against an exact baseline.

## Context: 

The only way to prove that a patch fixed the problem without creating a new one is to compare the after-state against an exact before-state. This snapshot is the reference point for every validation task that follows. If you skip this step, you are flying blind.

## Instructions: 

Write a script 2-pre_patch_snapshot.sh that captures the state required to validate and roll back patch operations. The script must:

    Record package versions for every installed package via dpkg'

    Record service state for every active systemd service: ActiveState, SubState, MainPID

    Record listening sockets via ss -tulnp

    Record SHA-256 hashes of every configuration file under /etc that is tracked by a package (use dpkg' to obtain the list)

    Record kernel release (uname -r) and any pending reboot indicator (/var/run/reboot-required presence)

    Emit pre_patch_state.json with top-level keys: timestamp, hostname, kernel, packages, services, listening, conffile_hashes, reboot_required

Hint: the JSON should be re-readable by later tasks. Keep the schema stable.

**Expected Output:**

```bash
$ sudo ./2-pre_patch_snapshot.sh
Snapshot: pre_patch_state.json
Size: 214 KB
Kernel: 5.15.0-91-generic
Reboot required: false

$ cat pre_patch_state.json
{
  "hostname": "billing-srv-01",
  "kernel": "5.15.0-91-generic",
  "packages": 1247,
  "services": 24
}
```

---

# [3. The Patch Plan](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/3-patch_plan.sh)

## Goal: 

Cross-reference the vulnerability inventory with the service dependency map to produce a prioritized, ordered patch plan that explicitly names the services each patch will disturb.

## Context: 

You now have two structured datasets: what is vulnerable (T0) and what depends on what (T1). The patch plan is the join between them, filtered through prioritization criteria. The output is the execution order for the next task.

## Instructions: 

Write a script 3-patch_plan.sh that reads vulnerability_inventory.json and service_dependency_map.json and produces an ordered patch plan. The script must:

    For each vulnerable package, compute a priority score using: cvss_weight * max_cvss + kev_weight * in_cisa_kev + criticality_weight * max(criticality of linked services) + exposure_weight * exposure_rank. Weights are defined as constants at the top of the script.

    Rank packages by priority score (highest first)

    For each ranked entry, compute: affected_services (array from T1), requires_restart (boolean), requires_reboot (true only if kernel or systemd itself), rollback_target_version (currently installed version)

    Classify each patch into one of three buckets: emergency (score >= 7), urgent (4 <= score < 7), scheduled (score < 4)

    Emit patch_plan.json with generated_at, weights, plan (ordered array) and a summary block

Note: this is a deterministic join. The same inputs must produce the same plan.

**Expected Output:**

```bash
$ ./3-patch_plan.sh
Emergency: 1   Urgent: 3   Scheduled: 2
Reboot required by plan: yes (kernel update present)
Report saved to: patch_plan.json

$ cat patch_plan.json
{
  "rank": 1,
  "package": "linux-image-generic",
  "score": 8.14,
  "bucket": "emergency",
  "affected_services": ["(kernel-wide)"]
}
{
  "rank": 2,
  "package": "libssl3",
  "score": 6.62,
  "bucket": "urgent",
  "affected_services": ["apache2.service", "ssh.service", "mysql.service"]
}
```

---

# 
