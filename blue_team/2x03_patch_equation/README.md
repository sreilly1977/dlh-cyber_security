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

# [4. The Safe Patch Execution](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/4-patch_execute.sh)

## Goal: 

Apply the planned patches in order, with per-patch pre-check and post-check, while recording every action as a structured execution log.

## Context: 

The plan is the intent. This task is the execution. Every patch that runs must log what it touched, how long it took, whether it succeeded and which services were affected. If the script is interrupted, the log must still be consistent up to the point of interruption.

## Instructions: 

Write a script 4-patch_execute.sh that consumes patch_plan.json and executes the plan safely. The script must:

    Acquire an advisory lock in /var/lock/meddefense-patch.lock so that two instances cannot run concurrently

    For each entry in patch_plan.json, in order:

        Record pre block: installed version, service states for linked services

        Run apt-get install --only-upgrade -y <package> with DEBIAN_FRONTEND=noninteractive

        Record the exit status, stdout and stderr

        Record post block: installed version, service states for linked services

        If requires_restart is true and no reboot is needed: attempt systemctl try-restart on each affected service and record the result

        If the apt call fails: mark the entry as failed, stop the loop and continue to finalization (do not abort the whole script)

    Handle a busy dpkg lock gracefully: on E: Could not get lock, wait up to 120 seconds with exponential backoff, then fail the entry with a clear reason

    Emit patch_execution_log.json containing: started_at, finished_at, hostname, plan_source_hash, entries (array of per-package objects with pre, post, status, duration_seconds, stdout_tail, stderr_tail)

    Exit with code 0 if all entries succeeded, 1 if any entry failed, 2 if the lock could not be acquired

Hint: use trap to ensure the lock is released even on abort.

**Expected Output:**

```bash
$ sudo ./4-patch_execute.sh
[*] Acquiring lock /var/lock/meddefense-patch.lock...  OK
[*] Loading plan: patch_plan.json (6 entries)
[1/6] linux-image-generic   emergency     apt-get ... OK (12.4s)
[2/6] libssl3               urgent        apt-get ... OK (3.1s)
      try-restart apache2.service         OK
      try-restart ssh.service             OK
      try-restart mysql.service           OK
[3/6] openssh-server        urgent        apt-get ... OK (2.8s)
      try-restart ssh.service             OK
[4/6] curl                  urgent        apt-get ... OK (1.9s)
[5/6] libpam-modules        scheduled     apt-get ... OK (2.2s)
[6/6] tzdata                scheduled     apt-get ... OK (1.4s)
Succeeded: 6  Failed: 0
Log saved to: patch_execution_log.json
```

---

# [5. The Post-Patch Service Validation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/5-post_patch_validate.sh)

## Goal: 

Prove that every critical service is running, listening on its expected port and responding correctly after the patch run, by comparing the current state to the pre-patch snapshot.

## Context: 

An apt command that exits 0 is not proof of anything. The package may have installed, but the service may have failed to restart, may now listen on a different socket or may refuse traffic. Validation closes the loop by comparing the actual post-patch behavior against the pre-patch baseline.

## Instructions: 

Write a script 5-post_patch_validate.sh that reads pre_patch_state.json and the live system, and emits a validation report. The script must:

    For every service present in the pre-patch services block: verify it is in the same ActiveState or better (anything other than active is a regression)

    For every socket present in the pre-patch listening block: verify the port is still listening

    For every service marked critical in service_dependency_map.json: run a lightweight liveness probe defined in a companion service_probes.json file (curl URL, mysqladmin ping, ssh -o BatchMode=yes etc.)

    Classify each check as pass, regression, or probe_failed

    Emit post_patch_validation.json with: total_checks, passed, failed, details (array of per-check objects)

    Exit with code 0 if all passed, 1 if any regression or probe failure is detected

**Expected Output:**

```bash
$ sudo ./5-post_patch_validate.sh
Service state checks:     24/24   PASS
Listening socket checks:  11/11   PASS
Critical liveness probes: 3/3     PASS
VERDICT: PASS (38/38)
Report saved to: post_patch_validation.json

$ jq '.details[] | select(.status!="pass")' post_patch_validation.json
# (empty, no regressions)
```

--- 

# [6. The Configuration Drift Detector](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/6-config_drift.sh)

## Goal: 

Detect every configuration file that changed during the patch run, distinguishing expected changes introduced by the new package versions from unexpected modifications that require investigation.

## Context: 

Patches often ship updated configuration defaults. Most of the time the package manager asks whether to keep the existing config or use the new one, and a noninteractive run defaults to keeping yours. But sometimes a patch silently updates an auxiliary config file under /etc, and that change can reintroduce a previously hardened setting. Drift detection catches this.

## Instructions: 

Write a script 6-config_drift.sh that compares pre_patch_state.json conffile hashes against current hashes. The script must:

    Load the conffile_hashes block from pre_patch_state.json

    Recompute the SHA-256 of every file still present in the list

    Classify each file as unchanged, modified, missing, or new (for tracked conffiles added by the patch)

    For each modified file, capture a unified diff truncated to 40 lines via diff -u

    Cross-reference modifications against patch_execution_log.json to mark drift as expected (the owning package was upgraded during this run) or unexpected (drifted without an owning upgrade)

    Emit config_drift.json containing summary (counts per classification) and files (array of per-file objects)

    Exit with code 0 if there is no unexpected drift, 1 otherwise

**Expected Output:**

```bash
$ sudo ./6-config_drift.sh

$ cat config_drift.json
{"path":"/etc/ssh/sshd_config","owning_package":"openssh-server","expected":true}
{"path":"/etc/ssl/openssl.cnf","owning_package":"openssl","expected":true}
```

---

# [7. The Broken Upgrade Recovery](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/7-apt_recovery.sh)

## Goal: 

Diagnose and repair a Linux system left in a broken package state by an interrupted upgrade, restoring every service to a working state and emitting a structured recovery report.

## Context: 

James mentioned it: billing-srv-01 has leftover damage from Mike Torres's aborted apt upgrade -y. dpkg is locked, apache2 is half-configured, libapache2-mod-php is unpacked but not set up. Recovery is a specific sequence: never the same command twice, never out of order. One wrong step and you make it worse.

## Instructions: 

Write a script 7-apt_recovery.sh that diagnoses and repairs a broken apt/dpkg state. The script must:

    Diagnose before changing anything:

        Check for live dpkg or apt processes with pgrep -fa

        Inspect /var/lib/dpkg/lock-frontend, /var/lib/dpkg/lock, /var/cache/apt/archives/lock

        Run dpkg --audit and parse the output

        List packages in half-configured, half-installed, unpacked or triggers-pending state via dpkg'

        Check free space on / and /var

    Refuse to proceed if a live dpkg or apt process is detected: emit the diagnosis and exit with code 2

    Repair in a strict order:

        Remove only stale lock files (and only after confirming no live process holds them)

        Run dpkg --configure -a

        Run apt-get --fix-broken install -y with noninteractive

        Re-run dpkg --audit and confirm the output is empty

    Restart any service listed in service_dependency_map.json whose package was in the broken set

    Emit apt_recovery.json with: initial_diagnosis, actions_taken (ordered array), final_state, recovered (boolean), duration_seconds

    Exit 0 on success, 1 on residual broken state

Hint: the lab ships a broken-state setup script. Run it, then run your recovery, then re-run the diagnosis to confirm clean.

**Expected Output:**

```bash
$ sudo ./7-apt_recovery.sh
[*] Diagnosing...
    live dpkg/apt processes: none
    stale locks: /var/lib/dpkg/lock-frontend, /var/lib/dpkg/lock
    dpkg --audit: apache2, libapache2-mod-php8.1, mysql-server-8.0
    broken packages: 3
[*] Repairing...
    remove stale locks                     OK
    dpkg --configure -a                    OK
    apt-get --fix-broken install           OK
    dpkg --audit (re-run)                  clean
[*] Restarting affected services...
    apache2.service                        active
    mysql.service                          active
RECOVERED: yes
Duration: 38s
Report saved to: apt_recovery.json
```

---

# [8. The Unattended Upgrades Configuration](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/8-unattended_config.sh)

## Goal: 

Configure unattended-upgrades so that low-risk security patches land automatically, while critical packages are protected by blacklist and automatic reboots are suppressed for healthcare systems.

## Context: 

Not every patch needs a human in the loop. Library updates, utility patches, minor security fixes in non-critical packages are the kind of work that should happen on its own, every night, without asking. But automation without guardrails is how billing-srv-01 got broken in the first place. This task builds the guardrails.

## Instructions: 

Write a script 8-unattended_config.sh that configures unattended-upgrades for MedDefense. The script must:

    Install unattended-upgrades if it is not present

    Write /etc/apt/apt.conf.d/50unattended-upgrades with:

        Allowed origins: ${distro_id}:${distro_codename}-security only

        Unattended-Upgrade::Package-Blacklist containing: linux-image*, linux-headers*, mysql-server*, apache2*, libapache2-mod-php*

        Unattended-Upgrade::Automatic-Reboot "false";

        Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";

        Mail notifications disabled (no mail system assumed in lab)

    Write /etc/apt/apt.conf.d/20auto-upgrades enabling the daily timer

    Enable and start apt-daily.timer and apt-daily-upgrade.timer

    Execute unattended-upgrades --dry-run --debug and parse its output to confirm that blacklisted packages are correctly skipped

    Emit unattended_config.json with: installed, config_paths, blacklist, timer_state, dry_run_summary (counts: would_upgrade, skipped_blacklisted, skipped_held)

Note: the script must be idempotent. Re-running it must not duplicate entries in the config files.

**Expected Output:**

```bash
$ sudo ./8-unattended_config.sh
[*] unattended-upgrades: already installed
[*] Writing /etc/apt/apt.conf.d/50unattended-upgrades...   OK
[*] Writing /etc/apt/apt.conf.d/20auto-upgrades...         OK
[*] Enabling timers...                                     OK
[*] Dry run...
would upgrade:       4
skipped (blacklist): 2 (linux-image-generic, apache2)
skipped (held):      0
Report saved to: unattended_config.json
```

---

# [9. The Rollback Capability](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/9-rollback.sh)

## Goal: 

Implement a package downgrade workflow that restores a specific package to its pre-patch version, validates that dependent services come back up, and proves that rollback is a real capability rather than a promise.

## Context: 

Every patch you apply must be reversible. The rollback path is not optional and it is not a runbook entry that somebody reads at 03:00. It is a script that takes a package name as an argument and returns that package to the version recorded in the pre-patch snapshot.

## Instructions: 

Write a script 9-rollback.sh that downgrades a package to its pre-patch version. The script must:

    Accept a single positional argument: the package name.

    Load the target version from pre_patch_state.json using packages[<name>].

    Fail with a clear message if the package is not present in pre_patch_state.json.

    Confirm the target version is available in the local package cache or resolvable from the repository using apt-cache madison.

    Execute the rollback using:

DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades <package>=<version>

    Apply apt-mark hold <package> after a successful downgrade so that unattended-upgrades does not immediately re-upgrade it.

    Re-run the lightweight probes from Task 5 for every service in service_dependency_map.json whose linked_packages contains the rolled-back package.

    Print a clear rollback summary showing:

    package name
    current version before rollback
    target version from the snapshot
    whether version availability was confirmed
    whether downgrade succeeded
    whether package hold was applied
    affected service probe results

    Exit 0 only if the downgrade, hold, and all affected service probes succeed.

    Exit 1 on any failure.

**Expected Output:**

```bash
$ sudo ./9-rollback.sh <package>
[*] Target version from pre_patch_state.json: <version>
[*] Version available in cache or repository: yes
[*] Downgrading <package>...                              OK
[*] apt-mark hold <package>                               OK
[*] Re-running probes for affected services...
    <service-name> probe                                  PASS
ROLLBACK: success
from <current_version> to <target_version>
```

---

# [10. The Version Hold Management](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/10-version_hold.sh)

## Goal: 

Manage apt-mark holds and preference pins as data, so that every held package has a recorded reason, a review date and a single source of truth readable by automation.

## Context: 

A held package without a recorded reason becomes permanent by accident. Six months later nobody remembers why mysql-server is pinned and nobody dares touch it. Hold management is the discipline that prevents this: every hold has an entry in a JSON registry with a reason, an owner and a review date, and the script is the only thing that changes the state.

## Instructions: Write a script 10-version_hold.sh that manages package holds and pins as a data-driven operation. The script must:

    Read a declarative input file hold_registry.json with the schema:

    { "holds": [
        {"package": "mysql-server-8.0", "reason": "billing app v8.0.35 dependency",
         "owner": "analyst", "review_date": "2026-05-28", "pin_version": "8.0.35-0ubuntu0.22.04.1"}
    ]}

    For each entry: apply apt-mark hold <package> and write an apt_preferences fragment to /etc/apt/preferences.d/meddefense-pins with Pin-Priority: 1001

    Remove any hold currently present on the system that is not in hold_registry.json (convergence mode)

    For each hold, compute days_to_review from review_date minus today's date

    Emit hold_management.json with: applied (array), released (array), overdue_reviews (array where days_to_review < 0), total_held

Note: the script is the only writer. Never edit apt-mark state or /etc/apt/preferences.d/meddefense-pins manually.

**Expected Output:**

```bash
$ sudo ./10-version_hold.sh
[*] Reading hold_registry.json...           (4 entries)
[*] Reading current apt-mark showhold...    (1 entry)
Applying holds:
  mysql-server-8.0        hold + pin 8.0.35-0ubuntu0.22.04.1   OK
  mysql-client-8.0        hold + pin 8.0.35-0ubuntu0.22.04.1   OK
  libapache2-mod-php8.1   hold + pin 8.1.2-1ubuntu2.14         OK
  php8.1-mysql            hold + pin 8.1.2-1ubuntu2.14         OK
Releasing holds no longer in registry:
  (none)
Overdue reviews: 0
Report saved to: hold_management.json
```

---

# [11. The Maintenance Window Enforcement](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/11-maintenance_window.sh)

## Goal: 

Implement maintenance window control as code: a guard script that refuses to run patch operations outside defined windows and defers them with a machine-readable rationale.

## Context: 

The policy ("only patch inside the window") means nothing if the enforcement is a human being reading the clock. This task turns the window into a predicate: before any patch script runs, it calls the guard. If the guard says "out of window", the operation does not proceed.

## Instructions: 

Write a script 11-maintenance_window.sh that acts as a maintenance window guard. The script must:

    Read a declarative maintenance_windows.json file with the schema:

    { "timezone": "Europe/Paris",
      "windows": [
        {"name": "standard",  "days": ["Sat"],       "start": "02:00", "end": "06:00"},
        {"name": "extended",  "days": ["Sat"],       "start": "00:00", "end": "08:00", "week_of_month": 1},
        {"name": "emergency", "always": true}
      ]}

    Accept a mode argument: --check (exit only), --wait <seconds> (poll until a window opens or timeout), --report (emit JSON only)

    In --check mode: exit 0 if inside a standard or extended window, exit 10 if only emergency applies (requires override env var MEDDEFENSE_EMERGENCY=1), exit 20 if outside all windows

    Emit maintenance_window.json with: now, timezone, active_window (name or null), next_window (name and ISO timestamp), seconds_until_next, decision

    Never change package state. This script is pure decision logic.

Hint: date +%u for day of week, date +%H:%M for local time. Respect the timezone field via TZ=<zone>.

**Expected Output:**

```bash
$ ./11-maintenance_window.sh --check
now:            2026-03-28 14:07 Europe/Paris (Sat)
active window:  standard
decision:       proceed
Report saved to: maintenance_window.json

$ echo $?
0

$ ./11-maintenance_window.sh --check
now:            2026-03-30 10:22 Europe/Paris (Mon)
active window:  (none)
next window:    standard  at 2026-04-04 02:00
seconds until:  403080
decision:       defer

$ echo $?
20
```

---

# [12. The Change Tracking Log](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/12-change_log.sh)

## Goal: 

Produce a canonical, structured change log for every patching activity on the host: what was changed, when, by whom, with what outcome and whether it respected the maintenance window.

## Context: 

Auditors ask one question: "show me every change to this system in the last 30 days and prove it was authorized". A change log written by humans is never complete. A change log produced by a script from /var/log/dpkg.log, /var/log/apt/history.log and the JSON artifacts from earlier tasks is always complete, because it is the same source of truth the system itself uses.

## Instructions: 

Write a script 12-change_log.sh that produces a structured change log for the host. The script must:

    Parse /var/log/apt/history.log* (including rotated files) to extract every apt transaction: start-date, commandline, requested-by, upgrade, install, remove

    Group transactions into "change events" by proximity (transactions within 15 minutes of each other are one event)

    For each change event, enrich it with:

        user from the Requested-By: field

        within_window: call 11-maintenance_window.sh --report against the event timestamp and read the decision

        linked_execution_log: path to patch_execution_log.json if the event timestamps overlap

        cves_resolved: cross-reference against vulnerability_inventory.json entries that are no longer present after the event

    Emit patch_change_log.json with: period_start, period_end, events (ordered array), summary (counts: total_events, inside_window, outside_window, cves_resolved)

    Output must be idempotent across runs: running the script twice on the same logs must produce identical JSON

**Expected Output:**

```bash
$ sudo ./12-change_log.sh

$ cat patch_change_log.json
{"started":"2026-03-21T23:01:05+01:00","user":"mike","within_window":"outside","packages":47}
{"started":"2026-03-28T02:03:12+01:00","user":"analyst","within_window":"inside","packages":6}
{"started":"2026-03-28T02:15:44+01:00","user":"analyst","within_window":"inside","packages":1}
```

---

# [13. The End-to-End Patch Pipeline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x03_patch_equation/13-patch_pipeline.sh)

## Goal: 

Chain every preceding task into a single idempotent pipeline that can be executed by hand today, by cron tomorrow and by another analyst next week, with identical results on identical input state.

## Context: 

You have the parts. The pipeline is the assembly: inventory, dependency map, snapshot, plan, window check, execute, validate, drift, change log. One script, one exit code, one composite JSON artifact that tells the operator what happened.

## Instructions: 

Write a script 13-patch_pipeline.sh that orchestrates the full patch workflow. The script must:

    Run the stages in this exact order, stopping on any stage failure: 0-vuln_inventory.sh, 1-service_deps.sh, 2-pre_patch_snapshot.sh, 3-patch_plan.sh, 11-maintenance_window.sh --check, 4-patch_execute.sh, 5-post_patch_validate.sh, 6-config_drift.sh, 12-change_log.sh

    If 11-maintenance_window.sh --check returns 20 (out of window) and MEDDEFENSE_EMERGENCY is not set: skip stages 4 through 6 and mark the pipeline as deferred

    Capture stdout, stderr, exit code and duration of every stage

    Emit pipeline_run.json with: started_at, finished_at, hostname, pipeline_status (ok, deferred, failed), stages (ordered array), artifacts (map of stage → output JSON path)

    Be idempotent: running the pipeline twice in a row on a clean system must not re-apply already-installed upgrades and must not rewrite unchanged JSON files with different content

    Exit 0 on ok or deferred, 1 on any stage failure

**Expected Output:**

```bash
$ sudo ./13-patch_pipeline.sh
[1/9] 0-vuln_inventory.sh           OK  (2.1s)
[2/9] 1-service_deps.sh             OK  (3.4s)
[3/9] 2-pre_patch_snapshot.sh       OK  (4.8s)
[4/9] 3-patch_plan.sh               OK  (0.3s)
[5/9] 11-maintenance_window.sh      OK  (standard window active)
[6/9] 4-patch_execute.sh            OK  (27.6s, 6 packages)
[7/9] 5-post_patch_validate.sh      OK  (2.9s, 38/38 checks)
[8/9] 6-config_drift.sh             OK  (1.4s, no unexpected drift)
[9/9] 12-change_log.sh              OK  (0.8s, 1 event)
PIPELINE: ok
Duration: 43.3s
Report saved to: pipeline_run.json
```

---

# 
