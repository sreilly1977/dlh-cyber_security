0. The Baseline Snapshot

Goal: Capture the complete security state of a system before any changes, establishing the measurement that every subsequent task will improve against.

Context: You cannot prove hardening worked if you do not know where you started. This task captures the system as it is: unhardened, default configuration, every setting at its out-of-the-box value. Every number you record here is the number you will improve.

Instructions: Write a script 0-baseline_snapshot.sh that captures the complete security baseline of a Linux system. The script must:

    Record system identification (hostname, OS, kernel version, uptime)

    List all running services and their state

    List all open ports and listening sockets

    List all SUID and SGID binaries

    List all world-writable files (excluding /proc, /sys, /dev)

    Capture current sysctl security-relevant parameters

    Capture current SSH configuration settings

    Record active user accounts and sudo group membership

Expected Output:

```bash
$ sudo ./0-baseline_snapshot.sh
Hostname: billing-srv-01
OS: Ubuntu 22.04.3 LTS
Running services: 24
Open ports: 11
SUID binaries: 23
SGID binaries: 12
World-writable files: 7
```

---

1. MedDefense CIS Control Profile

Goal: Build a threat-driven CIS hardening profile for MedDefense Linux servers that becomes the input for later remediation tasks.

Context: The original CIS priority task leaned too heavily toward manual benchmark interpretation. In this project, scripts are the primary deliverable. This rebuilt task turns CIS prioritization into a structured, reusable control profile that later scripts can consume.

MedDefense does not need a generic list of CIS recommendations. It needs a focused control profile for billing-srv-01, web-srv-01, and log-srv-01, tied to the project's actual risks: SSH lateral movement, weak authentication, unnecessary services, missing audit visibility, exposed database services, and insufficient kernel hardening.

Instructions: Write 1-cis_profile.sh.

The script must generate cis_profile.json containing exactly 15 controls. Each control must include:

    control_id
    title
    cis_section
    severity (critical, high, or medium)
    asset_scope
    threat_mapping
    implementation_task
    verification_method
    justification

The selected controls must cover SSH, kernel/sysctl hardening, PAM, service minimization, filesystem permissions, audit logging, firewall exposure, and log retention.

Expected Output:

```bash
$ ./1-cis_profile.sh
Controls selected: 15
Critical: 5
High: 7
Medium: 3
CIS sections covered: 5
Mapped implementation tasks: 10
Report saved to: cis_profile.json
'''
