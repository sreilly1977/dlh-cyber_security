# Week 2 Learning Objectives

## Permissions, SUID & SGID

### What are the three user-based permission groups in Linux?
Owner, group, and others.

### What are the Linux commands `chmod`, `sudo`, `su`, `chown`, and `chgrp` used for?
- `chmod` – Modifies file access rights
- `sudo` – Executes commands with elevated privileges
- `su` – Switches the current user identity
- `chown` – Changes file ownership
- `chgrp` – Changes the associated group

### What is the purpose of the setuid and setgid in Linux file permissions, and how do you use them?
setuid and setgid cause a file to execute with the permissions of its owner or group respectively and are applied using `chmod u+s` or `g+s`.

### What is the difference between the chown and chgrp commands?
`chown` is used to change both the user and group ownership of a file, whereas `chgrp` is restricted to changing only the group ownership.

### What are some best practices for managing file permissions on Linux?
Best practices include:
- Applying the principle of least privilege
- Avoiding world-writable permissions on sensitive files
- Regularly auditing access controls

### How can you audit file permissions changes on your system?
You can audit file permission changes by configuring `auditd` rules to monitor specific paths or by analyzing system logs for relevant syscalls.

### What is Umask in Linux?
Umask is a numeric mask that determines the default file creation permissions by subtracting specified bits from the system's maximum allowable permissions.

---

## MAC (Mandatory Access Control)

### What is MAC in Linux?
MAC (Mandatory Access Control) is a security model where the system enforces access policies that users cannot modify, overriding traditional discretionary permissions.

### How does SELinux enforce MAC?
SELinux enforces MAC by attaching security labels to processes and objects and allowing or denying actions based on configurable policy rules.

### What are the differences between SELinux and AppArmor?
| Feature | SELinux | AppArmor |
|---------|---------|----------|
| Policy Model | Label-based policies | Path-based profiles |
| Granularity | Fine-grained type enforcement | Simpler to configure |

### What is the purpose of policy in MAC systems?
A policy defines the rules governing which interactions between subjects and objects are permitted, serving as the authoritative source for all access decisions.

### How do labels work in SELinux?
Labels assign a security context (user, role, type, and optionally level) to every process and object, and policy rules reference these labels to determine allowed operations.

### What are Type Enforcement, Role-Based Access Control, and Multi-Level Security in SELinux?
- **Type Enforcement** – Governs access by process and object types
- **RBAC** – Restricts which roles can access which types
- **MLS** – Adds hierarchical secrecy levels to prevent unauthorized information flow

### How can you check the status of SELinux on a system?
Run `sestatus` or `getenforce` to see whether SELinux is enabled and whether it is running in enforcing, permissive, or disabled mode.

### What are common SELinux management commands?
Common commands include: `sestatus`, `getenforce`, `setenforce`, `audit2allow`, `restorecon`, `chcon`, and `semanage`.

### How do you set file contexts in SELinux?
Use `chcon` for temporary context changes or `semanage fcontext` with `restorecon` for persistent, policy-backed modifications.

### What is an AppArmor profile?
An AppArmor profile is a set of rules defining what files, capabilities, and network accesses a confined application is permitted to use.

### How do you reload AppArmor profiles?
Run `aa-disable` or `aa-enforce` followed by `apparmor_parser -r <profile>` or simply `systemctl reload apparmor`.

### What is the concept of least privilege in MAC?
Least privilege means granting only the minimum access rights necessary for a process or user to perform their intended function, reducing the attack surface.

### How do you troubleshoot SELinux issues?
Check `/var/log/audit/audit.log` for AVC denials, use `audit2why` and `audit2allow` to interpret them, and temporarily switch to permissive mode to isolate SELinux-related blocks.

### What is the significance of audit logs in MAC systems?
Audit logs record every policy denial and relevant access event, providing visibility into blocked operations and enabling administrators to refine policies.

### Can you explain the concept of capabilities in Linux security?
Capabilities break the monolithic root privilege into distinct units (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`), allowing fine-grained assignment of specific kernel-level permissions to processes without granting full root.

### How do you use semanage?
Use `semanage` to modify SELinux policy components persistently—for example, `semanage fcontext -a -t httpd_sys_content_t "/web(/.*)?"` to add a file context rule, followed by `restorecon -R /web`.

---

## Windows Fundamentals

### What is Windows and how does it differ from other operating systems?
Windows is a proprietary, GUI-centric operating system developed by Microsoft that relies on the NT kernel and closed-source architecture, distinguishing it from open-source or UNIX-like systems.

### What is the Windows architecture and how do kernel mode and user mode interact?
The architecture separates privileged kernel mode (handling hardware and core OS functions) from unprivileged user mode (running applications), with interactions occurring strictly through defined system calls and message passing to ensure stability.

### How does the Windows file system (NTFS) work and what are permissions and ACLs?
NTFS manages data storage using Master File Table records and enforces security via Access Control Lists (ACLs) containing Access Control Entries (ACEs) that define specific allow/deny rules for users and groups.

### What is the Windows Registry and what role does it play in system configuration?
The Registry is a hierarchical database storing low-level settings for the OS and applications, serving as the central repository for configuration data that replaces many legacy text-based config files.

### How does Windows manage users, groups, and access control?
Windows uses Security Identifiers (SIDs) to uniquely identify users and groups, applying access tokens generated at login to enforce permissions against objects secured by ACLs.

### How do you navigate the Windows interface and use built-in administrative tools?
Navigation is primarily graphical via the Start menu and File Explorer, while administrative tasks are performed using tools like Computer Management, Task Manager, PowerShell, and the Settings app.

### What are Windows processes and services and how do you monitor them?
Processes are active program instances running in memory, while services run in the background without direct user interaction; both are monitored and managed via Task Manager or the Services.msc console.

### How do you use the Command Prompt (cmd.exe) for basic system administration?
Command Prompt executes legacy DOS-style commands like `dir`, `ipconfig`, and `netstat` to perform file management, network diagnostics, and system queries in a text-based interface.

### What are Windows Event Logs and how do you read and interpret them?
Event Logs record system, security, and application events chronologically, which administrators analyze using Event Viewer to troubleshoot issues, track security incidents, and monitor system health.

### What built-in security features does Windows provide, such as UAC, Windows Defender, and BitLocker?
Windows includes:
- **User Account Control (UAC)** – To limit privilege escalation
- **Windows Defender** – For real-time antivirus protection
- **BitLocker** – For full-disk encryption of data volumes

### How does Windows handle network configuration and connectivity?
Network configuration is managed through the Network and Sharing Center, PowerShell cmdlets, and the TCP/IP stack settings, utilizing DHCP, DNS, and firewall rules to establish and secure connections.

### What are common Windows-based attack surfaces and how can they be mitigated?
Common attack vectors include:
- Unpatched vulnerabilities → Regular updates
- Weak credentials → Strong authentication policies
- Exposed RDP ports → Firewall restrictions, disable unnecessary services

---

## Forensic Ethics & Methodologies

### What is digital forensics?
Digital forensics is the scientific process of identifying, preserving, analyzing, and presenting digital evidence in a manner that is legally admissible.

### Why is ethics important in digital forensics?
Ethics ensure investigators maintain public trust, protect individual privacy rights, and guarantee that evidence is handled impartially without bias or unauthorized access.

### What are common ethical issues in digital forensics?
Common issues include:
- Privacy violations
- Scope creep during data collection
- Conflicts of interest
- Accidental exposure of sensitive non-relevant information

### What is the role of integrity in forensic analysis?
Integrity ensures that evidence remains unaltered from the time of seizure to presentation in court, typically verified through cryptographic hashing to prove authenticity.

### How does one maintain objectivity in digital investigations?
Objectivity is maintained by following standardized procedures, avoiding preconceived notions about the outcome, and documenting all findings regardless of whether they support the initial hypothesis.

### What are the ACPO principles for computer forensics?
The ACPO principles mandate that:
1. No action should change data
2. An audit trail must be created
3. The investigator must be competent
4. Law enforcement guidance must be followed throughout the process

### How do you ensure evidence is admissible in court?
Evidence is made admissible by strictly adhering to legal standards, maintaining a documented chain of custody, using validated tools, and proving the evidence's authenticity and integrity.

### What is chain of custody and why is it crucial?
Chain of custody is the chronological documentation of who handled evidence, when, and why; it is crucial to prevent tampering claims and establish the evidence's reliability in legal proceedings.

### What are the stages of the digital forensic process?
The standard stages are: identification → preservation → collection → examination → analysis → reporting → presentation (in legal or administrative settings).

### How does one document findings in a forensic report?
Findings are documented in a clear, reproducible report that details the methodology used, tools employed, step-by-step actions taken, and the specific results obtained without interpretation or bias.

### What are some standard digital forensic methodologies?
Standard methodologies include:
- NIST SP 800-86 framework
- Scientific Method applied to digital evidence
- Industry-specific protocols (SANS, IACIS)

### How does one handle digital evidence to preserve its integrity?
Integrity is preserved by:
- Creating bit-for-bit forensic images
- Write-blocking original media
- Calculating hash values before and after analysis
- Storing evidence in secure, controlled environments

### What are some common tools used in digital forensics?
Common tools include:
- **Autopsy** (open source)
- **EnCase**, **FTK** (Forensic Toolkit)
- **Wireshark** for network analysis
- **Write-blockers** (Tableau, WiebeTech hardware)

### What organizations set standards for digital forensic practices?
Key organizations include:
- **NIST** (National Institute of Standards and Technology)
- **ISO** (International Organization for Standardization)
- **SWGDE** (Scientific Working Group on Digital Evidence)
- **ENFSI**

### How do you stay current with evolving technology in forensics?
Investigators stay current through continuous education, attending conferences (like DFRWS), obtaining certifications (CFE, GCFA), and participating in professional communities and training workshops.

### What are the legal implications of digital forensic investigations?
Legal implications involve compliance with:
- Search and seizure laws (Fourth Amendment in the US)
- Data protection regulations (GDPR)
- Potential liability for mishandling evidence or violating privacy
