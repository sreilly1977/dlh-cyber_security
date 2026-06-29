# Week 1 Learning Objectives

## Git

- **Install and configure:** Run `git config --global user.name "Your Name"` and `user.email` after installation.
- **Create repo locally/remote:** Initialize with `git init` locally and link to GitHub via `git remote add origin <url>`.
- **Track changes:** Use `git add` to stage, `git commit` to save to history, distinguishing the working directory from the staging area.
- **Exclude files:** Create a `.gitignore` file listing patterns (like `*.log`) to prevent specific files from being tracked.
- **Push/pull auth:** Sync with `git push` or `git pull`, authenticating via a Personal Access Token instead of your password.
- **Work with branches:** Isolate work using `git checkout -b branch-name` to create and switch contexts safely.
- **Merge conflicts:** Execute `git merge branch-name` and manually edit conflicted files before finalizing with `git commit`.
- **Perform rollbacks:** Use `git reset` to rewrite history locally or `git revert` to create safe, new undo commits.
- **Apply GitHub Flow:** Iterate by branching, committing, pushing, opening Pull Requests, resolving conflicts, merging, and rolling back as needed.

## Introduction to Cyber Security

- **What is Cybersecurity?** It's the practice of protecting systems, networks, and data from digital attacks, theft, or damage.
- **What are the core principles of cybersecurity?** The CIA Triad consists of Confidentiality, Integrity, and Availability.
- **How does encryption contribute to security?** It transforms readable data into unreadable ciphertext to ensure confidentiality even if intercepted.
- **What is risk management in cybersecurity?** It is the process of identifying, assessing, and prioritizing risks followed by coordinated efforts to minimize their impact.
- **What are the different types of cybersecurity threats?** Common threats include malware, phishing, ransomware, DDoS attacks, and insider threats.
- **What is the difference between a virus and a worm?** A virus requires human action to spread, while a worm replicates itself automatically across networks.
- **What is social engineering in the context of security?** It is the psychological manipulation of people into performing actions or divulging confidential information.
- **What are the key components of an information security program?** Essential components include governance, risk management, security controls, awareness training, and incident response.
- **How do security policies and frameworks contribute to an organization's security posture?** They establish standardized rules, procedures, and best practices to consistently manage and mitigate security risks.
- **What is the purpose of the OWASP Top Ten?** It serves as a widely recognized standard awareness document listing the most critical web application security risks.
- **What is the role of access control in cybersecurity?** It ensures that only authorized users and systems can access specific resources based on defined permissions.
- **How does multi-factor authentication enhance security?** It requires multiple forms of verification, significantly reducing the risk of unauthorized access even if one credential is compromised.
- **What are the common methods for securing a network?** Key methods include firewalls, intrusion detection/prevention systems, network segmentation, and regular patching.

## Linux, Shell, Basics

### General

- **RTFM:** "Read The F***ing Manual" — a blunt reminder to check documentation before asking questions.
- **Shebang:** The `#!` at the start of a script that tells the OS which interpreter to use (e.g., `#!/bin/bash`).

### What is the Shell

- **Shell:** A program that provides a command-line interface to interact with the OS by reading and executing commands.
- **Terminal vs. Shell:** The terminal is the window/application that displays input/output; the shell is the program running inside it that interprets commands.
- **Shell prompt:** The text displayed before your cursor (e.g., `user@host:~$`) indicating the shell is ready for input.
- **History basics:** Use `history` to view past commands, `↑/↓` arrows to navigate them, and `!n` to re-run command number `n`.

### Navigation

- **`cd`:** Changes the current directory; **`pwd`:** Prints the working directory; **`ls`:** Lists directory contents.
- **Navigating the filesystem:** Move around using `cd` with absolute paths (`/home/user`) or relative paths (`../dir`).
- **`.` and `..`:** `.` is the current directory; `..` is the parent directory.
- **Working directory:** The directory you're currently in — print it with `pwd`, change it with `cd`.
- **Root directory:** The top-level directory `/`, from which all other directories descend.
- **Home directory:** The user's personal directory (`~`), reached by typing `cd` or `cd ~`.
- **Root directory vs. root's home:** The root directory `/` is the filesystem top; root's home directory is `/root`, the admin user's personal folder.
- **Hidden files:** Files starting with a dot (`.`); list them with `ls -a`.
- **`cd -`:** Switches you back to the previous working directory.

### Looking Around

- **`ls`:** Lists files; **`less`:** Views file contents one page at a time; **`file`:** Identifies a file's type.
- **Options and arguments:** Options modify behavior (e.g., `-l`), arguments specify targets (e.g., `filename`) — e.g., `ls -l /home`.
- **`ls` long format:** Use `ls -l`; shows permissions, owner, size, modification date, and filename.
- **A Guided Tour:** Exploring key system directories to learn the Linux filesystem layout.
- **`ln`:** Creates links between files — symbolic (`ln -s`) or hard (default).
- **Common/important directories:** `/etc` (configs), `/var` (variable data), `/home` (users), `/bin` (binaries), `/tmp` (temporary), `/usr` (user programs).
- **Symbolic link:** A pointer to another file by path; breaks if the target is deleted.
- **Hard link:** An additional name pointing to the same inode/data; persists if the original is deleted.
- **Hard vs. symbolic:** Hard links share the same inode and can't cross filesystems; symlinks are path-based references that can.

### Manipulating Files

- **`cp`, `mv`, `rm`, `mkdir`:** Copy files, move/rename files, remove files, create directories.
- **Wildcards:** Special characters (`*`, `?`, `[]`) that match patterns of filenames.
- **Using wildcards:** E.g., `*.txt` matches all `.txt` files; `file?.log` matches `file1.log`, `file2.log`, etc.

### Working with Commands

- **`type`, `which`, `help`, `man`:** `type` shows what a command is; `which` locates its binary; `help` gives shell builtin help; `man` shows the manual page.
- **Kinds of commands:** Executables (programs), shell builtins, aliases, and shell functions.
- **Alias:** A custom shortcut for a command (e.g., `alias ll='ls -la'`).
- **`help` vs. `man`:** Use `help` for shell builtins (like `cd`); use `man` for external programs.

### Reading Man Pages

- **How to read a man page:** Run `man <command>` and navigate with arrow keys, `Space`/`PageDown` to scroll, `q` to quit.
- **Man page sections:** Numbered categories organizing manual entries by topic (1–9).
- **Section numbers:** `1` = User commands, `2` = System calls, `3` = Library functions.

### Keyboard Shortcuts for Bash

- **Common shortcuts:** `Ctrl+C` (cancel), `Ctrl+Z` (suspend), `Ctrl+D` (exit/logout), `Ctrl+L` (clear screen), `Ctrl+A` (start of line), `Ctrl+E` (end of line), `Ctrl+R` (reverse search), `Tab` (autocomplete).

### LTS

- **LTS:** Long Term Support — a software release (commonly Ubuntu) guaranteed to receive updates/security patches for an extended period (typically 5 years).

## Linux Shell, Processes and Signals

- **PID (Process Identifier):** A unique number assigned by the OS to identify each running process.
- **Process:** An instance of a computer program that is being executed.
- **Finding a Process' PID:** Use commands like `ps aux`, `top`, or `pgrep`.
- **Killing a Process:** Use the `kill` command followed by the PID (e.g., `kill 1234`).
- **Signal:** A software interrupt sent to a process to notify it of an event or request action.
- **Non-Ignorable Signals:** `SIGKILL` (9) and `SIGSTOP` (19).

## Linux Security Basics

- **What is Linux:** Linux is a free, open-source operating system kernel that serves as the foundation for various Unix-like OS distributions.
- **What is a Linux Command:** A Linux command is a specific instruction typed into the terminal to execute programs, manage files, or configure system settings.
- **What is the structure of the Linux operating system:** The Linux structure consists of four main layers: the hardware, the kernel (core), the shell (interface), and the user applications.
- **What is the purpose of the FHS and what are the benefits of using it:** The Filesystem Hierarchy Standard defines directory structure to ensure consistency across distributions, simplifying software compatibility and administration.
- **What are the different directories in the Linux file system, and what are their purposes:** Key directories include `/bin` (user binaries), `/etc` (configuration files), `/var` (variable data like logs), `/home` (user data), and `/tmp` (temporary files).
- **How to protect files and directories:** Protect files by setting appropriate permissions with `chmod`, managing ownership with `chown`, and optionally applying encryption or mandatory access controls like SELinux/AppArmor.
- **How to monitor and investigate system activity:** Monitor activity using tools like `top`, `htop`, `journalctl` for logs, and `auditd` to track system calls and policy violations.
- **How to securely transfer files and data:** Securely transfer data using encrypted protocols such as SFTP (SSH File Transfer Protocol) or SCP over SSH to ensure confidentiality and integrity.
- **How to configure and manage a firewall:** Configure and manage firewalls using utilities like `ufw` (Uncomplicated Firewall) or editing rules directly with `iptables` or `nftables`.
- **How to identify and terminate malicious processes:** Identify malicious processes using `ps`, `top`, or `netstat` to spot anomalies, then terminate them safely using the `kill` command with the specific PID.
- **How to use the `ps` and `kill` commands to identify and terminate malicious processes:** Use `ps aux | grep [process]` to find the Process ID (PID) and then run `kill -9 [PID]` to force-terminate the malicious process.
- **How to use the `netstat` and `ss` commands to monitor network traffic for suspicious activity:** Use `netstat -tulpn` or `ss -tulpn` to list active connections and listening ports, helping you spot unauthorized outbound connections or open services.
- **How to use the `nmap`, `lynis` and `tcpdump` commands to analyze network traffic for suspicious behavior:** Use `nmap` to scan network topology, `tcpdump` to capture packet-level traffic, and `lynis` to audit system security and detect misconfigurations.
- **How to use `iptables` and `ufw` to manage the firewall rules on Linux systems:** Use `ufw allow/deny [port]` for simplified management or write specific `iptables -A [chain] -j [action]` rules to control packet filtering at a granular level.
