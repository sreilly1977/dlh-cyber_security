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

# 
