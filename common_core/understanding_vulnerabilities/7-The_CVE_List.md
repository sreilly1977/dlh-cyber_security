# The CVE List
**By Stephen Reilly** | *Understanding Vulnerabilities Series*

## Who Manages the CVE List?

The entire CVE Program is managed by the **MITRE Corporation**, a not-for-profit organization that operates federally funded research and development centers (FFRDCs) for the U.S. government. MITRE acts as the "root CNA" and oversees the global ecosystem, ensuring standards are met, resolving disputes, and maintaining the public CVE list.

However, MITRE doesn't hand out every single ID itself. They delegate the authority to issue IDs to a network of trusted organizations known as **CVE Numbering Authorities (CNAs)**.

## The Role of CVE Numbering Authorities (CNAs)

CNAs have the authority to number vulnerabilities within their specific domain.

### 1. Delegated Authority

CNAs are software vendors, open-source projects, industry groups, or even national CERTs (like US-CERT/CSIRT) authorized to assign CVE IDs for products or services under their scope.

* **Example:** If you find a bug in Firefox, you report it to Mozilla, which is a CNA. Mozilla assigns the ID.
* **Example:** If you find a flaw in the Linux kernel, the Linux Foundation (or a delegated CNA like the Kernel.org team) handles the assignment.

### 2. Scope Definition

Every CNA has a defined "scope." A vendor like Cisco only assigns CVEs for Cisco products. A national CERT might cover vulnerabilities reported to them within a specific country if no vendor CNA exists.

### 3. The Assignment Process

* **Discovery & Reporting:** A researcher or internal team finds a vulnerability.
* **Validation:** The CNA validates that the issue is a genuine security vulnerability (not a feature request or user error) and hasn't been previously assigned a CVE.
* **ID Generation:** The CNA generates a unique ID in the format `CVE-YYYY-XXXXX`.
* **Publication (Draft):** They publish a "reserved" or "draft" entry with a brief description. This prevents duplicate reporting while the vendor works on a fix.
* **Finalization:** Once a fix is available or the details are finalized, the entry is updated with the full description, affected versions, and references.

## The Workflow

The lifecycle of a CVE ID from a CNA perspective:

1. **Reservation:** When a vendor or researcher submits a report to a CNA, the CNA immediately reserves an ID. This locks the identifier so two different groups don't claim the same bug. At this stage, the public record usually just says "Vulnerability in [Product]" with limited details to prevent exploitation before a patch exists.

2. **Coordination:** The CNA coordinates between the discoverer and the vendor (if they aren't the same entity). This is where responsible disclosure happens. The CNA ensures all parties agree on the severity and the timeline for disclosure.

3. **Detail Enrichment:** The CNA updates the record with technical details, CVSS scores (often), and links to patches or advisories.

4. **Publication:** The final record is pushed to the official CVE List (hosted by MITRE) and aggregated by databases like NVD (National Vulnerability Database).

## Why This Structure Matters

Understanding the CNA structure is crucial for a few reasons:

* **Speed:** Delegation allows thousands of vulnerabilities to be cataloged simultaneously.
* **Authority:** You can trust that a CVE assigned by the vendor CNA (e.g., Microsoft) comes directly from the source that controls the code.
* **Conflicts:** Occasionally, two CNAs might try to claim the same vulnerability (e.g., a library used in many products). The MITRE root CNA steps in to resolve these conflicts and ensure only one CVE ID exists for the specific issue.
