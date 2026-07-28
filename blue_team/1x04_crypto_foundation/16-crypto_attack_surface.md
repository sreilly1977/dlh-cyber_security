# 16. The Cryptographic Attack Surface

## Goal

Map the cryptographic attacks to MedDefense's specific weaknesses, showing which attacks are viable today and which controls would neutralize them.

## Context

Downgrade attacks, collision attacks, birthday attacks and more. These are not abstract concepts. Every one of them maps to a real weakness at MedDefense. Understanding these attack vectors is essential for prioritizing remediation work and for defending against active adversaries who are targeting the organization's weakest cryptographic implementations.

---

## Part 1 - Cryptographic Attack Catalog

### 1. TLS Downgrade Attack (forcing TLS 1.0 on the patient portal)

| Field | Value |
|---|---|
| **Attack** | TLS Downgrade (Protocol Downgrade) |
| **Mechanism** | An on-path attacker intercepts the TLS handshake between client and server, modifying ClientHello and ServerHello messages to force negotiation of older, weaker protocol versions. By stripping out support for TLS 1.2/1.3, the attacker forces both parties to use TLS 1.0 or 1.1, which contain known vulnerabilities including BEAST, POODLE, and lack of modern cipher suites. The attacker then exploits weaknesses in the legacy protocol to decrypt traffic or perform MITM attacks. |
| **MedDefense Vulnerability** | web-srv-01 (patient portal) offers TLS 1.0, 1.1, and 1.2. Server accepts downgrade requests without enforcing strict minimum version requirements. HSTS header is not configured with `includeSubDomains` or `preload` directive. |
| **Evidence** | VULN-001 (1x02): Web server offers deprecated TLS protocols and weak cipher suites. CRYPTO-005 (Task 15): TLS configuration accepts TLS 1.0/1.1 with weak ciphers including `TLS_RSA_WITH_3DES_EDE_CBC_SHA`. |
| **Viable Today** | **Yes.** TLS 1.0/1.1 are still actively supported by browsers for backward compatibility. Attack tools like SSLstrip, tls-downgrade-tools, and Burp Suite can easily force downgrades on servers that accept legacy protocols. The attack requires only network positioning (ARP spoofing on LAN, compromised router, or evil twin Wi-Fi), no cryptographic breakthrough. |
| **Mitigation** | Disable TLS 1.0 and 1.1 on web-srv-01 entirely. Configure nginx/Apache to respond to `SSLv3`, `TLSv1`, `TLSv1.1` with connection refusal. Add HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. Enforce TLS 1.2 minimum with `cipher_suites` restricted to AEAD ciphers only (AES-256-GCM, CHACHA20-POLY1305). Implement TLS 1.3 as preferred protocol with fallback only to TLS 1.2 (never below). |

---

### 2. Collision Attack (exploiting MD5 in Kerberos tickets)

| Field | Value |
|---|---|
| **Attack** | Hash Collision Attack (MD5 Birthday Collision) |
| **Mechanism** | A hash collision occurs when two different inputs produce the same hash digest. With MD5 (128-bit output), collisions can be generated computationally in seconds on consumer hardware using techniques like the SHAttered attack methodology. In Kerberos, if tickets or authentication tokens rely on MD5 signatures, an attacker can craft two different credential sets that hash to the same value, effectively creating forged authentication tickets that pass verification. This breaks the fundamental assumption that unique identities map to unique ticket hashes. |
| **MedDefense Vulnerability** | MedDefense's internal Kerberos domain controller (krb-srv-01) still supports DES-CBC-MD5 and RC4-HMAC cipher suites for legacy application compatibility. Ticket-granting tickets (TGTs) may be issued with MD5 signatures when negotiated with older clients. |
| **Evidence** | T6 (Algorithm Assessment): MD5 is cryptographically broken for collision resistance since 2004 (Wang et al.). SHA-1 is broken since 2017 (SHAttered attack). Kerberos RFC 4556 deprecated DES-CBC-MD5 and RC4-HMAC in favor of AES-128/256-CTS-HMAC-SHA1-96 and AES-256-CTS-HMAC-SHA384-192. No explicit finding in 1x02 due to legacy focus, but kerberized services were assumed to use strong ciphers. |
| **Viable Today** | **Yes, conditionally.** Generating MD5 collisions is trivial on modern hardware (seconds). However, MedDefense must still be using MD5-signed Kerberos tickets for this attack to succeed. If all Kerberos principals enforce AES-256 encryption types, the attack is impossible. The risk exists only if legacy Windows Server 2008 R2 or older systems are still running as domain controllers or application servers accepting weak cipher negotiations. |
| **Mitigation** | Enforce AES-256-CTS-HMAC-SHA384-192 as the only permitted encryption type for Kerberos. Disable DES-CBC-MD5, RC4-HMAC, and AES-128-CTS-HMAC-SHA1-96 via Group Policy: `Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Kerberos Policy → Supported encryption types`. Run `klist` on domain controllers to audit active encryption types. Replace all legacy Windows Server 2008 R2 domain controllers with 2016+. Issue new service principal keys with AES-256-only credentials. |

---

### 3. Birthday Attack (theoretical relevance to hash functions)

| Field | Value |
|---|---|
| **Attack** | Birthday Attack (Collision Probability via Pigeonhole Principle) |
| **Mechanism** | The birthday attack exploits the mathematics of the birthday paradox to find hash collisions more efficiently than brute force. For an n-bit hash, the probability of finding two inputs that collide reaches 50% after approximately √(2^n) = 2^(n/2) attempts. For MD5 (128 bits), this means ~2^64 (~18 quintillion) attempts—still large, but feasible with nation-state resources. For SHA-1 (160 bits), it means ~2^80 (~1.2×10^24) attempts, which became feasible in 2017 (SHAttered attack). For SHA-256 (256 bits), it means ~2^128 attempts, which remains computationally infeasible. The attack does not crack individual hashes—it finds any two messages that produce the same hash, enabling substitution attacks on signed documents or certificates. |
| **MedDefense Vulnerability** | No active use of SHA-1 or MD5 in production systems post-T6 remediation. However, T0 analysis showed legacy systems using SHA-1 for certificate chains and digital signatures. If any system still validates SHA-1 signatures without upgrade paths, the birthday attack becomes viable. Additionally, if digital signatures for software updates, firmware signing (BD Alaris pumps), or code signing use 128-bit or 160-bit hash functions, collision attacks could forge signatures. |
| **Evidence** | T6 (Algorithm Assessment): SHA-1 collision demonstrated in 2017 with $100,000 compute cost. MD5 collision practical since 2004. NIST SP 800-131A prohibits SHA-1 for digital signatures after 2023. No active finding in T15 because T6 remediation already migrated all certificates to SHA-256/SHA-384. |
| **Viable Today** | **No, given current posture.** MedDefense migrated to SHA-256/SHA-384 per T6 and T15. SHA-256 (256-bit output) requires 2^128 operations for collision—exponentially beyond any realistic adversary capability even for nation-states. The theoretical math remains valid: if an attacker gains physical access to signing infrastructure and extracts private keys, they could sign malicious firmware or code. But pure collision attacks (hash-only, without key theft) are irrelevant against SHA-256+ hash functions. |
| **Mitigation** | Maintain SHA-256 or stronger for all digital signatures and certificate hashing. Monitor for NIST guidance on SHA-3 adoption for long-term archival signatures (20+ year retention). For critical infrastructure (BD Alaris pump firmware, CA private keys), implement dual-signature schemes requiring two independent keys for validation (defense in depth). Ensure all code signing and firmware signing workflows use HSM-backed keys (CRYPTO-011 remediation) rather than software keystores. |

---

### 4. Kerberoasting (exploiting RC4/DES in Kerberos for offline cracking)

| Field | Value |
|---|---|
| **Attack** | Kerberoasting (Service Ticket Cracking) |
| **Mechanism** | Kerberoasting exploits the ability in Active Directory to request service tickets (STs) for any domain-joined account without administrative privileges. The attacker requests an ST for a target service account, receiving a ticket encrypted with the service account's password hash (NTLM or RC4-HMAC). The attacker then extracts this encrypted ticket and performs offline brute-force or dictionary cracking. Because the attack happens entirely offline, there are no authentication logs generated on the domain controller. Success depends on weak service account passwords and legacy cipher support (RC4, DES) which allow faster cracking. |
| **MedDefense Vulnerability** | MedDefense runs Active Directory for employee authentication. Service accounts for EHR, billing, and PACS applications are domain-joined with password policies that may not meet complexity requirements. The krb-srv-01 domain controller still accepts RC4-HMAC for legacy compatibility (same weakness as MD5 collision attack). |
| **Evidence** | No explicit 1x02 finding (legacy assessment did not include AD attack simulation). T14 noted service account keys in HashiCorp Vault but did not address AD service ticket encryption types. Industry baseline: 70% of enterprises have at least one service account vulnerable to Kerberoasting (SecureAuth Labs 2022). |
| **Viable Today** | **Yes, high likelihood.** Kerberoasting requires no special privileges beyond a standard domain user account (any employee workstation). Attack tools like Rubeus, Impacket, and PowerSploit automate ticket extraction and offline cracking. With modern GPU clusters (RTX 4090), RC4-HMAC tickets can be cracked at 500 million attempts/second. If MedDefense service account passwords are under 16 characters or lack special characters, cracking completes in hours to days. |
| **Mitigation** | Enforce AES-256 encryption types for all service accounts (Group Policy as described in Kerberos mitigation). Set service account passwords to 25+ random characters using automated password generators, stored in HashiCorp Vault. Enable Azure AD Identity Protection or Windows Defender Advanced Threat Protection to detect anomalous Kerberoasting patterns (high ticket request frequency from single user). Audit service account usage quarterly via PowerShell: `Get-DomainSPNTicket -OutputFormat JTR`. Require MFA for all privileged service accounts accessing sensitive data. |

---

### 5. On-path/MITM on Unencrypted Channels (DICOM traffic, unencrypted database connections)

| Field | Value |
|---|---|
| **Attack** | Man-in-the-Middle (MITM) / Passive Eavesdropping |
| **Mechanism** | An attacker positioned on the same network segment (hospital LAN, guest Wi-Fi, compromised switch) captures unencrypted network traffic using packet sniffers (Wireshark, tcpdump, ettercap). Without TLS or IPsec, the attacker reads all transmitted data in plaintext including database queries, authentication credentials, medical images, and PHI. The attack can be passive (just listening) or active (injecting malicious packets to modify data or redirect sessions). For DICOM protocols specifically, the lack of mutual TLS means the attacker can impersonate a modality or PACS server to steal or corrupt medical images. |
| **MedDefense Vulnerability** | Multiple unencrypted or weakly encrypted channels remain per T15: PACS DICOM TLS uses TLS 1.0 with 3DES; some modalities transmit DICOM without TLS entirely. PostgreSQL connections from clinical workstations to ehr-db-01 may not enforce TLS (libpq sslmode may be set to `prefer` rather than `require`). MySQL billing connections similarly may not enforce TLS. |
| **Evidence** | VULN-016 (1x02): DICOM transport uses TLS 1.0 with 3DES; some modalities unencrypted. CRYPTO-004 (T15): PACS images protected only by filesystem permissions, no transport encryption for inter-modality transfer. CRYPTO-012 (T15): DICOM TLS upgraded only partially, some legacy modalities remain. T0 Data Protection Map: "In Transit" column marked "Weak" for PACS, billing database, and email. |
| **Viable Today** | **Yes, extremely likely.** Hospital networks are notoriously flat (minimal VLAN segmentation) and often use unmanaged switches. Any employee with a laptop can plug into a wall jack or join guest Wi-Fi and capture traffic. MITM tools like BetterCAP, ARP spoofing, and DNS spoofing are readily available and require minimal skill. For passive eavesdropping on unencrypted channels, the only barrier is physical network access. |
| **Mitigation** | Enforce mutual TLS for all DICOM communications: modalities and PACS server present certificates signed by internal CA (CRYPTO-011 remediation). Disable cleartext DICOM transmission via hospital network policy (block port 104 to non-TLS destinations). Configure PostgreSQL `sslmode=require` and `sslcert` for all client connections; MySQL `require_secure_transport=ON`. Segment hospital network into VLANs by zone: clinical workstations, imaging devices, administration, guest. Place database servers in dedicated database subnet with firewall rules blocking all non-authorized application servers. Deploy network IDS (Suricata/Zeek) to alert on cleartext traffic patterns. |

---

### 6. Key Recovery from Memory (root on billing-srv-01 extracting AES keys from RAM)

| Field | Value |
|---|---|
| **Attack** | Cold Boot Attack / Memory Scraping |
| **Mechanism** | When an attacker has root access to a server, they can dump the entire contents of DRAM using memory scraping tools or cold boot techniques (physically freezing memory modules and reading them after power loss). Encryption keys stored in plaintext in RAM during cryptographic operations can be extracted from memory dumps. Even with full-disk encryption, the keys must reside in memory to decrypt data, making them accessible to root-level attackers. Kernel-level rootkits can continuously monitor memory for cryptographic material. Modern mitigations like memory encryption (AMD SME, Intel TXT) protect against physical cold boot attacks but do not stop software-based memory scraping from compromised kernels. |
| **MedDefense Vulnerability** | billing-srv-01 hosts MySQL TDE master key in memory during operation. If an attacker compromises the server (via unpatched CVE, phishing, insider threat), they gain root access to memory space where AES-256 keys are loaded. The T15 remediation placed the TDE master key in HSM-01, but the key must still be decrypted and loaded into application memory during transaction processing. No memory encryption or secure enclaves are deployed on billing-srv-01. |
| **Evidence** | VULN-005 (1x02): Billing server credentials exposed to DBA. CRYPTO-003 (T15): MySQL TDE with HSM-backed key management. T14 noted that HSM provides "highest-value keys requiring hardware protection" but acknowledged that "application servers still handle decrypted keys in memory during query execution." No explicit 1x02 finding about memory scraping—assumed acceptable risk for operational feasibility. |
| **Viable Today** | **Yes, conditional on root access.** Extracting keys from memory requires root access or kernel module loading. If the attacker already has root (via CVE exploitation, credential stuffing, insider threat), the memory scraping attack is trivial using `/proc/[pid]/mem` or Volatility framework. Cold boot attacks (physical memory extraction after power loss) are less relevant for virtualized environments (cloud-hosted MySQL), but remote memory scraping is a serious threat. The HSM protects against network-level key theft but cannot protect against root-level attackers who have already compromised the application server. |
| **Mitigation** | Use HSM-backed key management where the HSM performs all cryptographic operations remotely—the application server sends plaintext data to the HSM for encryption and receives ciphertext back without ever holding the key in application memory. Enable Intel SGX or AMD SEV for confidential computing on billing-srv-01 to isolate memory from kernel access. Implement process isolation: run MySQL in a container with strict seccomp/AppArmor profiles preventing `/proc/mem` access. Deploy runtime application self-protection (RASP) to detect memory scraping attempts. Rotate TDE keys immediately upon suspected compromise. Consider cloud HSM with remote key wrapping so application never holds KEK. |

---

## Part 2 - Attack Viability Summary Matrix

| Attack | Viable Today | Prerequisites | Blast Radius | Priority |
|---|---|---|---|---|
| TLS Downgrade | ✅ Yes | Network positioning (ARP spoofing, evil twin Wi-Fi) | Patient portal session hijacking; credential theft | **Immediate** |
| Collision Attack (MD5) | ✅ Yes, conditionally | Legacy Kerberos cipher support (DES-CBC-MD5, RC4-HMAC) | Forged authentication tickets; unauthorized domain access | **High** |
| Birthday Attack | ❌ No (given SHA-256+ posture) | Would require SHA-1 or MD5 signature validation | Certificate forgery; firmware signature bypass | **Low** (already mitigated) |
| Kerberoasting | ✅ Yes | Standard domain user account; RC4/DES cipher support | Offline service account password cracking; privilege escalation | **Immediate** |
| MITM on Unencrypted Channels | ✅ Yes | Physical network access (LAN, Wi-Fi) | Full PHI exfiltration; database query interception | **Immediate** |
| Memory Scraping (Root Access) | ✅ Yes, conditional | Root access to database server | All TDE keys extracted; database decryption | **High** |

---

## Part 3 - Mitigation Implementation Roadmap

### Immediate (Week 1-4)

| Control | Affected Systems | Effort | Expected Risk Reduction |
|---|---|---|---|
| Disable TLS 1.0/1.1 on web-srv-01; add HSTS header | Patient portal | 2 hours | Eliminates TLS downgrade attack |
| Enforce AES-256 encryption types for Kerberos principals | krb-srv-01, domain-joined servers | 4 hours | Neutralizes collision and Kerberoasting attacks |
| Segment hospital network; disable cleartext DICOM | PACS, imaging devices | 8 hours | Prevents MITM on medical images |
| Deploy IDS to monitor for Kerberoasting patterns | krb-srv-01, all DCs | 4 hours | Detects Kerberoasting before success |

### Phase 2 (Month 2-3)

| Control | Affected Systems | Effort | Expected Risk Reduction |
|---|---|---|---|
| Force `sslmode=require` for PostgreSQL and MySQL connections | ehr-db-01, billing-srv-01 | 4 hours | Eliminates MITM on database traffic |
| Migrate service account passwords to 25+ random characters | All AD service accounts | 8 hours | Makes Kerberoasting impractical (>10 years to crack) |
| Enable Intel SGX or AMD SEV on billing-srv-01 | MySQL application server | 16 hours | Protects TDE keys from memory scraping |

### Phase 3 (Month 4-6)

| Control | Affected Systems | Effort | Expected Risk Reduction |
|---|---|---|---|
| Deploy remote HSM key wrapping for all database TDE keys | All DB servers | 8 hours | Application servers never hold TDE master key |
| Enable memory encryption (AMD SME, Intel TXT) on all database servers | ehr-db-01, billing-srv-01 | 4 hours | Protects keys from cold boot and software memory scraping |
| Implement ZTNA (Zero Trust Network Access) for clinical workstations | All employee devices | 16 hours | Removes flat network topology enabling MITM |

---

## Part 4 - Residual Risk Assessment

After implementing all immediate and Phase 2 mitigations, the residual risk profile is:

| Attack | Pre-Mitigation Viability | Post-Mitigation Viability | Residual Risk Level |
|---|---|---|---|
| TLS Downgrade | High (active TLS 1.0/1.1) | Eliminated (TLS 1.2+ only, HSTS enforced) | ✅ Negligible |
| Collision Attack (MD5) | Medium (legacy ciphers active) | Low (AES-256-only Kerberos; legacy ciphers disabled) | ✅ Low |
| Birthday Attack | Low (already SHA-256+ posture) | Low (no change needed) | ✅ Negligible |
| Kerberoasting | High (RC4/DES supported; weak passwords) | Medium (strong passwords; AES-256-only; detection active) | ⚠️ Medium |
| MITM on Unencrypted Channels | High (flat network; cleartext DICOM) | Low (network segmentation; encrypted DICOM; database TLS required) | ⚠️ Low |
| Memory Scraping (Root Access) | High (keys in application memory) | Medium (SGX/SEV; HSM remote wrapping) | ⚠️ Medium |

**Critical Observation:** Two attacks remain viable post-mitigation: Kerberoasting and memory scraping. Both require either domain user access (Kerberoasting) or root access (memory scraping)—meaning they are attacks from within the security perimeter, not from external adversaries. This shifts the defense-in-depth strategy toward **insider threat prevention** rather than perimeter hardening.

---

## Appendix - Attack Tool References

| Attack | Common Tools | Skill Level Required |
|---|---|---|
| TLS Downgrade | SSLstrip, Burp Suite, mitmproxy | Beginner |
| Collision Attack (MD5) | hashcollisions.org, fastcoll, multicoll | Expert (math-heavy) |
| Birthday Attack | SHA-1 collision finder (Google/Stanford) | Expert (research-grade) |
| Kerberoasting | Rubeus, Impacket GetUserSPNs, PowerSploit | Intermediate |
| MITM / Sniffing | Wireshark, BetterCAP, ettercap, tcpdump | Beginner |
| Memory Scraping | Volatility, DumpIt, ProcDump, GRR | Intermediate-Expert |

---

## Summary

MedDefense faces **six concrete cryptographic attack vectors**, of which **four are actively viable today** without any novel research or advanced capabilities. The most immediate threats are TLS downgrade attacks (requiring only network positioning), Kerberoasting (requiring only a standard employee account), MITM on unencrypted channels (requiring only physical LAN access), and memory scraping attacks (requiring root access to database servers).

Two attacks—birthday attacks and collision attacks—are theoretically sound but **neutralized by MedDefense's SHA-256+ posture** post-T6 remediation. These represent defensive wins but should remain under periodic review as cryptanalysis advances.

The mitigation roadmap prioritizes **immediate elimination of TLS downgrade** (web-srv-01 hardening), **elimination of legacy Kerberos ciphers** (domain-wide AES-256 enforcement), and **network segmentation** to prevent MITM attacks. Phase 2 and Phase 3 controls address memory scraping and insider threats, which require root-level or domain-level access to exploit—making them harder but still viable for determined adversaries.

**Bottom line:** The cryptographic attack surface is now well-defined, with clear ownership for each vulnerability and remediation path. Four of six attacks are actively exploitable today; eliminating these four is the top priority for reducing MedDefense's cryptographic risk footprint.
