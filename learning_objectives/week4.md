# Week 4 Learning Objectives

## Email Security Fundamentals

### Q: What is email authentication and why is it important?
A: Email authentication verifies that a message comes from who it claims to be from, preventing spoofing and phishing attacks.

### Q: What are the main threats that email authentication protocols protect against?
A: Email spoofing, phishing, domain impersonation, BEC (Business Email Compromise), and unauthorized sending on behalf of a domain.

### Q: How do SPF, DKIM, and DMARC work together to provide comprehensive email security?
A: SPF authorizes sending servers, DKIM verifies message integrity via cryptographic signatures, and DMARC ties both together with alignment checks and enforcement policies.

### Q: What is the difference between email spoofing and domain impersonation?
A: Spoofing forges the sender address directly, while domain impersonation uses a lookalike domain (e.g., paypa1.com instead of paypal.com).

---

## Sender Policy Framework (SPF)

### Q: What is SPF and what problem does it solve?
A: SPF is a DNS-based protocol that specifies which mail servers are authorized to send email on behalf of a domain, preventing unauthorized senders from spoofing that domain.

### Q: How does SPF authorize sending mail servers?
A: By publishing a DNS TXT record listing permitted IP addresses, ranges, and included domains that receivers check against the connecting server's IP.

### Q: What is the correct syntax for an SPF record?
A: `v=spf1 [mechanisms] [qualifier]all` — e.g., `v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all`.

### Q: What are the different SPF mechanisms (ip4, include, mx, a, all) and when do you use each?
A: ip4/ip6 for specific IP ranges, include to incorporate another domain's SPF, mx to authorize your MX servers, a to authorize IPs from your domain's A record, and all as the catch-all default.

### Q: What are the SPF qualifiers (+pass, -fail, ~softfail, ?neutral) and what do they mean?
A: + = pass (default), - = fail (reject), ~ = softfail (mark suspicious but accept), ? = neutral (no policy assertion).

### Q: What is the SPF evaluation order and why does it matter?
A: Mechanisms are evaluated left to right; the first matching mechanism determines the result, so order affects which rules take priority.

### Q: What are the different SPF results (pass, fail, softfail, neutral, temperror, permerror)?
A: Pass = authorized, fail = unauthorized, softfail = probably unauthorized, neutral = no assertion, temperror = transient DNS error, permerror = permanent record error (e.g., syntax invalid).

### Q: What is the 10 DNS lookup limit in SPF and why does it exist?
A: RFC 7208 limits resolving include, a, mx, and redirect mechanisms to 10 total lookups to prevent DNS amplification attacks and excessive load on receiving servers.

### Q: Why does email forwarding break SPF and how can you mitigate this?
A: Forwarding changes the originating IP, failing the receiver's SPF check; mitigation includes ARC (Authenticated Received Chain), SRS (Sender Rewriting Scheme), or relying on DKIM which survives forwarding.

### Q: What does -all mean in an SPF record and why is it important?
A: It means "fail all servers not explicitly authorized," ensuring that any sender not listed is marked as unauthorized — the strongest enforcement stance.

### Q: How do you test and validate an SPF record?
A: Use dig TXT domain.com, online tools like MXToolbox or dmarcian, or send test emails and inspect the Received-SPF header.

---

## DomainKeys Identified Mail (DKIM)

### Q: What is DKIM and how does it differ from SPF?
A: DKIM attaches a cryptographic signature to messages verified via a public key in DNS, proving content integrity and sender authorization — unlike SPF which only validates the sending server's IP.

### Q: How does DKIM use cryptographic signatures to verify email authenticity?
A: The sending server signs selected headers and body with a private key; the receiver retrieves the public key from DNS and verifies the signature.

### Q: What is a DKIM selector and why are selectors used?
A: A selector is a string in the DKIM header that identifies which specific key to look up in DNS, enabling multiple concurrent keys and key rotation.

### Q: What are the components of a DKIM signature header?
A: Key fields include v (version), a (algorithm), b (signature value), bh (body hash), d (domain), h (signed headers), s (selector), and c (canonicalization).

### Q: How does the DKIM signing process work step-by-step?
A: 1) Canonicalize headers/body → 2) Hash the body → 3) Sign selected headers and body hash with the private key → 4) Attach the DKIM-Signature header → 5) Send.

### Q: How does the DKIM verification process work step-by-step?
A: 1) Extract selector and domain from DKIM-Signature → 2) Query `[selector]._domainkey.[domain]` in DNS for the public key → 3) Canonicalize → 4) Verify signature with the public key → 5) Compare body hash.

### Q: What are canonicalization methods (simple/simple, relaxed/relaxed) and when do you use each?
A: Simple preserves headers/body exactly; relaxed tolerates whitespace/case changes — relaxed is preferred for headers and body since mail servers often modify content in transit.

### Q: What is the format of a DKIM DNS record?
A: A TXT record at `[selector]._domainkey.[domain]` containing `v=DKIM1; k=rsa; p=[base64-encoded-public-key]`.

### Q: How do you generate DKIM keys and what key size should you use?
A: Use OpenSSL (`openssl genrsa -out private.pem 2048`) — RSA 2048-bit minimum; 4096-bit recommended for longer-term use; Ed25519 is also now supported.

### Q: Why is DKIM forwarding-friendly while SPF is not?
A: Because the DKIM signature travels with the message and verifies against DNS (independent of the sending IP), while SPF breaks when the connecting IP changes during forwarding.

### Q: What is DKIM key rotation and how do you perform it?
A: Publishing a new selector/key pair alongside the old one, allowing signed messages already in transit to still verify under the old key before removing it — typically done every 6–12 months.

### Q: How do you test and validate DKIM signatures?
A: Send a test email and inspect the Authentication-Results header, use tools like DKIM Validator, or verify manually with dig TXT selector._domainkey.domain.com.

---

## Domain-based Message Authentication, Reporting & Conformance (DMARC)

### Q: What is DMARC and how does it build on SPF and DKIM?
A: DMARC uses SPF and DKIM results plus alignment checks between the envelope/domain/from addresses to determine a policy action (none/quarantine/reject) and provides reporting.

### Q: What are the required and optional DMARC tags?
A: Required: v (version) and p (policy); Optional: rua (aggregate reports), ruf (forensic reports), sp (subdomain policy), pct (percentage), ri (report interval), adkim/aspf (alignment mode).

### Q: What are the three DMARC policy levels (none, quarantine, reject) and what does each do?
A: none = monitor only, no enforcement; quarantine = send failing messages to spam; reject = drop failing messages entirely.

### Q: What is DMARC alignment and why is it important?
A: Alignment ensures the domain in the From header matches the domain validated by SPF (envelope sender) or DKIM (d= tag), closing loopholes where a passing SPF/DKIM could belong to a different domain.

### Q: What is the difference between strict and relaxed alignment modes?
A: Strict requires exact domain match; relaxed allows organizational domain match (e.g., mail.example.com aligns with example.com).

### Q: How does DMARC evaluate email authentication (SPF and DKIM checks)?
A: It checks if SPF passes and the envelope domain aligns with the From header, OR if DKIM passes and the DKIM domain aligns with the From header — either suffices.

### Q: What are the conditions for a DMARC pass result?
A: At least one of SPF + alignment or DKIM + alignment must pass — that is, authenticated and aligned with the From domain.

### Q: What is the pct tag and how is it used for gradual policy enforcement?
A: pct=X applies the DMARC policy to X% of failing messages, allowing incremental rollout (e.g., pct=10 quarantines only 10% of failures).

### Q: What is the sp tag and how does it affect subdomain policies?
A: sp sets a separate DMARC policy for subdomains; if omitted, subdomains inherit the p policy — useful for rejecting subdomain spoofing while monitoring the apex domain.

### Q: What are DMARC aggregate reports (RUA) and what information do they contain?
A: XML reports sent periodically to the RUA address containing sending IP, SPF/DKIM/DMARC results, counts, and policy outcomes — used for monitoring authentication across all senders.

### Q: What are DMARC forensic reports (RUF) and when are they sent?
A: Individual failure reports sent per-message when DMARC fails, containing the original message headers and sometimes the body — useful for forensics but raises privacy concerns.

### Q: How do you parse and analyze DMARC reports?
A: Use tools like dmarcian, Postmark's DMARC tool, parsedmarc (Python), or commercial platforms that ingest XML/RUA reports and present dashboards.

### Q: What is the recommended DMARC deployment strategy?
A: Start with p=none with rua monitoring → analyze reports → move to p=quarantine with low pct → gradually increase → switch to p=reject.

---

## Protocol Integration

### Q: How do SPF, DKIM, and DMARC work together in the email authentication flow?
A: Receiver checks SPF (IP authorized?), DKIM (signature valid?), then DMARC (do either align with From header?) → apply DMARC policy accordingly.

### Q: What happens when SPF passes but DKIM fails (and vice versa)?
A: DMARC still passes if the one that passed aligns with the From header — only one aligned pass is needed.

### Q: What happens when both SPF and DKIM fail?
A: DMARC fails, and the receiver applies the domain's DMARC policy (none/quarantine/reject).

### Q: How does DMARC use SPF and DKIM results to make policy decisions?
A: DMARC combines the pass/fail results of each with alignment checks; if neither aligns and passes, it enforces the published policy.

### Q: What threats does each protocol protect against?
A: SPF prevents unauthorized IP spoofing, DKIM prevents content tampering and verifies sender identity, DMARC prevents domain spoofing and provides enforcement + visibility.

### Q: What are the limitations of each protocol?
A: SPF breaks on forwarding and has a 10-lookup limit; DKIM can break if intermediaries modify content; DMARC only protects the From header domain and requires at least one aligned pass.

---

## Implementation and Configuration

### Q: How do you implement SPF for a domain?
A: Publish a TXT record at the domain root: `v=spf1 [authorized-sources] -all`.

### Q: How do you implement DKIM for a domain?
A: Generate a key pair, configure your mail server to sign outgoing messages, and publish the public key at `[selector]._domainkey.[domain]` as a TXT record.

### Q: How do you implement DMARC for a domain?
A: Publish a TXT record at `_dmarc.[domain]`: `v=DMARC1; p=none; rua=mailto:dmarc@domain.com`.

### Q: What is the correct order for implementing email authentication protocols?
A: SPF first → DKIM second → DMARC last (starting at p=none with reporting).

### Q: How do you configure subdomain policies?
A: Use the sp tag in the DMARC record, or publish a separate DMARC record at `_dmarc.subdomain.domain.com`.

### Q: How do you handle third-party email services in SPF records?
A: Use include: directives pointing to the provider's SPF record (e.g., `include:_spf.google.com`), being mindful of the 10-lookup limit.

### Q: How do you troubleshoot authentication failures?
A: Inspect Authentication-Results and Received-SPF headers, validate DNS records with dig/online tools, check alignment, and analyze DMARC reports.

---

## DNS and Technical Details

### Q: Where are SPF, DKIM, and DMARC records published in DNS?
A: SPF at the domain root, DKIM at `[selector]._domainkey.[domain]`, DMARC at `_dmarc.[domain]`.

### Q: What DNS record type is used for email authentication records?
A: TXT records for all three (SPF, DKIM, and DMARC).

### Q: How do you query DNS records using dig, nslookup, or online tools?
A: dig TXT domain.com (SPF), dig TXT selector._domainkey.domain.com (DKIM), dig TXT _dmarc.domain.com (DMARC); or use MXToolbox/dmarcian.

### Q: What is the format of each DNS record type?
A: SPF: `v=spf1 ... -all`; DKIM: `v=DKIM1; k=rsa; p=[key]`; DMARC: `v=DMARC1; p=none; rua=...`.

### Q: How do DNS lookups work for SPF includes?
A: Each include: triggers a recursive TXT lookup on the referenced domain, counting toward the 10-lookup limit.

### Q: How do DNS lookups work for DKIM public keys?
A: The verifier constructs the query `[selector]._domainkey.[d=domain]` and retrieves the TXT record containing the public key.

---

## Best Practices and Common Mistakes

### Q: What are the best practices for SPF record configuration?
A: Keep it under the 10-lookup limit, end with -all, avoid +all, use ip4/ip6 where possible, and use SPF flattening services if includes are too many.

### Q: What are the best practices for DKIM key management?
A: Use RSA 2048+ or Ed25519, rotate keys every 6–12 months, use dual selectors during rotation, and store private keys securely.

### Q: What are the best practices for DMARC policy deployment?
A: Start at p=none with rua reporting, analyze reports thoroughly, incrementally move to quarantine then reject, and set sp=reject for subdomains early.

### Q: What are common mistakes when implementing email authentication?
A: Using +all or ~all in SPF, skipping DKIM, deploying DMARC at p=reject immediately, exceeding the 10-lookup limit, and neglecting third-party senders.

### Q: How do you avoid the SPF 10 DNS lookup limit?
A: Use IP addresses directly instead of include:, consolidate includes with SPF flattening tools, or use a delegated SPF service.

### Q: Why should you never use +all in an SPF record?
A: It explicitly authorizes every IP on the internet to send email from your domain, completely defeating SPF's purpose.

### Q: Why should you start with p=none in DMARC before enforcing policies?
A: To collect reports and identify all legitimate senders before enforcement, avoiding false positives that block valid mail.

### Q: How often should you rotate DKIM keys?
A: Every 6–12 months is recommended, or immediately if a private key is compromised.

---

## Troubleshooting

### Q: How do you diagnose SPF authentication failures?
A: Check the Received-SPF header, verify the sending IP against the SPF record, look for include chain issues, and confirm the record doesn't exceed 10 lookups.

### Q: How do you diagnose DKIM signature failures?
A: Verify the public key is published correctly in DNS, check for body/header modifications in transit (canonicalization mismatch), confirm the selector exists, and ensure key length is supported.

### Q: How do you diagnose DMARC policy issues?
A: Analyze DMARC aggregate reports, verify alignment between SPF/DKIM domains and the From header, and check that the DMARC record is published at `_dmarc.[domain]`.

### Q: What tools can you use to test email authentication?
A: MXToolbox, dmarcian, mail-tester.com, DKIM Validator, dig/nslookup, and Parsedmarc for report analysis.

### Q: How do you read and interpret email headers?
A: View the full message source and trace from bottom (oldest) to top (newest), looking at Authentication-Results, Received-SPF, DKIM-Signature, and Received headers.

### Q: How do you analyze DMARC aggregate reports?
A: Ingest XML reports via tools like parsedmarc or commercial dashboards, then review which IPs/senders pass or fail authentication and alignment.

### Q: What are common causes of authentication failures?
A: Unlisted third-party senders in SPF, broken include chains, modified message bodies breaking DKIM, misaligned domains, missing/expired DNS records, and forwarding scenarios.

---

# Network Protocols: Auditing and Securing

## Core Security Principles & Protocol Differentiation

### Q: What are the three core security goals that secure protocols aim to achieve?
A: Confidentiality, integrity, and availability (the CIA triad).

### Q: What is the main difference between application-layer protocols and network-layer protocols?
A: Application-layer operates at OSI layer 7 (user-facing services), while network-layer operates at layer 3 (routing and addressing).

### Q: Explain the concept of port numbers and their significance in network communication.
A: Port numbers identify specific applications or services running on a host, allowing multiplexing of communications.

---

## Secure Web & Remote Access Protocols

### Q: What is the difference between SSL and TLS, and which one is actually used today?
A: TLS is the modern successor; SSL is deprecated and insecure.

### Q: How the TLS handshake works when visiting a secure website?
A: Client and server negotiate encryption algorithms, authenticate via certificates, and establish session keys before data transfer.

### Q: What problem did SSH solve that older protocols like Telnet couldn't handle?
A: SSH provides encrypted remote shell access, while Telnet transmits all data (including credentials) in plaintext.

### Q: How does SSH authentication with public keys work?
A: The client proves identity using a private key without transmitting it, while the server verifies against a stored public key.

### Q: Differentiate between secure protocols like HTTPS, SFTP and their insecure counterparts HTTP, FTP.
A: Secure versions encrypt data in transit; insecure versions transmit plaintext vulnerable to interception.

### Q: Explain why HTTPS is mandatory for user trust, data protection, and modern web features.
A: It prevents man-in-the-middle attacks, protects sensitive data, and is required by browsers for mixed content handling.

---

## Network Layer & VPN Protocols

### Q: What is the difference between Transport Mode and Tunnel Mode in IPSec, and which is used for VPNs?
A: Transport mode encrypts only payload; tunnel mode encrypts entire packet—tunnel mode is used for VPNs.

### Q: What is the difference between the AH (Authentication Header) and ESP (Encapsulating Security Payload) protocols in IPSec?
A: AH provides authentication only; ESP provides both encryption and authentication.

### Q: Why should PPTP never be used for security-sensitive tasks?
A: It has known cryptographic weaknesses and vulnerabilities including MSCHAPv2 cracking.

### Q: What makes the modern WireGuard protocol faster and more efficient than traditional VPN protocols like OpenVPN?
A: Simpler codebase, modern cryptography (ChaCha20, Curve25519), and stateless design reduce overhead.

---

## Common Protocol Auditing & Risk Assessment

### Q: Explain the purpose of the Network File System (NFS) protocol and how misconfigurations can lead to exposed shares.
A: NFS enables file sharing across networks; improper access controls expose sensitive directories to unauthorized users.

### Q: Describe how the SMTP commands VRFY and EXPN can be exploited for user enumeration on a mail server.
A: These commands reveal valid email addresses/usernames, enabling targeted phishing attacks.

### Q: Explain the purpose of SNMP and the security risks associated with unencrypted data and default community strings.
A: SNMP monitors devices but defaults allow attackers to read/write device configurations with minimal effort.

---

## System Hardening & Vulnerability Management

### Q: Explain the importance of keeping network protocols and server configurations up-to-date and patched.
A: Unpatched systems contain known vulnerabilities exploitable by attackers with published exploits.

### Q: Explain the need for setting up basic firewall rules (like using iptables) to control network access.
A: Firewalls filter unauthorized traffic and limit attack surface by blocking unnecessary ports.

### Q: Identify common SSH configuration weaknesses that require hardening (permitting root login, password authentication).
A: Disabling root login, password authentication, and enforcing key-based auth reduces brute-force and privilege escalation risks.

---

# Passive Reconnaissance

### Q: What can we learn about a Server?
A: We can discover its open ports, running services, OS fingerprint, and potential vulnerabilities.

### Q: What is a DNS server?
A: It is a specialized server that translates human-readable domain names into machine-readable IP addresses.

### Q: What happens when we type www.holbertonschool.com and press ENTER?
A: Your browser queries a DNS server to resolve the domain to an IP address, then establishes a TCP connection to retrieve and render the website.

### Q: How can we find the owner information for a domain name?
A: You can query public WHOIS databases or use tools like whois to retrieve registration details.

### Q: What is dig?
A: dig (Domain Information Groper) is a flexible command-line tool used for querying DNS servers and analyzing records.

### Q: What is nslookup?
A: nslookup is a network administration command-line program used to query the Domain Name System (DNS) to obtain domain name or IP address mapping.

### Q: What are the different types of DNS RECORDS?
A: Common types include A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail exchange), TXT (text/verification), NS (nameserver), and SOA (start of authority).

### Q: What is DNS Dumpster?
A: DNS Dumpster is a free online reconnaissance tool that allows users to scan a domain for DNS records and map its infrastructure.

### Q: What is Shodan.io?
A: Shodan is a search engine that indexes Internet-connected devices, allowing users to find specific servers, IoT devices, and open ports by banner information.

### Q: How can we find subdomains?
A: Methods include brute-forcing with wordlists, checking certificate transparency logs, scraping search engines, and using specialized enumeration tools.

### Q: What is subfinder?
A: subfinder is a fast, passive subdomain discovery tool that gathers results from various online sources without directly interacting with the target.

### Q: What is the difference between Active reconnaissance and Passive reconnaissance?
A: Active reconnaissance involves directly interacting with the target system to gather data, while passive reconnaissance collects information from publicly available sources without touching the target.

---

# Active Reconnaissance

### Q: What is active reconnaissance?
A: Active reconnaissance is a cybersecurity phase involving direct interaction with a target system (like port scanning or sending requests) to gather detailed, real-time intelligence that often leaves detectable traces.

### Q: Why is active reconnaissance important for cyber security?
A: It provides precise, up-to-date data on open services and vulnerabilities, enabling both attackers to find entry points and defenders to validate their external attack surface and patch critical gaps.

### Q: How can Wappalyzer be used for active reconnaissance?
A: Wappalyzer performs active scanning by analyzing HTTP headers and HTML source code of web pages to fingerprint and identify the specific technology stack, CMS, and software versions in use.

### Q: What is DNS enumeration?
A: DNS enumeration is the process of querying Domain Name System records to map out network infrastructure, discover subdomains, and identify associated IP addresses and mail servers.

### Q: How to enumerate SMTPs using command-line tools?
A: You can enumerate SMTP users by running commands like telnet [target] 25 followed by VRFY [username] or EXPN [list] to verify if specific accounts exist on the mail server.

### Q: How should we perform OS fingerprinting?
A: OS fingerprinting is best performed using active tools like Nmap with flags such as -O to analyze TCP/IP stack responses, or passive methods that inspect packet characteristics without direct probing.

### Q: What is sqlmap? How to use it?
A: SQLmap is an automated penetration testing tool for detecting and exploiting SQL injection flaws; you typically use it by running a command like `sqlmap -u "http://target.com/page?id=1"` to test for vulnerabilities.
