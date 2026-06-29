# Week 3 Learning Objectives

## Networking Fundamentals

**Q: What is networking and why is it essential?**

A: Networking connects devices to share resources and data, enabling communication, collaboration, and access to centralized systems across organizations.

**Q: What is the difference between LAN and WAN?**

A: LAN spans a limited geographic area like a building while WAN covers larger distances connecting multiple locations or cities.

**Q: What are the main network topologies (Bus, Star, Ring, Mesh)?**

A: Bus uses a single backbone cable, Star centers around a hub/switch, Ring connects nodes in a circle, and Mesh provides redundant interconnections between all nodes.

**Q: What is the difference between physical and logical topology?**

A: Physical topology describes actual cable/device layout while logical topology defines how data flows through the network regardless of physical connections.

**Q: What are the 7 layers of the OSI model and their functions?**

A: Physical (cabling/signals), Data Link (frames/MAC), Network (packets/routing), Transport (segments/reliability), Session (connections), Presentation (encryption/formatting), Application (user interfaces).

**Q: What happens at each layer during data transmission?**

A: Data encapsulates downward adding headers at each layer during transmission and decapsulates upward removing headers at the receiving end.

**Q: What is encapsulation and decapsulation?**

A: Encapsulation adds protocol headers/footers as data moves down layers while decapsulation removes them as data moves up layers at the destination.

**Q: What are the 4 layers of the TCP/IP model?**

A: Network Interface, Internet, Transport, and Application layers corresponding to OSI's combined physical/data link, network, transport, and session/presentation/application.

**Q: How does TCP/IP compare to the OSI model?**

A: TCP/IP condenses OSI's 7 layers into 4 practical layers with TCP/IP being implementation-focused while OSI serves as a theoretical reference framework.

---

## Protocols & Transmission

**Q: What are the main network protocols (HTTP, HTTPS, FTP, SSH, DNS, DHCP)?**

A: HTTP/HTTPS for web traffic, FTP for file transfer, SSH for secure remote access, DNS for name resolution, and DHCP for automatic IP address assignment.

**Q: What is the difference between TCP and UDP?**

A: TCP is connection-oriented with guaranteed delivery and ordering while UDP is connectionless with faster but unreliable transmission without guarantees.

**Q: What are the different types of transmission media (wired vs wireless)?**

A: Wired includes twisted pair copper cables and fiber optics while wireless uses radio waves including Wi-Fi, cellular, and microwave technologies.

**Q: What is the role of a Hub, Switch, Router, Firewall?**

A: Hubs broadcast traffic indiscriminately, switches direct frames by MAC addresses, routers route packets between networks, and firewalls filter traffic by rules.

**Q: What is the difference between Layer 2 and Layer 3 devices?**

A: Layer 2 devices forward frames using MAC addresses while Layer 3 devices route packets using IP addresses across networks.

**Q: What is a VLAN and why is it used?**

A: A Virtual Local Area Network logically segments broadcast domains on a single switch for improved security, performance, and traffic management.

**Q: What is 802.1Q tagging?**

A: IEEE 802.1Q adds a 4-byte tag to Ethernet frames identifying VLAN membership for trunk links carrying multiple VLANs.

**Q: What are VLAN hopping attacks and how to prevent them?**

A: VLAN hopping allows unauthorized access across VLANs via switch spoofing or double-tagging; prevent by disabling auto-trunking and limiting native VLAN usage.

**Q: What is Inter-VLAN routing?**

A: Inter-VLAN routing enables communication between different VLANs using a router or Layer 3 switch acting as a gateway between segmented networks.

**Q: What is a MAC address and how is it structured?**

A: A Media Access Control address is a 48-bit unique hardware identifier formatted as six hexadecimal pairs separating OUI from device-specific portions.

**Q: What is the difference between OUI and NIC-specific portions?**

A: The first 24 bits (OUI) identify the manufacturer while the last 24 bits uniquely identify the individual network interface card.

**Q: What are special MAC addresses (broadcast, multicast)?**

A: Broadcast FF:FF:FF:FF:FF:FF reaches all devices while multicast addresses target specific groups and unicast targets a single destination.

**Q: What is an IPv4 address and its format?**

A: An IPv4 address is a 32-bit numerical identifier expressed in dotted decimal notation as four octets separated by periods (e.g., 192.168.1.1).

**Q: What are IP address classes (A, B, C, D, E)?**

A: Class A supports large networks (first bit 0), Class B medium (first bits 10), Class C small (first bits 110), Class D for multicast, Class E experimental.

**Q: What are private IP ranges (RFC 1918)?**

A: Private ranges include 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 which cannot be routed publicly and require NAT for internet access.

**Q: What are special IP addresses (loopback, broadcast)?**

A: Loopback 127.0.0.1 tests local TCP/IP stack and broadcast sends to all hosts within a network segment.

**Q: What is CIDR notation?**

A: Classless Inter-Domain Routing notation expresses IP blocks using prefix length (e.g., /24) indicating the number of bits in the network portion.

**Q: How to calculate subnets, hosts per subnet, and network ranges?**

A: Subnet count equals 2^(borrowed bits), hosts per subnet equals 2^(host bits)-2, and ranges are determined by incrementing the subnet portion systematically.

**Q: How to perform subnetting manually?**

A: Identify borrowed bits, calculate block size from least significant subnet bit, then increment network addresses by that block value.

**Q: What is ARP and how does it work?**

A: Address Resolution Protocol maps IP addresses to MAC addresses by broadcasting requests and caching responses in an ARP table.

**Q: What are the security concerns with ARP (ARP spoofing)?**

A: ARP lacks authentication allowing attackers to forge MAC-to-IP mappings enabling man-in-the-middle interception and traffic redirection attacks.

**Q: Why was IPv6 developed and how does it differ from IPv4?**

A: IPv6 was created to address IPv4 exhaustion with 128-bit addresses eliminating NAT, built-in IPsec, and simplified header structure.

**Q: What are well-known ports (0-1023)?**

A: Well-known ports are system-reserved for standard services like HTTP(80), HTTPS(443), SSH(22), DNS(53), and SMTP(25).

**Q: What are registered ports and dynamic ports?**

A: Registered ports (1024-49151) are assigned by IANA for applications while dynamic/ephemeral ports (49152-65535) are client-assigned temporarily.

**Q: What is DHCP and what problem does it solve?**

A: Dynamic Host Configuration Protocol automates IP address assignment preventing manual configuration errors and managing address pool allocation efficiently.

**Q: What is the DORA process (Discover, Offer, Request, Acknowledgement)?**

A: Client broadcasts Discover, server responds with Offer, client requests the offered address, and server acknowledges completing IP lease assignment.

**Q: What is a DHCP lease and how does renewal work?**

A: A DHCP lease is temporary IP assignment renewed automatically at 50% of lease time through unicast T1 renewal or broadcast T2 rebind.

**Q: What are DHCP attacks (Rogue Server, Starvation)?**

A: Rogue server attacks assign malicious configurations while starvation exhausts the address pool by flooding requests with fake MAC addresses.

**Q: What is DHCP Snooping and how does it protect networks?**

A: DHCP Snooping distinguishes trusted from untrusted ports blocking rogue server responses and validating DHCP packet integrity against a binding database.

**Q: What is NAT and why is it used?**

A: Network Address Translation maps private internal addresses to public external addresses conserving IPv4 space and providing basic security obfuscation.

**Q: What is the difference between Static NAT, Dynamic NAT, and PAT?**

A: Static creates permanent 1:1 mappings, Dynamic pools addresses dynamically assigning them, and PAT uses port multiplexing many:one for maximum conservation.

**Q: What is Port Forwarding?**

A: Port forwarding redirects incoming traffic on a specific public port to an internal private IP address and port mapping.

**Q: What is NAT Traversal (STUN, TURN, ICE)?**

A: STUN discovers public addresses, TURN relays through intermediate servers, and ICE combines methods for establishing connections through NAT.

**Q: What is Carrier-Grade NAT (CGNAT)?**

A: CGNAT extends NAT to ISP level where multiple subscribers share public IPs creating additional addressing constraints for end users.

**Q: What is DNS and how does it work?**

A: Domain Name System resolves human-readable domain names to IP addresses through hierarchical query cascading from recursive to authoritative servers.

**Q: What is the DNS hierarchy (Root, TLD, Authoritative)?**

A: Root servers delegate to Top-Level Domains which delegate to authoritative name servers holding actual resource records for specific domains.

**Q: What is the DNS resolution process?**

A: Recursive resolver queries root, receives TLD referral, queries TLD, receives authoritative referral, queries authoritative server returning final answer cached locally.

**Q: What are the main DNS record types (A, AAAA, CNAME, MX, NS, TXT, PTR)?**

A: A stores IPv4, AAAA IPv6, CNAME aliases, MX mail routing, NS name servers, TXT text verification, and PTR reverse lookup entries.

**Q: What are DNS security threats (Spoofing, Hijacking, Tunneling)?**

A: Spoofing returns false records, hijacking redirects domains to attacker servers, and tunneling exfiltrates data through DNS query responses.

**Q: What is DNSSEC and encrypted DNS (DoH, DoT)?**

A: DNSSEC digitally signs records ensuring authenticity while DoH/DoT encrypt queries preventing eavesdropping and modification attacks.

---

## Authentication & Directory Services

**Q: What is RADIUS and how does it work?**

A: Remote Authentication Dial-In User Service centralizes authentication using shared secrets and UDP transmitting credentials to verify access authorization.

**Q: What is TACACS+ and how does it differ from RADIUS?**

A: TACACS+ separates authentication authorization accounting over TCP encrypting entire payloads while RADIUS only encrypts passwords and combines AAA.

**Q: What is Kerberos and what attacks target it?**

A: Kerberos provides ticket-based mutual authentication requiring KDC; attacks include Golden Ticket, Silver Ticket, Pass-the-Ticket, and AS-REP Roasting.

**Q: What is LDAP and how is it used in networks?**

A: Lightweight Directory Access Protocol queries hierarchical directory databases for user authentication, group memberships, and centralized identity management.

**Q: Why is NTP important for security?**

A: Network Time Protocol ensures synchronized clocks critical for log correlation, certificate validation, Kerberos ticket timestamps, and forensic analysis accuracy.

**Q: What is Syslog and its severity levels?**

A: Syslog collects and forwards logs across 8 severity levels from Emergency(0) to Debug(7) enabling centralized monitoring and incident investigation.

**Q: What is an Autonomous System (AS) and ASN?**

A: An Autonomous System is a network under single administrative control identified by a unique Autonomous System Number for routing policy purposes.

**Q: What is BGP and how does it work?**

A: Border Gateway Protocol exchanges routing information between ASes selecting optimal paths based on policies maintaining global internet connectivity tables.

**Q: What are BGP hijacking attacks?**

A: BGP hijacking announces illegitimate prefixes redirecting traffic to attacker-controlled networks enabling interception disruption or surveillance.

**Q: What is peering vs transit?**

A: Peering directly exchanges traffic between networks without payment while transit purchases upstream connectivity accessing broader internet reach.

**Q: What is an Internet Exchange Point (IXP)?**

A: IXPs are physical facilities where networks interconnect for efficient local traffic exchange reducing latency and transit costs through direct peering.

**Q: What is a CDN and how does Anycast work?**

A: Content Delivery Networks cache content geographically while Anycast routes users to nearest identical IP announced from multiple locations simultaneously.

**Q: What are the Wi-Fi frequency bands (2.4 GHz, 5 GHz, 6 GHz)?**

A: 2.4GHz offers range with congestion, 5GHz provides speed with better penetration balance, and 6GHz delivers maximum throughput with limited range.

**Q: What are the Wi-Fi standards (802.11a/b/g/n/ac/ax)?**

A: Standards progress from 802.11a/b legacy through g/n improvements to ac(WiFi5) and ax(WiFi6) offering increasing speeds and efficiency gains.

**Q: What is the difference between WEP, WPA, WPA2, WPA3?**

A: WEP is broken RC4, WPA introduced TKIP, WPA2 mandates AES-CCMP, and WPA3 adds Simultaneous Authentication Equals forward secrecy protection.

**Q: What are common wireless attacks (Evil Twin, Deauth, KRACK)?**

A: Evil Twin mimics legitimate APs, deauthentication floods disconnect clients forcing reconnection, and KRACK exploits WPA2 handshake key reinstallation flaws.

**Q: What are wireless security best practices?**

A: Use WPA3 when available strong passphrases disable WPS separate SSIDs monitor for rogue APs and enable 802.1X Enterprise authentication.

**Q: What is the difference between PSK and Enterprise authentication?**

A: PSK uses shared pre-shared keys vulnerable to compromise while Enterprise leverages RADIUS authenticating each user individually with certificates or credentials.

---

## Security Principles & Defense

**Q: What is the CIA Triad (Confidentiality, Integrity, Availability)?**

A: Confidentiality prevents unauthorized disclosure, Integrity ensures data accuracy and trustworthiness, and Availability guarantees accessible resources when needed.

**Q: What is Defense in Depth?**

A: Defense in Depth layers multiple security controls across people processes and technology ensuring breach prevention even if individual controls fail.

**Q: What are the key security principles (Least Privilege, Zero Trust)?**

A: Least Privilege grants minimum necessary access rights while Zero Trust assumes no implicit trust requiring continuous verification of every request.

**Q: What is AAA (Authentication, Authorization, Accounting)?**

A: Authentication verifies identity, Authorization grants permissions, and Accounting tracks user actions for accountability and auditing compliance.

**Q: What are the main attack categories (Reconnaissance, Interception, DoS)?**

A: Reconnaissance gathers intelligence, Interception modifies/captures data in transit, and Denial-of-Service overwhelms resources preventing legitimate access.

**Q: What is a Man-in-the-Middle (MitM) attack?**

A: MitM positions attackers between communicating parties intercepting modifying or injecting messages without either party detecting the manipulation.

**Q: What are DDoS attacks (Volumetric, Protocol, Application)?**

A: Volumetric floods bandwidth, Protocol exhausts infrastructure state tables, and Application targets resource-intensive endpoints exhausting server capacity.

**Q: What are common password attacks?**

A: Brute force tries combinations, dictionary uses wordlists, rainbow tables use precomputed hashes, and credential stuffing reuses leaked credentials.

**Q: What are the types of firewalls (Packet Filtering, Stateful, NGFW)?**

A: Packet filters check individual packets, stateful track connection context, and Next-Gen Firewalls add deep inspection IDS application awareness.

**Q: How to write firewall rules?**

A: Define source destination port protocol action allow/deny order matters placing specific rules before general ones with implicit deny all default.

**Q: What is a DMZ?**

A: Demilitarized Zone isolates publicly-facing servers from internal networks limiting lateral movement if perimeter systems get compromised.

**Q: What is the difference between IDS and IPS?**

A: Intrusion Detection Systems alert on suspicious activity while Intrusion Prevention Systems actively block detected threats inline with traffic flow.

**Q: What are detection methods (Signature, Anomaly, Heuristic)?**

A: Signatures match known patterns, anomalies identify deviations from baseline behavior, and heuristics apply rule-based logic to detect novel threat indicators.

**Q: What is network segmentation and why is it important?**

A: Segmentation divides networks into isolated zones containing breaches limiting lateral movement and enforcing granular security policy boundaries.

**Q: What is Zero Trust architecture?**

A: Zero Trust requires explicit verification for every access request regardless of network location implementing microsegmentation continuous monitoring multi-factor auth.

**Q: What is a SIEM and what logs should be monitored?**

A: Security Information Event Management aggregates correlates analyzes logs from firewalls endpoints authentication systems and critical infrastructure components continuously.

**Q: What is NAC (Network Access Control)?**

A: Network Access Control validates device compliance identity health posture before granting network access blocking non-compliant endpoints.

**Q: What is 802.1X authentication and the EAP methods?**

A: 802.1X provides port-based network access control using Extensible Authentication Protocol variants including PEAP EAP-TLS and EAP-TTLS.

---

## Scanning & Enumeration

**Q: What are the types of port scans (TCP Connect, SYN, UDP)?**

A: TCP Connect completes three-way handshakes, SYN sends flags without completion stealthier, and UDP probes open/closed filtered UDP services.

**Q: What are the port states (Open, Closed, Filtered)?**

A: Open accepts connections, Closed rejects connections actively, and Filtered drops packets silently leaving status ambiguous to scanners.

**Q: What protocols are used for network enumeration (SNMP, NetBIOS, SMB, LDAP)?**

A: SNMP extracts device information, NetBIOS enumerates Windows shares, SMB reveals file shares/user sessions, and LDAP queries directory structures.

**Q: How to defend against reconnaissance?**

A: Implement strict firewall rules limit exposed services disable unnecessary protocols log scan attempts use IDS and employ honeytokens honeypots.

---

## Cryptography Basics

**Q: What is cryptography in cybersecurity?**

A: The science of securing data through mathematical algorithms that convert readable information into unreadable formats to protect confidentiality, integrity, and authenticity.

**Q: What are the different types of cryptography?**

A: Symmetric encryption (single shared key), asymmetric encryption (public-private key pairs), and cryptographic hashing (one-way functions).

**Q: What is Encryption?**

A: The process of transforming plaintext into ciphertext using an algorithm and key, rendering data unreadable without the appropriate decryption key.

**Q: What is Decryption?**

A: The reverse process of converting ciphertext back into readable plaintext using the correct cryptographic key.

**Q: What is the importance of cryptography?**

A: It protects sensitive data at rest and in transit, ensures authentication, prevents tampering, and maintains regulatory compliance across digital systems.

**Q: What are the types of cryptography?**

A: Symmetric cryptography uses one shared secret key, asymmetric uses mathematically linked public-private key pairs, and hashing produces irreversible fixed-length digests for integrity verification.

**Q: What are the applications of cryptography?**

A: Secure communications (TLS/SSL), disk encryption, digital signatures, cryptocurrency/blockchain, authentication systems, VPN tunneling, and secure key exchange protocols.

**Q: What is a hash algorithm?**

A: A one-way mathematical function that converts arbitrary-length input into a fixed-length deterministic output used for integrity checks and password storage without reversible decryption.

**Q: What SHA stands for?**

A: Secure Hash Algorithm, a family of cryptographic hash functions published by NIST producing digests of varying bit lengths (SHA-1, SHA-256, SHA-512, etc.).

**Q: What is John the Ripper?**

A: An open-source password cracking tool that recovers passwords from hashed formats using dictionary attacks, brute force, and rule-based transformations.

**Q: How to use John the Ripper?**

A: Run john against a hash file specifying format with --format=, optional wordlist with --wordlist=, and rules with --rules; cracked passwords display via --show.

**Q: How to crack advanced hashes with John the Ripper?**

A: Specify exact hash format, apply aggressive rule sets (--rules=Jumbo), use large/custom wordlists, enable incremental mode, and leverage dynamic magic for auto-detection.

**Q: What is hashcat?**

A: A high-performance password recovery tool leveraging GPU acceleration to crack hashes significantly faster than CPU-based tools, supporting hundreds of hash types and multiple attack modes.

**Q: How to use hashcat?**

A: Execute hashcat with the hash file, hash type identifier (-m #), attack mode (-a #), and wordlist/mask path; cracked results display with --show.

---

## Authentication vs Authorization

### General Concepts

**Q: What is the purpose of authentication in computer security?**

A: Authentication verifies the identity of a user, system, or entity requesting access.

**Q: What is the purpose of authorization in access control systems?**

A: Authorization determines what actions and resources an authenticated entity is permitted to access.

**Q: What are the fundamental differences between authentication and authorization?**

A: Authentication confirms who you are; authorization determines what you can do.

**Q: What is the correct sequence of authentication and authorization in security systems?**

A: Authentication always occurs first, followed by authorization — you must prove identity before permissions can be evaluated.

### Authentication

**Q: What are the three main authentication factors?**

A: Something you know (password/PIN), something you have (token/smart card), and something you are (biometrics).

**Q: How does the authentication process work?**

A: A subject presents credentials which are validated against a stored identity record, and a token or session is issued upon success.

**Q: What are the main authentication protocols?**

A: OAuth 2.0, OpenID Connect (OIDC), SAML, Kerberos, and RADIUS.

**Q: What is the difference between single-factor and multi-factor authentication?**

A: Single-factor uses one credential type, while MFA combines two or more distinct factors, significantly reducing compromise risk.

**Q: What HTTP status code indicates authentication failure?**

A: 401 Unauthorized indicates authentication failure (despite the misleading name).

### Authorization

**Q: What are the main authorization models?**

A: RBAC, ABAC, ACL (Access Control List), MAC (Mandatory Access Control), and DAC (Discretionary Access Control).

**Q: How does Role-Based Access Control (RBAC) work?**

A: Permissions are assigned to roles, and users inherit those permissions by being assigned to the appropriate role.

**Q: How does Attribute-Based Access Control (ABAC) differ from RBAC?**

A: ABAC evaluates dynamic attributes (user, resource, environment, action) rather than static roles, enabling finer-grained and context-aware decisions.

**Q: What are the components of authorization?**

A: Subject (requester), action (operation), resource (target object), and policy/context (rules governing the decision).

**Q: What HTTP status code indicates authorization failure?**

A: 403 Forbidden indicates the authenticated user lacks permission for the requested resource.

### Security Best Practices

**Q: What are the advantages of implementing both authentication and authorization?**

A: Together they enforce defense-in-depth — ensuring only verified identities access only their permitted resources.

**Q: What are the security risks of skipping authentication or authorization?**

A: Skipping authentication allows impersonation and uncontrolled entry; skipping authorization lets any authenticated user access all resources, leading to privilege escalation and data breaches.

**Q: How do authentication and authorization work together to protect systems?**

A: Authentication gates entry by verifying identity, then authorization restricts scope by enforcing least-privilege access policies.

**Q: What is the difference between a username/password and biometric authentication?**

A: Username/password is a knowledge factor that can be shared or reset, while biometrics is an inherent factor that is unique to the individual and cannot be easily changed if compromised.
