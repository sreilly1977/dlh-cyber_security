================================================================================

  HEALTHBANE ATTACK FRAMEWORK MAPPING
  
  MITRE ATT&CK v15 NAVIGATOR
  
  Project 4x02 - Intelligence-Driven Defense
  
================================================================================

Document ID:      MD-4x02-ATTACK-MAP-001

Analyst:          Steve - Cybersecurity Engineer

Date:             2026-09-28

Classification:   INTERNAL

Framework:        MITRE ATT&CK Enterprise v15

================================================================================

1. EXECUTIVE SUMMARY

================================================================================

Total ATT&CK techniques identified: 30

  - OBSERVED (direct evidence): 18 (60%)
  
  - INFERRED (logical necessity or parent-category): 12 (40%)

Tactics with most coverage:

  1. Execution (5 techniques: 4 OBSERVED, 1 INFERRED)
  
  2. Resource Development (5 techniques: 4 OBSERVED, 1 INFERRED)
  
  3. Initial Access / Persistence / Command and Control /
     Exfiltration (3 techniques each)

Tactics with least coverage:

  1. Privilege Escalation, Defense Evasion, Discovery, Lateral Movement
     (0 to 1 techniques; no evidence of these behaviors in sources)
     
  2. Collection (2 techniques, both INFERRED - a detection gap, not an
     adversary absence; see Task 8 gap analysis)

Most important techniques for detection planning:

  1. T1071.004 (DNS) - DNS tunnel exfiltration, HIGH-fidelity signature
  
  2. T1566.002 (Spearphishing Link) - primary initial access vector
  
  3. T1053.005 (Scheduled Task) - reliable persistence mechanism
  
  4. T1056.003 (Web Portal Capture) - credential theft endpoint detection


================================================================================

2. TECHNIQUE MAPPING BY TACTIC

================================================================================

Legend:

  OBSERVED = Direct evidence in at least one source (victim telemetry,
             packet capture, sandbox detonation, kit artifact)
             
  INFERRED = Logical necessity from observed behavior, but not directly
             witnessed in available telemetry

--------------------------------------------------------------------------------

RECONNAISSANCE (1 technique)

--------------------------------------------------------------------------------

T1589.002 - Gather Victim Identity: Email

  Classification:     OBSERVED
  
  Evidence:           HC3 Section 4; HC3 Section 1.5 describes lookalike domains
                      registered 4-10 days before first email, requiring
                      prior victim identification
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (Section 4)
  
  Attack Phase:       Pre-campaign (Resource Development precursor)
  
  Notes:              Operator identified healthcare organizations via
                      public directories, employee profiles, or breach data

--------------------------------------------------------------------------------

RESOURCE DEVELOPMENT (5 techniques)

--------------------------------------------------------------------------------

T1583.001 - Acquire Infrastructure: Domains

  Classification:     OBSERVED
  
  Evidence:           HC3 Section 4; 8 domains registered 2026-04-05 to
                      2026-04-10 per HC3 and Internal 4x00 F2
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt; Internal 4x00
  
  Attack Phase:       Pre-campaign

T1585.002 - Establish Accounts: Email

  Classification:     OBSERVED
  
  Evidence:           HC3 Section 4; Stage 2 emails sent FROM compromised
                      legitimate accounts (credential reuse after Stage 1)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (Section 2)
  
  Attack Phase:       Stage 1 → Stage 2 transition

T1587.001 - Develop Capabilities: Malware

  Classification:     OBSERVED
  
  Evidence:           HC3 Section 4; custom macro dropper, svchost_update.exe,
                      sync_healthdata.ps1 all observed; researcher recovered
                      kit ZIP from attacker infrastructure
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt; researcher_blog
  
  Attack Phase:       Pre-campaign

T1608.005 - Stage Capabilities: Link Target

  Classification:     OBSERVED
  
  Evidence:           HC3 Section 4; phishing landing pages customized per
                      target brand using templating system (researcher
                      discovered per-target static/ assets in kit)
                      
  Source:             researcher_blog_analysis.txt (Section 2)
  
  Attack Phase:       Pre-campaign

T1584.001 - Compromise Infrastructure: Host Server (INFERRED)

  Classification:     INFERRED
  
  Evidence:           Kit directory listing exposure on misconfigured
                      attacker endpoint enabled researcher to download
                      full phishing kit (researcher Section 1); this
                      indicates the operator owns the server, and the
                      operator likely compromised it or purchased hosting
                      
  Source:             researcher_blog_analysis.txt (Section 1)
  
  Attack Phase:       Pre-campaign (attacker-side)

--------------------------------------------------------------------------------

INITIAL ACCESS (4 techniques)

--------------------------------------------------------------------------------

T1566.002 - Spearphishing Link

  Classification:     OBSERVED
  
  Evidence:           Primary vector per HC3 Section 2, Stage 1; dmarsh clicked
                      link in email E2 (Internal 4x00); all three 4x00 phishing
                      emails contained clickable URLs
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt; Internal 4x00
  
  Attack Phase:       Stage 1

T1566.001 - Spearphishing Attachment

  Classification:     OBSERVED
  
  Evidence:           Stage 2 macro document delivered via email from
                      compromised internal account (HC3 Section 2);
                      HEALTHBANE_S2_invoice.docm hash confirmed
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (Section 2)
  
  Attack Phase:       Stage 2

T1566.003 - Spearphishing via Service (INFERRED)

  Classification:     INFERRED
  
  Evidence:           outlook-protection.com variant passes full email
                      authentication (Internal F3); this may indicate
                      compromised legitimate service accounts or
                      sophisticated DNS configuration
                      
  Source:             Internal 4x00_findings.txt (F3)
  
  Attack Phase:       Stage 1

T1199 - Trusted Relationship (INFERRED)

  Classification:     INFERRED
  
  Evidence:           Stage 2 emails sent FROM compromised internal email
                      accounts to colleagues exploit existing trust between
                      internal senders and recipients
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (Section 2)
  
  Attack Phase:       Stage 2

--------------------------------------------------------------------------------

EXECUTION (4 techniques)

--------------------------------------------------------------------------------

T1204.001 - User Execution: Malicious Link

  Classification:     OBSERVED
  
  Evidence:           dmarsh clicked link in email E2 (Internal 4x00 F5);
                      47-second HTTPS session logged to phishing LP
                      
  Source:             Internal 4x00_findings.txt
  
  Attack Phase:       Stage 1

T1204.002 - User Execution: Malicious File

  Classification:     OBSERVED
  
  Evidence:           Stage 2 macro document required user interaction
                      to enable macros and execute payload (HC3 Section 2)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
  
  Attack Phase:       Stage 2

T1059.005 - VBA (macro)

  Classification:     OBSERVED
  
  Evidence:           HEALTHBANE_S2_invoice.docm is macro-enabled; macro
                      pulls executable from C2 (HC3 Section 2, Stage 2)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
  
  Attack Phase:       Stage 2

T1059.001 - PowerShell

  Classification:     OBSERVED
  
  Evidence:           sync_healthdata.ps1 observed; deployed Stage 2,
                      performed Stage 3 exfiltration (HC3 Section 3.3)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
  
  Attack Phase:       Stage 2/3

T1059 - Command and Scripting Interpreter (INFERRED)

  Classification:     INFERRED
  
  Evidence:           PowerShell is a subtype; broader category applies
                      when specific version unknown
                      
  Source:             Derived from T1059.001
  
  Attack Phase:       Stage 2/3

--------------------------------------------------------------------------------

PERSISTENCE (2 techniques)

--------------------------------------------------------------------------------

T1053.005 - Scheduled Task

  Classification:     OBSERVED
  
  Evidence:           Scheduled task "HealthSync Update Service" installed
                      (HC3 Section 2); detection rule hunts for name
                      pattern in Section 5.3
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
  
  Attack Phase:       Stage 2

T1547.001 - Registry Run Keys

  Classification:     OBSERVED
  
  Evidence:           Persistence via Registry Run key documented
                      (HC3 Section 2)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
  
  Attack Phase:       Stage 2

T1543.003 - Windows Service (INFERRED)

  Classification:     INFERRED
  
  Evidence:           Named "HealthSync Update Service" suggests service
                      installation; could be service OR scheduled task
                      (HC3 confirms task, service not explicitly ruled out)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (name suggests)
  
  Attack Phase:       Stage 2

--------------------------------------------------------------------------------

PRIVILEGE ESCALATION (0 techniques)

--------------------------------------------------------------------------------

No privilege escalation techniques observed in available evidence.
Operator achieved desired outcome (credential access + exfil) without
admin elevation.

--------------------------------------------------------------------------------

DEFENSE EVASION (0 techniques)

--------------------------------------------------------------------------------

Minimal evasion observed. Notable absence of anti-analysis techniques:

  - No code obfuscation reported in payloads
  
  - DNS tunnel not obfuscated beyond base32 encoding
  
  - No process injection documented
  
This suggests mid-tier operator focused on speed over stealth.

T1027 - Obfuscated Files or Information (INFERRED)

  Classification:     INFERRED (weak)
  
  Evidence:           Base32 encoding in DNS labels may qualify as
                      minimal obfuscation; no strong evidence
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (inferred)
  
  Attack Phase:       Stage 3

--------------------------------------------------------------------------------

CREDENTIAL ACCESS (2 techniques)

--------------------------------------------------------------------------------

T1056.003 - Web Portal Capture

  Classification:     OBSERVED
  
  Evidence:           Phishing landing pages collected username/password
                      via PHPMailer-served HTML form (HC3 Section 2);
                      credentials posted to attacker VPS
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt; Internal 4x00
  
  Attack Phase:       Stage 1

T1056 - Input Capture (INFERRED)

  Classification:     INFERRED
  
  Evidence:           Web portal capture is a subtype; general category
                      applies when form POST observed but keystroke
                      logging not confirmed
                      
  Source:             Derived from T1056.003
  
  Attack Phase:       Stage 1

T1552.001 - Credentials From Password Stores (INFERRED)

  Classification:     INFERRED
  
  Evidence:           Once inside via stolen credentials, attacker could
                      harvest stored credentials; no confirmation from
                      victim telemetry
                      
  Source:             Hypothesized from T1078 credential usage
  
  Attack Phase:       Stage 2+ (post-initial access)

--------------------------------------------------------------------------------

DISCOVERY (0 techniques)

--------------------------------------------------------------------------------

No discovery techniques explicitly documented in available evidence.

--------------------------------------------------------------------------------

LATERAL MOVEMENT (0 techniques)

--------------------------------------------------------------------------------

No lateral movement techniques explicitly documented in available evidence.
Stage 2 involved authenticated email from compromised account to colleagues,
but no network lateral movement confirmed.

--------------------------------------------------------------------------------

COLLECTION (1 technique)

--------------------------------------------------------------------------------

T1213 - Collect Data From Network Share (INFERRED)

  Classification:     INFERRED
  
  Evidence:           Exfiltrated data included patient records and insurance
                      claims (HC3); collection method not documented; network
                      share access is a common collection method for healthcare
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (data types imply)
  
  Attack Phase:       Stage 3 (pre-exfiltration)

T1005 - Data From Local System (INFERRED)

  Classification:     INFERRED
  
  Evidence:           Patient records must be located and copied from local
                      endpoints or network shares before exfiltration
                      
  Source:             Logical necessity from HC3 data type descriptions
  
  Attack Phase:       Stage 3

--------------------------------------------------------------------------------

COMMAND AND CONTROL (3 techniques)

--------------------------------------------------------------------------------

T1071.004 - DNS

  Classification:     OBSERVED
  
  Evidence:           DNS TXT-record tunneling to data-sync.healthbane-c2.net
                      with base32 subdomain labels (HC3 Section 2, Stage 3)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (Section 3.4)
  
  Attack Phase:       Stage 3

T1071.001 - Web Protocols

  Classification:     OBSERVED
  
  Evidence:           Stage 1 phishing LPs via HTTP(S); Stage 2 malware
                      download via HTTPS from C2 (healthbane-c2.net)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt; Internal 4x00
  
  Attack Phase:       Stage 1/2

T1095 - Non-Application Layer Protocol (INFERRED)

  Classification:     INFERRED
  
  Evidence:           DNS tunnel qualifies as non-application layer
                      communication; T1071.004 is more specific
                      
  Source:             Derived from T1071.004
  
  Attack Phase:       Stage 3

--------------------------------------------------------------------------------

EXFILTRATION (2 techniques)

--------------------------------------------------------------------------------

T1048.003 - Exfiltration Over Unencrypted Non-C2

  Classification:     OBSERVED
  
  Evidence:           HC3 Section 2, Stage 3: "Exfiltrates patient records
                      and insurance claims data by encoding them in base32
                      subdomain labels of DNS TXT-record queries"
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
  
  Attack Phase:       Stage 3

T1041 - Exfiltration Over C2 Channel

  Classification:     OBSERVED
  
  Evidence:           Same DNS tunnel traffic serves both exfil and C2
                      command/response (TXT records containing base64-encoded
                      commands per HC3 Section 2)
                      
  Source:             HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
  
  Attack Phase:       Stage 3

T1048 - Exfiltration Over Alternative Protocol (INFERRED)

  Classification:     INFERRED
  
  Evidence:           DNS tunnel may be primary; other channels not ruled
                      out; T1048.003 is more specific if confirmed
                      
  Source:             Derived from T1048.003
  
  Attack Phase:       Stage 3

================================================================================

3. DETECTION PLANNING PRIORITIES

================================================================================

Based on technique frequency, observability, and operational impact:

Priority 1 (Highest Value Detections):

  1. T1071.004 (DNS) - Query-length anomaly detection on subdomains > 40 chars
  
  2. T1566.002 (Spearphishing Link) - Email gateway blocking on campaign domains
  
  3. T1053.005 (Scheduled Task) - Task name pattern detection ("Sync", "Update")
  
  4. T1056.003 (Web Portal Capture) - Outbound to new domains with credential forms

Priority 2 (Medium Value):

  5. T1059.001 (PowerShell) - Script Block Logging for base64 payloads > 1KB
  
  6. T1547.001 (Registry Run Keys) - Run-key modification monitoring
  
  7. T1071.001 (Web Protocols) - C2 domain blocking + TLS inspection

Priority 3 (Lower Priority):

  8. T1583.001 (Acquire Infrastructure) - Newly registered domain alerts
  
  9. T1059.005 (VBA) - Macro execution alerts from external senders

================================================================================

END OF ATTACK FRAMEWORK MAPPING       MD-4x02-ATTACK-MAP-001

================================================================================
