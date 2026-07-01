# Top 25 Wazuh Queries

## Authentication & Access Control

### 1. Multiple Failed Login Attempts (Brute Force Detection)

```xml
<rule id="100101" level="10">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>Multiple failed SSH login attempts - possible brute force</description>
  <group>authentication_failures,brute_force,</group>
</rule>
```

Triggers when repeated SSH authentication failures occur from the same IP within a time window.

### 2. Successful Login After Failed Attempts

```xml
<rule id="100102" level="12">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>Successful authentication after multiple failed attempts</description>
  <group>authentication_success,brute_force,</group>
</rule>
```

Detects a successful login following brute force attempts — high-priority indicator of compromise.

### 3. Login Outside Business Hours

```xml
<rule id="100103" level="7">
  <if_sid>5715</if_sid>
  <time>6 pm - 6 am</time>
  <weekday>saturday,sunday</weekday>
  <description>Login attempt outside business hours</description>
  <group>login_time,</group>
</rule>
```

Flags authentications occurring during unusual times or weekends.

### 4. Root/Superuser Login Detection

```xml
<rule id="100104" level="9">
  <if_sid>5715</if_sid>
  <user>root</user>
  <description>Direct root login detected</description>
  <group>privileged_login,</group>
</rule>
```

Catches direct root logins, which should typically be disabled in favor of sudo.

### 5. New User Account Creation

```xml
<rule id="100105" level="8">
  <if_sid>5402</if_sid>
  <description>New user account created on the system</description>
  <group>account_changes,</group>
</rule>
```

Monitors for newly created local accounts — common post-exploitation activity.

## Privilege Escalation

### 6. Sudo Usage Monitoring

```xml
<rule id="100106" level="5">
  <if_sid>5402</if_sid>
  <match>sudo</match>
  <description>Sudo command execution detected</description>
  <group>privilege_escalation,</group>
</rule>
```

Tracks all privilege escalation via sudo for audit purposes.

### 7. SUID Binary Execution

```xml
{
  "query": {
    "bool": {
      "must": [
        {"match": {"data.suid": "true"}},
        {"match_phrase": {"data.file": "/usr/bin/"}}
      ]
    }
  }
}
```

Indexer query to find execution of SUID binaries, often used in privilege escalation attacks.

### 8. Unauthorized SUID File Creation

```xml
<rule id="100107" level="10">
  <if_sid>5503</if_sid>
  <match>chmod</match>
  <regex>\+s|4777|4755</regex>
  <description>SUID bit set on file - possible privilege escalation</description>
  <group>privilege_escalation,suid,</group>
</rule>
```

Detects when the SUID bit is set on a file, a classic priv-esc technique.

## File Integrity & System Changes

### 9. Critical File Modification (FIM)

```xml
<rule id="100108" level="10">
  <if_sid>5503</if_sid>
  <match>/etc/passwd|/etc/shadow|/etc/sudoers|/etc/ssh/sshd_config</match>
  <description>Critical system file modified</description>
  <group>file_integrity,critical_files,</group>
</rule>
```

Alerts on changes to mission-critical configuration files.

### 10. Binary File Replacement

```xml
<rule id="100109" level="12">
  <if_sid>5530</if_sid>
  <match>/usr/bin/|/usr/sbin/|/bin/|/sbin/</match>
  <description>System binary modified - possible rootkit/trojan</description>
  <group>file_integrity,malware,rootkit,</group>
</rule>
```

Detects replacement of system binaries — a hallmark of rootkit installation.

## 11. Web Shell Detection

```xml
<rule id="100110" level="12">
  <if_sid>5503</if_sid>
  <match>/var/www/|/srv/http/|/opt/lampp/htdocs/</match>
  <regex>\.php$|\.jsp$|\.asp$</regex>
  <description>New script file created in web root - possible web shell</description>
  <group>file_integrity,web_shell,malware,</group>
</rule>
```

Flags new script files appearing in web server directories.

## Network & Connection Monitoring
### 12. Outbound Connection to Suspicious Port

```xml
{
  "query": {
    "bool": {
      "should": [
        {"match": {"data.dstport": "4444"}},
        {"match": {"data.dstport": "1337"}},
        {"match": {"data.dstport": "9001"}}
      ],
      "filter": [
        {"range": {"data.dstip": {"gte": "0.0.0.0", "lte": "255.255.255.255"}}}
      ]
    }
  }
}
```

Indexer query to detect connections to ports commonly used by reverse shells and C2 frameworks.

### 13. Reverse Shell Detection

```xml
<rule id="100111" level="14">
  <if_sid>5302</if_sid>
  <match>/dev/tcp/|nc -e|bash -i&gt;&amp;1|python -c 'import socket</match>
  <description>Possible reverse shell command execution</description>
  <group>reverse_shell,network,</group>
</rule>
```

Detects commands commonly associated with establishing reverse shells.

### 14. Listening on Non-Standard Ports

```xml
<rule id="100112" level="7">
  <if_sid>5302</if_sid>
  <match>LISTEN</match>
  <regex>:(1337|4444|8080|9090|31337)</regex>
  <description>Process listening on suspicious port</description>
  <group>network,listening_ports,</group>
</rule>
```

Identifies services binding to ports frequently used by malware.

### 15. DNS Exfiltration Detection

```xml
<rule id="100113" level="11">
  <if_sid>5302</if_sid>
  <program_name>named</program_name>
  <regex>QUERY.*TXT</regex>
  <frequency>20</frequency>
  <timeframe>60</timeframe>
  <description>High volume of TXT DNS queries - possible data exfiltration</description>
  <group>dns,exfiltration,data_loss,</group>
</rule>
```

Large volumes of TXT record queries can indicate DNS tunneling for data exfiltration.

## Malware & IOC Detection

### 16. Known Malware Hash Detection

```xml
{
  "query": {
    "bool": {
      "must": [
        {"exists": {"field": "data.hash"}},
        {"terms": {"data.hash.sha256": [
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]}}
      ]
    }
  }
}
```

Indexer query matching file hashes against known malicious IOCs.

### 17. Suspicious Process Execution

```xml
<rule id="100114" level="12">
  <if_sid>5302</if_sid>
  <match>mimikatz|procdump|powershell.exe -enc|certutil -decode|rundll32</match>
  <description>Suspicious process associated with credential theft or lateral movement</description>
  <group>malware,credential_theft,lateral_movement,</group>
</rule>
```

Flags execution of tools commonly used by attackers for credential dumping and evasion.

### 18. Encoded PowerShell Execution

```xml
<rule id="100115" level="12">
  <if_sid>5302</if_sid>
  <match>powershell</match>
  <regex>-enc|-EncodedCommand|JAB</regex>
  <description>Encoded PowerShell command execution - possible obfuscation</description>
  <group>malware,powershell,obfuscation,</group>
</rule>
```

Detects base64-encoded PowerShell commands, a frequent obfuscation technique used in real-world attacks.

## Command & Activity Auditing

### 19. Shell History Cleared

```xml
<rule id="100116" level="9">
  <if_sid>5302</if_sid>
  <match>history -c|rm ~/.bash_history|cat /dev/null > ~/.bash_history</match>
  <description>Shell history cleared - anti-forensics behavior</description>
  <group>anti_forensics,evasion,</group>
</rule>
```

Tampering with shell history is a strong indicator someone is trying to cover their tracks.

### 20. Cron Job Modification

```xml
<rule id="100117" level="10">
  <if_sid>5503</if_sid>
  <match>/etc/crontab|/etc/cron.d/|/var/spool/cron/</match>
  <description>Cron job modified - possible persistence mechanism</description>
  <group>persistence,cron,</group>
</rule>
```

Attackers frequently modify cron jobs for persistence — this catches those changes.

### 21. SSH Authorized Keys Modified

```xml
<rule id="100118" level="11">
  <if_sid>5503</if_sid>
  <match>.ssh/authorized_keys</match>
  <description>SSH authorized_keys file modified - possible backdoor</description>
  <group>persistence,ssh,backdoor,</group>
</rule>
```

Adding SSH keys is one of the most common persistence techniques on Linux systems.

## SOC & Compliance Queries

### 22. User Group Changes (Compliance Audit)

```xml
<rule id="100119" level="8">
  <if_sid>5402</if_sid>
  <match>usermod|gpasswd|useradd|groupadd|visudo</match>
  <description>User or group membership changed - requires audit review</description>
  <group>compliance,user_management,cis,</group>
</rule>
```

Important for CIS, PCI-DSS, and HIPAA compliance requirements around access management.

### 23. Kernel Module Loading

```xml
<rule id="100120" level="10">
  <if_sid>5302</if_sid>
  <match>insmod|modprobe</match>
  <description>Kernel module loaded - possible rootkit</description>
  <group>kernel_module,rootkit,persistence,</group>
</rule>
```

Rootkits often load kernel modules to hide their presence — this flags the activity.

### 24. USB / Removable Media Insertion

```xml
<rule id="100121" level="6">
  <if_sid>5302</if_sid>
  <match>usb</match>
  <regex>new full-speed USB device|new high-speed USB device</regex>
  <description>USB/removable media inserted</description>
  <group>removable_media,data_transfer,</group>
</rule>
```

Useful for DLP (Data Loss Prevention) and insider threat monitoring.

### 25. VPN Connection from Anomalous Location

```xml
{
  "query": {
    "bool": {
      "must_not": [
        {"terms": {"data.srcip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]}}
      ],
      "filter": [
        {"term": {"data.event_type": "vpn_connection"}},
        {"range": {"@timestamp": {"gte": "now-1h/h"}}}
      ]
    }
  }
}
```

Indexer query to catch VPN connections originating from unexpected external IPs, helping detect unauthorized remote access.

## Quick Reference Summary
###	Category	Risk Level	Technique
1–5	Authentication	L5–L12	Brute force, root login, new accounts
6–8	Privilege Escalation	L5–L12	Sudo, SUID abuse
9–11	File Integrity	L10–L12	Critical file changes, web shells
12–15	Network	L7–L14	Reverse shells, DNS exfil, suspicious ports
16–18	Malware/IOC	L12	Hashes, suspicious processes, encoded PS
19–21	Anti-Forensics & Persistence	L9–L11	History clearing, cron, SSH keys
22–25	Compliance & SOC	L6–L10	Group changes, kernel modules, USB, VPN

These are starting points, Steve — each should be tuned to your specific environment (whitelisting known-good IPs, adjusting frequency/timeframe windows, and integrating with your threat intel feeds).

Happy hunting!
