# Authentication & Access

## 1. Failed Logins (Brute Force Detection)

```spl
index=* sourcetype=* (eventtype=authentication OR action=failure)
| stats count as failures by user, src_ip, dest_host
| where failures > 5
| sort -failures
```

## 2. Successful Login After Multiple Failures

```spl
index=* sourcetype=* (action=failure OR action=success)
| stats count(eval(action="failure")) as failed_attempts,
       max(eval(if(action="success", _time, null))) as success_time,
       values(src_ip) as src_ips by user
| where failed_attempts > 3 AND isnotnull(success_time)
```

## 3. Logins Outside Business Hours

```spl
index=* sourcetype=* action=success
| eval hour=strftime(_time, "%H")
| where (hour < 7 OR hour > 18) AND date_wday!="Saturday" AND date_wday!="Sunday"
| table _time, user, src_ip, dest_host, action
```

## 4. Login from New Geographic Location

```spl
index=* sourcetype=* action=success
| iplocation src_ip
| stats values(Country) as countries, values(City) as cities by user
| eventstats dc(Country) as country_count by user
| where country_count > 1
```

## 5. Multiple Users from Same IP

```spl
index=* sourcetype=* action=success
| stats dc(user) as unique_users, values(user) as users by src_ip
| where unique_users > 3
| sort -unique_users
```

#  Endpoint & Process Monitoring

## 6. Suspicious PowerShell Execution

```spl
index=* (EventCode=4688 OR source=WinEventLog:Microsoft-Windows-PowerShell/Operational)
(Powershell.exe OR powershell_ise.exe)
("*-enc*" OR "*-EncodedCommand*" OR "*downloadstring*" OR "*iex*" OR "*Invoke-*")
| table _time, host, user, CommandLine, process_name
```

## 7. Rundll32 with Suspicious Arguments

```spl
index=* EventCode=4688 rundll32.exe
| regex CommandLine="(?i)(javascript|mshtml|shell\.Application|ShellExecute|htm)"
| table _time, host, user, CommandLine, parent_process
```

## 8. Credential Dumping — LSASS Access

```spl
index=* (EventCode=4656 OR EventCode=4663)
(ObjectName="*lsass.exe*" OR ObjectName="*lsass*")
| stats count by host, user, AccessMask, process_name
| table _time, host, user, process_name, AccessMask
```

## 9. Scheduled Task Creation (Persistence)

```spl
index=* (EventCode=4698 OR source=WinEventLog:System "Task Scheduler")
| table _time, host, user, TaskName, TaskContent, Command
```

## 10. New Service Installation (Persistence)

```spl
index=* EventCode=7045 OR (EventCode=4697)
| table _time, host, user, ServiceName, ServiceType, StartType, ServiceCommand
```

# Network & Traffic Analysis

## 11. DNS Queries to Known Malicious Domains (Threat Intel Match)

```spl
index=dns sourcetype=dns
| lookup malicious_domains domain OUTPUT threat_name
| where isnotnull(threat_name)
| stats count by src_ip, domain, threat_name
```

## 12. Beaconing Behavior Detection

```spl
index=* sourcetype=firewall OR sourcetype=network
| bin _time span=1m
| stats count by src_ip, dest_ip, _time
| streamstats avg(count) as avg_count stdev(count) as stdev by src_ip, dest_ip window=60
| where count > 0 AND stdev < (avg_count * 0.5)
| stats count as sessions by src_ip, dest_ip, avg_count, stdev
| where sessions > 50
```

## 13. Data Exfiltration — Large Outbound Transfers

```spl
index=* sourcetype=firewall action=allowed
| stats sum(bytes_out) as total_out by src_ip, dest_ip, dest_port
| where total_out > 100000000
| sort -total_out
```

## 14. Connections to Non-Standard Ports

```spl
index=* sourcetype=firewall action=allowed
| stats count by src_ip, dest_ip, dest_port
| where dest_port NOT IN (80, 443, 22, 53, 25, 123, 3389)
| sort -count
```

## 15. Tor Exit Node Traffic

```spl
index=* sourcetype=firewall OR sourcetype=network
| lookup tor_exit_nodes ip AS dest_ip OUTPUT ip as tor_match
| where isnotnull(tor_match)
| stats count by src_ip, dest_ip, dest_port
```

# File Integrity & Data Access

## 16. Mass File Access / Staging for Exfiltration

```spl
index=* sourcetype=auditd OR (EventCode=4663 OR EventCode=4656)
| bucket _time span=5m
| stats count as access_count, dc(ObjectName) as unique_files by user, _time
| where access_count > 500
| sort -access_count
```

## 17. Ransomware Indicators — Rapid File Encryption

```spl
index=* sourcetype=auditd OR (EventCode=4663)
(rename OR create_file OR delete)
| bucket _time span=1m
| stats count as file_ops by host, user, _time
| where file_ops > 100
| sort -file_ops
```

## 18. Suspicious File Creation in Startup Folder

```spl
index=* EventCode=11 (TargetFilename="*\\Start Menu\\Programs\\Startup\\*")
| table _time, host, user, TargetFilename, Image
```

# Privilege Escalation

## 19. User Added to Privileged Group

```spl
index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| rename MemberName as member, TargetUserName as group_name
| table _time, host, user, member, group_name
```

## 20. Clearing Security Logs (Anti-Forensics)

```spl
index=* (EventCode=1102 OR EventCode=104)
| table _time, host, user, source
```

# EDR / AV & Threat Detection

## 21. AV Alert Trends Over Time

```spl
index=* sourcetype=WinEventLog:System (EventCode=1116 OR EventCode=1117)
| timechart count by host
| sort -_time
```

## 22. Suspicious Command Line Executions (Generic)

```spl
index=* EventCode=4688
| regex CommandLine="(?i)(certutil.*-urlcache|bitsadmin|vssadmin.*delete|wmic.*process.*call|netsh.*interface.*portproxy)"
| table _time, host, user, CommandLine, process_name, parent_process
```

# General Security Posture

## 23. Error Rate Spike by Host (Possible Attack Indicator)

```spl
index=* sourcetype=* (level=ERROR OR level=error OR severity=high)
| timechart span=1h count by host
| streamstats avg(count) as avg_errors stdev(count) as stdev_errors by host window=24
| eval threshold = avg_errors + (3 * stdev_errors)
| where count > threshold
```

## 24. Top 10 Hosts by Security Events

```spl
index=* (tag=security OR eventtype=security)
| stats count as security_events by host
| sort -security_events
| head 10
```

## 25. MITRE ATT&CK Technique Correlation

```spl
| tstats count from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe","rundll32.exe","mshta.exe","regsvr32.exe","certutil.exe")
by Processes.host, Processes.user, Processes.process_name, Processes.process
| rename Processes.* as *
| lookup mitre_attack_technique process_name OUTPUT technique_id, tactic_name
| stats count by host, user, technique_id, tactic_name, process_name
| sort -count
```
