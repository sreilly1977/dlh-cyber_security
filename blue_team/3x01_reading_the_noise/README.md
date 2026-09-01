# Introduction

> "Before you can spot an intruder, you must know what normal looks like." 
>
> - James Chen, SOC Lead

Last week you built the evidence pipeline. Today you become the first person inside MedDefense who knows how to read what that pipeline produces. Forty thousand enriched events, eight days of activity, twelve hosts, six source types, one timeline. Most of it is noise. Most of the noise is normal noise — the heartbeat of a working hospital infrastructure. Somewhere inside it there are signals that matter, and nobody at MedDefense has ever taken the time to write down what normal sounds like here.

That is the work this week. You are going to take your 3x00 handoff, split it into a baseline window and an evaluation window, and build the first behavioral baselines MedDefense has ever had. Authentication patterns. Process inventories. Network destinations. File access footprints. Hourly and daily activity profiles. Each one a machine-readable reference that says, for this infrastructure, this is normal. Then you are going to hunt the evaluation window for everything that does not match those references, correlate the findings across sources, and rank them so the Tier 1 analyst who runs your toolkit on Monday morning sees the most dangerous thing first.

This project does not ask you to click buttons in a dashboard. It asks you to write the analytical scripts that the dashboard would run behind the scenes if you had one. The dataset is the one your own pipeline produced in 3x00. The tools are jq, python3, and a handful of bash. The output is a baseline_package/ directory that will be loaded as a dependency by every downstream project in this module and reused as the ground truth reference in the capstone.

## Why this matters

A Tier 1 analyst stares at a queue of alerts and has to decide, in under two minutes, whether each alert is worth waking somebody up at 3 AM. That decision is only possible if the analyst has a reference for what the same alert looks like on a quiet Tuesday. Without a baseline, every alert is equally suspicious or equally boring, and the analyst guesses. With a baseline, the analyst compares. The baseline is the analyst's intuition, externalized into a JSON file that does not care about coffee or fatigue.

The 2020 SolarWinds campaign stayed undetected for nine months inside thousands of organizations. The malicious activity was designed to blend: legitimate protocols, legitimate tools, legitimate account names, legitimate traffic volumes. The victims who eventually caught it were the ones who had written down, ahead of time, the minor behavioral fingerprints of their own environments and noticed subtle shifts no human would have spotted in a dashboard review. That is what you are building this week, at the scale of one hospital group. And everything you build feeds directly into 3x02, where the deviations you identify here become the detection rules that fire in production.

Security+ domain 4.9 expects you to understand the mitigation and risk-reduction value of monitoring and baselining; domain 4.4 expects you to know log aggregation, correlation, and monitoring. This project exercises both at the same time, against data you produced yourself.

## Context

You are currently working as a SOC Analyst for MedDefense Health Systems.
The Scenario: "What Normal Sounds Like"

---

**FROM:** James Chen, SOC Lead - MedDefense Health Systems

**TO:** SOC Analyst (You)

**SUBJECT:** First assignment now that your pipeline is live

**PRIORITY:** High

Good work on the pipeline. evidence_handoff/ is sitting on your workstation, schema-valid, enriched, timeline-indexed. I have already pulled it into my review environment.

Here is the problem nobody at MedDefense has ever solved. We have no baselines. Three sites, two thousand employees, a dozen production servers, and nobody can tell me how many failed logins are normal on a Tuesday morning, which processes are supposed to run on the patient portal, which external destinations the billing server is supposed to contact, or whether a spike of auditd events at 02:00 on Saturday is routine backup activity or a lateral movement attempt. When Dr. Morales asks whether we are safe, the honest answer is "I do not know, because I have nothing to compare today against."

Your handoff covers eight days of activity. I want you to treat the first seven as your clean baseline window and the last day as your evaluation window. Infrastructure has confirmed the first seven days contain only authorized administration and normal clinical operations. The last day contains real activity that we have not reviewed yet, and I have reason to believe something slipped through. Do not tell me what to look for. Your baselines should tell me.

Build the baselines. Build the anomaly detection. Correlate findings across sources so if something touches both the endpoint and the network on the same host in the same minute, I see it as one thing, not two. Rank the output so the worst item is at the top, not buried in a list of low-severity noise.

Last thing. The scripts you write become the MedDefense SOC reference toolkit. Whatever Tier 1 analyst picks up this keyboard on Monday should be able to run your baseline_package/ against any new evidence drop and get the same analytical quality you produced today. I expect that directory to be the most reused artifact in this department.

-- James Chen

---

# [0. Format Analysis Across All Sources](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/0-format_analysis.sh)
### advanced
## Goal: 

Profile every source type in the enriched dataset and produce a structured breakdown of fields, types, cardinality, and example values.

## Context: 

Before you can reason about what normal looks like, you have to know what you actually have. The 3x00 pipeline guarantees the schema is uniform, but per-source field populations vary wildly: src_ip is present on almost every network record and almost no process record, user is mandatory on authentication events but empty on PCAP flows. The format analysis is the first thing a Tier 1 analyst should run when a new dataset lands.

## Instructions: 

Write a script 0-format_analysis.sh (bash calling a Python helper is fine) that reads $HANDOFF_DIR/data/enriched_events.json and produces format_analysis.json. For each distinct source_type present in the data, the output must include:

    record_count

    first_event and last_event timestamps

    unique_hosts count

    field_profile: for every field observed in at least one record of this source, list presence_pct, inferred_type, cardinality, and up to three example_values

    top_event_categories with counts

The script must also print a human-readable summary to stdout listing each source and its record count, and a line counting the total number of source types discovered.

The script must default HANDOFF_DIR to ~/3x00_handoff/evidence_handoff if the variable is not set.

**Expected Output:**

```bash
$ source ~/m3_env.sh && ./0-format_analysis.sh
windows_json     <N> records   <N> hosts   <N> fields
linux_text       <N> records   <N> hosts   <N> fields
firewall         <N> records   <N> hosts   <N> fields
suricata_alert   <N> records   <N> hosts   <N> fields
pcap_flow        <N> records   <N> hosts   <N> fields
<N> source types profiled
format_analysis.json written
```

***Note: Exact counts depend on your 3x00 pipeline output.***

---

# [1. Critical Field Extraction and Indexing](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/1-field_index.sh)
### advanced

## Goal: 

Extract the critical analytical fields from every record and build a compact index keyed by field name for fast lookup.

## Context: 

During triage you do not want to scan 40,000 records every time you ask "which hosts saw a user value of svc_backup". You want an index that answers that question in milliseconds. This task builds the index once and writes it to disk so every subsequent task in the project reads from it instead of re-scanning the enriched dataset.

## Instructions: 

Write a script 1-field_index.sh that reads $HANDOFF_DIR/data/enriched_events.json and produces field_index.json containing, for each critical field in the schema, a reverse index mapping observed values to the list of event references where they appear. Critical fields must include at minimum: hostname, user, process_name, src_ip, dst_ip, event_category, source_type.

For each value in the index, include the count of occurrences and an optional capped list of up to 50 event_ref pointers. Values that occur more than 50 times should only store the count and a capped: true marker to keep the index bounded.

The script must default HANDOFF_DIR to ~/3x00_handoff/evidence_handoff if not set.

Print a summary showing total fields indexed, total unique values, and index size on disk.

**Expected Output:**

```bash
$ source ~/m3_env.sh && ./1-field_index.sh
indexing 7 critical fields over <N> records
  hostname        unique values :   <N>
  user            unique values :   <N>
  process_name    unique values :   <N>
  src_ip          unique values :   <N>
  dst_ip          unique values :   <N>
  event_category  unique values :   <N>
  source_type     unique values :   <N>
field_index.json written (<X> MB)
```

---

# [2. Reusable Query Toolkit](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/2-query_toolkit.sh)

## Goal: 

Build a reusable CLI query toolkit that filters, projects, and aggregates events from the handoff dataset without a SIEM.

## Context: 

Every baseline and anomaly task in this project will need to answer small pointed questions against the dataset. Rather than reimplement that logic in every script, you build the toolkit once. Every downstream task calls it.

## Instructions: 

Write a script 2-query_toolkit.sh that dispatches sub-commands against the enriched dataset. It must support at minimum:

    filter --source <type> --host <h> --from <iso> --to <iso> --category <c>: emits newline-delimited JSON of matching records to stdout

    top --field <name> --limit <n> [filters]: emits a two-column table of the top N values of a field, sorted desc by count

    distinct --field <name> [filters]: emits the distinct values of a field one per line

    count [filters]: emits a single integer with the record count matching the filters

    window --field <name> --bucket <hour|day> [filters]: emits a two-column table of bucket to count

    help: prints the usage

The toolkit must accept filters in any combination, must read from $HANDOFF_DIR/data/enriched_events.json, and must default HANDOFF_DIR to ~/3x00_handoff/evidence_handoff if not set.

**Expected Output:**

```bash
$ ./2-query_toolkit.sh help
query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message
```

---

# [3. Event Type Taxonomy](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/3-event_taxonomy.sh)

## Goal: 

Build the MedDefense event type taxonomy that maps every observed source-specific event into a canonical analytical label.

## Context: 

The schema gives you event_category at a coarse grain. For baselining and anomaly analysis you need finer granularity. The taxonomy is the deterministic mapping from raw source fields to canonical labels. Every downstream script in this project labels events through the taxonomy instead of interpreting source fields directly.

## Instructions: 

Write a script 3-event_taxonomy.sh that reads $HANDOFF_DIR/data/enriched_events.json and produces event_taxonomy.json. The taxonomy must contain, for each canonical label, the list of rules that identify it. A rule is a record {source_type, match: {field: value, ...}, label}.

At minimum the taxonomy must cover:

    login_success, login_failure, logout, account_lockout, privilege_escalation

    process_start, process_stop, child_process_spawn

    file_read_sensitive, file_write_sensitive, file_permission_change

    network_connection_outbound, network_connection_inbound, network_alert, network_blocked

The script must also write the labeled dataset to labeled_events.json (newline-delimited JSON) with a new canonical_label field. Records whose label cannot be determined are assigned unlabeled.

The script must default HANDOFF_DIR to ~/3x00_handoff/evidence_handoff if not set.

**Expected Output:**

```bash
$ source ~/m3_env.sh && ./3-event_taxonomy.sh
taxonomy rules         : <N>
records labeled        : <N>
records unlabeled      : <N>
canonical label distribution (top 10):
  process_start              <N>
  login_success              <N>
  ...
event_taxonomy.json written
labeled_events.json written
```

---

# [4. Authentication Baseline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/4-baseline_auth.sh)

## Goal: 

Compute the authentication baseline over the clean window: per-host, per-user, per-time-of-day success and failure patterns.

## Context: 

Authentication is the most frequently queried log category in a SOC. The baseline must answer: who logs in where, when do they log in, what is the normal success-to-failure ratio, what is the largest failure burst from a single source that is considered normal. Every number in this baseline will be compared against day 8 by the anomaly script in T10.

## Instructions: 

Write a script 4-baseline_auth.sh that reads labeled_events.json, restricts to the baseline window (first seven days by default, overridable by $BASELINE_DAYS), and produces baseline_auth.json containing:

    window: the baseline window start and end timestamps

    per_host: for each host, the counts of login_success, login_failure, logout, account_lockout, privilege_escalation

    per_user: list of accounts observed with per-account success and failure counts

    known_accounts: the deduplicated list of usernames that appear at least once

    business_hours_avg: average successes and failures per hour during 06:00 to 17:59

    offhours_avg: average successes and failures per hour during 18:00 to 05:59

    max_failures_1h_window: the maximum number of failures observed in any 1-hour window from a single src_ip during the baseline

**Expected Output:**

```bash
$ ./4-baseline_auth.sh
baseline window : <start> -> <end>
hosts           : <N>
known accounts  : <N>
business hours  : <N> success/h  |  <N> failure/h
off hours       : <N> success/h  |  <N> failure/h
max 1h src_ip failures : <N>
baseline_auth.json written
```

---

# [5. Process Execution Baseline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/5-baseline_process.sh)

## Goal: 

Compute the per-host process execution baseline: which processes are expected on which host and with what frequency.

## Context: 

A process that has never been seen on a host is an investigation trigger in almost every SOC playbook. The baseline is the authoritative list of "expected" processes per host. The key distinction is per host, not global: python3 may be normal on a data analyst workstation and deeply abnormal on a clinical imaging server. A global baseline erases that distinction and produces useless noise.

## Instructions: 

Write a script 5-baseline_process.sh that reads labeled_events.json, restricts to the baseline window, and produces baseline_process.json containing:

    per_host: for each host, the list of expected process names with execution count, first and last seen timestamps, and distinct executing users

    global_top: the 50 most executed processes across the whole baseline

    rare_processes: processes that appear on only one host or run fewer than five times total during the baseline

    parent_child_pairs: for process start events with parent-child information, the set of observed parent -> child pairs per host

**Expected Output:**

```bash
$ ./5-baseline_process.sh
baseline window : <start> -> <end>
processes indexed by host: <N> hosts
global top process    : <name> (<N> executions)
rare processes        : <N>
parent->child pairs   : <N>
baseline_process.json written
```

---

# [6. Network Connection Baseline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/6-baseline_network.sh)
### advanced

## Goal: 

Compute the network baseline: expected destinations, ports, and services per host, and expected cross-zone flows.

## Context: 
The network baseline captures who normally talks to whom, on which port, and across which network zone boundaries. The asset inventory and network zone enrichment from 3x00 make it possible to reason about flows at the zone level, not just at the IP level, which matters for healthcare segmentation compliance. A clinical workstation normally talks to the EHR server on 443 and to the internal DNS on 53 and to nothing else. A flow to an unknown external IP on port 8443 is immediately suspicious even if the destination is not on a threat feed.

## Instructions: 

Write a script 6-baseline_network.sh that reads labeled_events.json, restricts to the baseline window, and produces baseline_network.json containing:

    per_host_destinations: for each host, the set of distinct dst_ip contacted with counts

    per_host_ports: for each host, the set of distinct dst_port used with counts

    zone_flows: counts of flows keyed by (src_zone, dst_zone) tuples derived from the enrichment

    known_external_ips: the list of dst_ip values falling into an external zone with counts

    service_profiles: the mapping of dst_port to the set of hosts that normally use it

**Expected Output:**

```bash
$ ./6-baseline_network.sh
baseline window   : <start> -> <end>
hosts with network activity : <N>
distinct dst_ip           : <N>
distinct dst_port         : <N>
zone flows recorded       : <N>
known external IPs        : <N>
baseline_network.json written
```

---

# [7. File Access Baseline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/7-baseline_file.sh)
### advanced

## Goal: 

Compute the baseline for file access events against sensitive directories on every host.

## Context: 

Sensitive directories are the ones where a single unexpected read or write is a signal. /etc/shadow, /etc/sudoers.d/, /var/log/audit/, C:\Windows\System32\config\, and the MedDefense application config directories are touched by a small, predictable set of processes and users during normal operation. The baseline captures that footprint so any access from outside the footprint becomes visible later.

## Instructions: 

Write a script 7-baseline_file.sh that reads labeled_events.json, restricts to events with canonical labels file_read_sensitive, file_write_sensitive, or file_permission_change, and produces baseline_file.json containing:

    sensitive_paths: the distinct set of sensitive file paths observed during the baseline

    per_path_access: for each path, the list of distinct accessing processes and users with counts

    per_host_paths: for each host, the set of sensitive paths touched during the baseline

    rare_accesses: paths touched fewer than three times during the whole baseline

The list of sensitive path prefixes must be declared at the top of the script as a configurable array: /etc/shadow, /etc/sudoers, /etc/ssh/, /var/log/audit/, C:\\Windows\\System32\\config\\, and MedDefense application paths.

**Expected Output:**

```bash
$ ./7-baseline_file.sh
baseline window   : <start> -> <end>
sensitive paths   : <N>
total accesses    : <N>
per host coverage : <N> hosts
rare accesses     : <N>
baseline_file.json written
```

---

# [8. Temporal Pattern Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/8-temporal_profile.sh)
### advanced

## Goal: 

Produce hourly and daily activity profiles per source type to capture when things normally happen.

## Context: 

MedDefense is a hospital. Clinical staff log in at 06:00, administrative staff arrive at 08:00, backup jobs run at 02:00, nobody deploys code at midnight. A burst of auditd execve events at 03:00 on Saturday is either the weekly backup window or something that should have never happened. The temporal profile encodes those rhythms as numbers. T10, T11, and T12 will compare the evaluation window against this profile to flag time-shape anomalies.

## Instructions: 

Write a script 8-temporal_profile.sh that reads labeled_events.json, restricts to the baseline window, and produces temporal_profile.json containing for each source_type and each canonical_label:

    hour_of_day_histogram: 24 buckets with mean count per hour of day over the baseline

    day_of_week_histogram: 7 buckets with mean count per day of week

    peak_hour and quiet_hour

    business_offhours_ratio: the ratio of business-hours events to off-hours events

The script must also emit a simple ASCII histogram for the top three most active canonical labels for human inspection.

**Expected Output:**

```bash
$ ./8-temporal_profile.sh
source_type         labels profiled
  windows_json           <N>
  linux_text             <N>
  firewall               <N>
  suricata_alert         <N>
  pcap_flow              <N>
top 3 labels temporal shape (per hour, baseline avg):
  process_start  ...
  login_success  ...
temporal_profile.json written
```

---

# [9. Cross-Source Baseline Summary](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/9-baseline_summary.sh)

## Goal: 

Combine all baselines into a single machine-readable baseline summary consumed by the anomaly detection block.

## Context: 

Each previous task produced one slice of the baseline. The anomaly scripts in the next block should not have to open four separate files and cross-reference them. The summary is the single input contract: one file that contains everything an anomaly detector needs, with clear section boundaries and a version number. It is also the artifact Tier 1 analysts will load on Monday morning.

## Instructions: 

Write a script 9-baseline_summary.sh that reads baseline_auth.json, baseline_process.json, baseline_network.json, baseline_file.json, and temporal_profile.json, and produces baseline_summary.json containing:

    version

    generated_at (ISO 8601 UTC)

    baseline_window (start, end, duration in days)

    evaluation_window (start, end, duration in hours)

    host_inventory: the set of hosts present in the baseline

    auth, process, network, file, temporal: the respective sub-documents from the prior tasks, nested

    thresholds: a derived object containing the numeric thresholds anomaly scripts will apply (for example, failure_rate_multiplier: 3, unknown_process_penalty: 5, unknown_port_penalty: 4). Each threshold must include a short comment explaining how it was derived

**Expected Output:**

```bash
$ ./9-baseline_summary.sh
version           : 1.0
baseline window   : <start> -> <end>  (<N> days)
evaluation window : <start> -> <end>  (24h)
hosts             : <N>
sections included : auth, process, network, file, temporal, thresholds
baseline_summary.json written
```

---

# [10. Authentication Anomalies](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/10-anomalies_auth.sh)

## Goal: 

Scan the evaluation window for authentication anomalies using thresholds derived from the baseline summary.

## Context: 

This is where the baseline pays off. Every deviation you flag is a potential signal that has to be credible enough to justify an analyst's time. The script must detect the categories that matter most in practice: accounts that do not exist in the baseline, failure bursts that exceed baseline expectations, logins at unusual hours, and privilege escalations that did not appear during the baseline.

## Instructions: 

Write a script 10-anomalies_auth.sh that reads baseline_summary.json and labeled_events.json, restricts to the evaluation window, and writes anomalies_auth.json containing one entry per anomaly with at minimum these fields: timestamp, host, user, src_ip, anomaly_type, baseline_value, observed_value, severity, event_refs.

The script must detect at minimum:

    unknown_account: a user value not present in the baseline known_accounts

    failure_rate_burst: any 1-hour window where the failure rate from a single src_ip exceeds the baseline max_failures_1h_window multiplied by the failure_rate_multiplier threshold

    offhours_login: a login_success event outside business hours for a user that has only ever logged in during business hours in the baseline

    privilege_escalation_surge: more than N privilege_escalation events on a host where the baseline has zero such events

**Expected Output:**

```bash
$ ./10-anomalies_auth.sh
evaluation window  : <start> -> <end>
unknown_account           : <N>
failure_rate_burst        : <N>
offhours_login            : <N>
privilege_escalation_surge: <N>
total anomalies           : <N>
anomalies_auth.json written
```

---

# [11. Process Anomalies](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/11-anomalies_process.sh)

## Goal: 

Scan the evaluation window for process execution anomalies relative to the per-host process baseline.

## Context: 

Process anomalies are the highest signal-to-noise category when the baseline is computed per host. A process that has never run on a specific host during the baseline and shows up on day 8 is, at minimum, a note in the analyst's notebook. If it is a process with a reputation for misuse (scripting interpreters, network tools, archivers), it is already a medium-severity item.

## Instructions: 

Write a script 11-anomalies_process.sh that reads baseline_summary.json and labeled_events.json, restricts to the evaluation window, and writes anomalies_process.json containing one entry per anomaly with timestamp, host, user, process_name, parent_process_name, anomaly_type, severity, event_refs.

The script must detect at minimum:

    unknown_process_for_host: a process name that never appeared on that host in the baseline

    unknown_parent_child: a parent-child pair that never appeared on that host in the baseline

    rare_process_spike: a process that ran fewer than five times in the whole baseline but runs more than ten times in the evaluation window on a single host

    high_risk_process: hits on a watchlist of interpreters and tooling (powershell.exe, cmd.exe, wscript.exe, mshta.exe, nc, nmap, wget, curl, python3, bash) running on a host where they did not run during the baseline

Severity is assigned from a rubric declared at the top of the script.

**Expected Output:**

```bash
$ ./11-anomalies_process.sh
evaluation window : <start> -> <end>
unknown_process_for_host : <N>
unknown_parent_child     : <N>
rare_process_spike       : <N>
high_risk_process        : <N>
total anomalies          : <N>
anomalies_process.json written
```

---

# [12. Network Anomalies](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/12-anomalies_network.sh)
### advanced

## Goal: 

Scan the evaluation window for network anomalies relative to the per-host network baseline.

## Context: 

Network anomalies catch lateral movement, data exfiltration, and command and control before the endpoint side has a chance to generate high-fidelity telemetry. The baseline tells you what each host normally contacts and how. Anything outside that set is either a new service, a misconfiguration, or the thing you need to find.

## Instructions: 

Write a script 12-anomalies_network.sh that reads baseline_summary.json and labeled_events.json, restricts to the evaluation window, and writes anomalies_network.json containing one entry per anomaly with timestamp, host, src_ip, dst_ip, dst_port, src_zone, dst_zone, anomaly_type, severity, event_refs.

The script must detect at minimum:

    unknown_destination_for_host: a dst_ip that this host never contacted during the baseline

    unknown_port_for_host: a dst_port this host never used during the baseline

    unexpected_zone_flow: a (src_zone, dst_zone) pair that never occurred in the baseline

    volume_burst: a 1-hour window where the host's outbound connection count exceeds the baseline mean multiplied by the threshold

    external_destination_new: a dst_ip in an external zone that never appeared in known_external_ips

**Expected Output:**

```bash
$ ./12-anomalies_network.sh
evaluation window : <start> -> <end>
unknown_destination_for_host : <N>
unknown_port_for_host        : <N>
unexpected_zone_flow         : <N>
volume_burst                 : <N>
external_destination_new     : <N>
total anomalies              : <N>
anomalies_network.json written
```

---

# [13. Cross-Source Correlation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/13-correlate_anomalies.sh)

## Goal: 

Correlate anomalies from multiple sources that share a host and a time window to produce higher confidence findings.

## Context: 

A single unknown process on a clinical workstation might be a developer running a one-off script. The same unknown process happening one minute before an unknown_destination_for_host anomaly on the same host is a very different story. Correlation is what turns three low-value single-source items into one high-value multi-source finding. Triage in 3x03 will consume the output of this task directly.

## Instructions: 

Write a script 13-correlate_anomalies.sh that reads anomalies_auth.json, anomalies_process.json, and anomalies_network.json, and writes correlated_anomalies.json. A correlated finding groups any two or more single-source anomalies that share the same host and whose timestamps fall within a configurable correlation window (default: 300 seconds).

Each correlated finding must contain:

    correlation_id (a short deterministic identifier)

    host

    window_start and window_end

    sources_involved (the set of source categories: auth, process, network)

    anomaly_types (the set of anomaly types from the involved items)

    member_refs (list of references back to the individual anomaly entries)

    score (an integer composite score: 1 per involved source, plus a bonus for each distinct anomaly type, plus an asset criticality multiplier)

**Expected Output:**

```bash
$ ./13-correlate_anomalies.sh
single-source anomalies  : <N>
correlated findings      : <N>
multi-host findings      : <N>
max score                : <N>
correlated_anomalies.json written
```

---

# [14. Anomaly Priority Ranking](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x01_reading_the_noise/14-rank_anomalies.sh)
### advanced

## Goal: 

Rank every anomaly (single-source and correlated) by a composite priority score suitable for an analyst queue.

## Context: 

Anomaly output without ranking is useless in a real SOC. If you give a Tier 1 analyst a flat list of 40 items, they work the first few and run out of shift. You need to guarantee the highest-risk item is at the top so the first ten minutes of the shift focus on the right thing. The score must be explainable so senior analysts can audit why item number one is at the top.

## Instructions: 

Write a script 14-rank_anomalies.sh that reads anomalies_auth.json, anomalies_process.json, anomalies_network.json, and correlated_anomalies.json, and writes ranked_anomalies.json containing every item sorted descending by priority_score.

The priority score must be a deterministic integer computed from:

    Base severity value (low=1, medium=3, high=5, critical=8)

    Asset criticality multiplier (low=1, medium=2, high=3, critical=4)

    Cross-source correlation bonus (+2 per additional source beyond the first)

    Off-hours bonus (+1 if the anomaly occurred outside business hours)

    Known high-risk category bonus (+2 for high_risk_process, privilege_escalation_surge, or external_destination_new)

The output must include for every ranked entry the full anomaly record plus a score_breakdown sub-object.

Print the top five items as a short table for human inspection.

**Expected Output:**

```bash
$ ./14-rank_anomalies.sh
ranked anomalies total : <N>
top 5:
 1  score <N>  <host>  <anomaly_type>
 ...
ranked_anomalies.json written
```

---
