# MedDefense SOC Triage Methodology

## Classification Taxonomy

- **true_positive**: the alert correctly describes security-relevant activity confirmed by the referenced event. Example: rule 001 (SSH brute force) firing on a login_failure burst whose src_ip is IOC-tagged malicious.
- **false_positive**: the rule matched legitimate activity because its conditions are over-broad. Example: rule 002 (off-hours privileged logon) firing on svc_backup executing its documented 01:00-04:00 nightly schedule on db-patient-01.
- **benign**: the alert accurately describes the event but the activity carries no risk. Example: rule 007 (unknown outbound destination) hitting a dst_ip that baseline history shows as routine Cloudflare CDN traffic.
- **escalated**: a true_positive meeting any escalation criterion below, promoted to a Tier 2 incident record. Example: rule 012 (medical segment egress) on an MRI host communicating with a C2-tagged external IP.

## Priority Ordering Rule

Work alerts in descending priority_score; break ties by rule_level, then asset criticality (CRITICAL first), then alert_id. Overrides: alerts sharing entities (rule_src_ip, hostname, correlated event_refs) are worked as one unit at the highest member's priority; an unattributed-host alert outranks equal-score attributed alerts until its event's hostname is resolved.

## Evidence Requirement

Every ticket cites at least one event_ref resolving to a record_id in enriched_events.json. The analyst inspects timestamp, hostname, user, src_ip, dst_ip, process_name, canonical_label, event_category, plus event_data detail fields (LogonType, FailureReason) for authentication events and dst_port, bytes_out for network events. Any classification other than benign must name the driving field and value in the justification. Where an external IP appears, ioc_context.json reputation informs and is recorded in ioc_hits.

## Escalation Criteria

Escalate to Tier 2 when any predicate holds:

- Any referenced IOC has reputation == "malicious"
- The TP affects an asset with data_classification PHI or PCI, or criticality == "CRITICAL"
- Activity implies outbound data movement violating an inter_zone_rules BLOCK
- Same actor or src_ip is implicated across three or more hosts
- A login_success follows failures from the same src_ip (credential compromise)
- The TP involves authentication as admin, administrator, or temp_user_* accounts

## SLA

- critical: 15 minutes
- high: 30 minutes
- medium: 60 minutes
- low: same business day
- score-0 batch: reviewed before shift end

## Documentation Standard

Per ticket, verbatim from the locked schema:

- ticket_id (deterministic from alert_id)
- alert_id
- classification (true_positive | false_positive | benign | escalated)
- justification naming field and value
- evidence_refs (list of event_ref)
- ioc_hits
- attack_techniques
- recommended_action (close | escalate_tier2 | monitor | tune_rule)
- analyst_time_seconds
- created_at (ISO 8601 UTC)
