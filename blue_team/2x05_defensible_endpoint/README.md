# Introduction

>"The job is not finished when the system is hardened. The job is finished when somebody else can take the hardened system, verify it in one command and use it the same night without calling you." 
>
> — Engineering handoff principle, adapted

For five weeks you built skills on five separate projects. You hardened a Linux server. You hardened a Windows host. You instrumented endpoints with Sysmon, auditd and Script Block Logging. You engineered a patch pipeline. You designed a segmented network with nftables, custom Suricata rules and DNS filtering. Every project produced scripts, configs and structured artifacts on its own island.

This capstone is the project where the islands become a continent.

MedDefense is onboarding a new satellite clinic, Hawthorne Medical Center, a 40-bed community hospital 35 miles north of the main campus. Its IT cabinet contains one Linux application server, one Windows administrative endpoint, a flat switch fabric and zero existing security controls. The cutover is in three weeks. James Chen is handing you the environment and the deadline at the same time. Your job is not to write a plan. Your job is to hand back a defensible endpoint package: the same environment, hardened, instrumented, patched, segmented, validated and documented as structured data, in a form that another engineer can pick up, verify in one command and run in production the same night.

This is not a report. It is not an essay. It is not a design document. Every deliverable is a script, a config file, a structured JSON artifact or a signed handoff bundle. A reviewer armed with ls, jq, grep and the scripts themselves must be able to reach the same pass-fail verdict as you did, line by line, without asking you a single question.

## Why this matters

Real security engineering ends with a handoff. The engineer who hardens a system and then walks away has delivered half the job. The engineer who hardens the system, captures the delta as code, validates it against measurable criteria and packages the result so that operations can own it without further translation has delivered the whole job. Hospitals, banks, regulated environments, auditors: everybody needs the whole job. This capstone is the rehearsal. The evaluation grille at the end of this project is intentionally binary and countable, not because subjective judgment has no value, but because the professional standard you are training for is one where the evidence speaks before you do.

## Context

Week ten at MedDefense Health Systems. Monday morning.

James Chen drops a plastic bag on your desk. Inside it: a printed asset label, a USB stick and a single-page handover sheet.

"Hawthorne Medical Center. Forty beds, one satellite data closet, one Linux app server running the clinical intake application, one Windows host they use for administrative scheduling. They are joining MedDefense in three weeks and their current security posture is whatever Dell shipped in the box. Nothing more. Your job is to turn that box into a system we can put on our network without regretting it."

He hands you the handover sheet:

<pre>
HAWTHORNE MEDICAL CENTER — ENDPOINT HANDOFF
====================================================
Site:              Hawthorne, 35 mi north of HQ
Cutover date:      three weeks from today
Data sensitivity:  HIPAA PHI (clinical intake forms)

Endpoints:
  - hawthorne-app-01    Ubuntu 22.04, fresh install, unmanaged
  - hawthorne-adm-01    Windows 11 Pro, domain-joinable, unmanaged

Network:
  - Flat /24, no segmentation, no firewall on either host
  - Single switch, uplink to a FortiGate we do not control

Controls in place:
  - None
</pre>

Dr. Morales stops by mid-sentence.

"I do not want a PowerPoint next Monday. I want to walk into your office and run one command on the Linux host and another on the Windows host, get a green pass-fail from both and know the environment is ready. If I cannot do that without a phone call, the deliverable is not finished."

Sarah Park adds the continuity constraint.

"And whatever evidence you package at the end has to be readable by the Module 3 analysts we are training right now. Same field names, same layout, same manifest as the exports from 2x02 and 2x04. If they have to reverse-engineer your schema, we lost the point of standardizing it."

Mike Torres is already at the rack in the satellite closet taking pictures.

"Flat switch. One uplink. I will hand you the cable map and the VLAN plan by Tuesday. Everything else is yours."

---

