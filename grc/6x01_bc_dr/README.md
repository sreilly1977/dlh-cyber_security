# Introduction

> "The time to repair the roof is when the sun is shining."
>
> — John F. Kennedy

At 2:47 AM on a Tuesday in February, MedDefense's primary data center loses power. The generator starts. The UPS holds. Then the cooling system fails. By 3:15 AM, three critical servers are offline. Epic EHR is unreachable. Lab results from the overnight shift cannot be accessed. The charge nurse in the ICU is on hold with the help desk. A physician needs medication history for a patient who is deteriorating.

This is not a hypothetical. Healthcare organizations that have never tested their recovery procedures often discover that the difference between written plans and real recovery is measured in clinical risk, not only in minutes.

This project closes that gap before a real crisis opens it. You will build a Business Impact Analysis that prioritizes systems by patient safety consequence, design a backup architecture that can actually satisfy stated recovery objectives, write command-level recovery runbooks, execute a timed LIS recovery test inside the provided lab container, and convert the recovery gap into a board-ready remediation package.

The answer to disaster recovery is almost never "the plan worked exactly as written." The professional answer is: what did the plan promise, what did the test prove, what changed afterward, and what evidence supports that claim?

## Context

The HHS OCR desk audit preparation surfaced a gap more operationally dangerous than any missing policy: MedDefense has never tested its disaster recovery plan. The existing DR documentation predates the Epic EHR migration, does not account for the Laboratory Information System modernization completed last year, and references backup infrastructure that was decommissioned eighteen months ago.

James Chen escalated this to Dr. Morales immediately. Her response was direct: "I am not going to tell an auditor we have a DR plan and then have them ask when we last tested it and have no answer. Fix it."

Sarah Park pulled the existing documentation. It was 47 pages. It referenced a physical tape library in the basement that was replaced with cloud backup in 2024. The RTO for Epic EHR was listed as four hours, with no evidence that anyone had ever attempted to verify that number.

Robert Kim ran a check against the backup logs. In three cases, the declared RPO was shorter than the backup frequency. On paper, MedDefense was promising to recover data that the backup schedule mathematically could not preserve. A plan that fails arithmetic is not a plan.

Your assignment covers three things: build a defensible BIA, write a DR plan that reflects current infrastructure, and run a real recovery test against the Laboratory Information System using the provided containerized lab artifacts. The LIS was chosen as the test target because it has a clean backup chain and is critical enough to be meaningful without requiring students to manage Docker, MariaDB, or cloud infrastructure during the exercise.

The results will be presented to Dr. Morales and the Board Risk Committee next month. You are not being asked to produce documents only. You are being asked to produce evidence.

---

# 0. Quiz

---

# [1. Build the Business Impact Analysis](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/business_impact_analysis.md)

## Goal: 

Produce a signed BIA document that classifies every critical MedDefense system by patient safety consequence, regulatory obligation, revenue exposure and operational dependencies, and assigns defensible RTO, RPO and MTD values.

## Context

The gap between the old DR plan and operational reality starts here. Whoever wrote the previous BIA listed systems as "critical" or "non-critical" without explaining what made them so. Sarah Park needs a document that answers one question for every system: if this goes down at 2 AM on a Tuesday, what breaks, what is the patient safety consequence, and how long can we be down before the harm is irreversible?

## Instructions

Create business_impact_analysis.md.

Use the provided materials:

    /opt/meddefense/materials/bia/meddefense_system_inventory.csv
    /opt/meddefense/materials/bia/downtime_impact_notes.md
    /opt/meddefense/materials/bia/regulatory_reference_map.md
    /opt/meddefense/materials/backup_architecture/dependency_map_seed.md

Assess these ten MedDefense systems:

    Active Directory
    Epic EHR
    Laboratory Information System
    PACS/RIS
    Pharmacy Dispensing System
    Medical Device Integration Gateway
    Network Core
    Email and Secure Messaging
    Backup and DR Infrastructure
    Security Operations Platform

For each system, document:

    Patient Safety Impact at 1 hour, 4 hours and 24 hours
    Regulatory Impact with specific HIPAA, Joint Commission or reporting references
    Revenue Impact as an estimated exposure per hour
    Operational Dependencies and downstream failure sequence
    Maximum Tolerable Downtime
    Recovery Time Objective
    Recovery Point Objective
    Priority Tier: Tier 1, Tier 2, Tier 3 or Tier 4

Required structure:

<pre>
# MedDefense Business Impact Analysis

**Version:** 1.0
**Classification:** Confidential
**Prepared by:** [Your name]
**Date:** [Date]
**CISO approval:** _________________________ Date: _________

## Executive Summary

## Methodology

## System Impact Assessment

## Dependency Map

## RTO / RPO / MTD Summary Table

## Assumptions and Limitations
</pre>

Quality Requirements

    Every RTO must be lower than the system MTD.
    Every RPO must be stated in time.
    The LIS must be treated as a Tier 1 or Tier 2 system.
    Active Directory and Network Core must appear in the dependency map.
    Generic statements such as "operations are affected" are not sufficient.

---
