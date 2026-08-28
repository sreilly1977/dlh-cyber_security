# Introduction

>"Before you can find the needle, you have to build the haystack you can actually search." 
>
> - SOC engineering proverb

The SOC runs on data. Not dashboards. Not alerts. Not war rooms. Data. Every detection rule, every hunt query, every triage decision, every incident timeline is built on top of a pile of raw events that somebody, at some point, had to collect, parse, normalize, clean, and enrich before any of it could be useful. That somebody is you this week.

MedDefense is in the middle of a platform migration. For the next 48 hours the centralized SIEM is offline. Telemetry is still being produced by every endpoint, every firewall, every network sensor, but there is no platform to catch it. Exports are being dropped into a shared directory in whatever format the source system happens to produce: EVTX files from Windows, plain syslog from Linux, JSON blobs from Suricata, CSV exports from the firewall. Raw, inconsistent, duplicated, incomplete, and arriving faster than anyone can read.

Your mission is to build the pipeline that turns this flood of raw exports into analyst-ready evidence. You will inventory sources, parse six different formats into structured JSON, design the unified schema that every downstream project in this module will consume, normalize, validate, clean the dirty data that real-world logging always produces, enrich events with asset and network context, index everything into a chronological timeline, and wrap the whole thing into a reproducible pipeline script that a new analyst can run with a single command.

This project is the foundation of Module 3. Every line of data that 3x01 analyzes, every detection rule that 3x02 runs, every alert that 3x03 triages, every SIEM query that 3x04 executes, is data you shaped here. Get this wrong and everything downstream breaks. Get it right and the rest of the module becomes a series of focused exercises instead of an ongoing fight with malformed data.

## Why this matters

The glamorous part of the SOC is the investigation. The invisible part is the pipeline behind it. Real incident postmortems almost always include a sentence like "the data was there but we could not correlate it" or "the timestamps did not line up across sources" or "the field we needed was dropped during normalization." These are not analyst failures. They are pipeline failures. The reason senior detection engineers and SOC architects are paid more than junior analysts is that they understand how data moves from source to search, and they know that every detection rule is only as good as the record it runs against.

This project teaches you to think like a data engineer with a security brain. You will not deploy a SIEM. You will do the work that a SIEM does under the hood, by hand, in scripts you wrote yourself. When you later query a production Wazuh or Splunk or Sentinel instance and something does not behave the way you expect, you will know exactly which stage of the pipeline is lying to you, and you will know how to fix it.

## Context

You are currently working as a SOC Analyst for MedDefense Health Systems.

### The Scenario: "48 Hours Without a Platform"

**FROM:** James Chen, SOC Lead - MedDefense Health Systems

**TO:** SOC Analyst (You)

**SUBJECT:** SIEM migration window. We need a bridge.

**PRIORITY:** High

Good morning, and welcome to Module 3. You finished your Module 2 work on Friday. Your hardened endpoints are running. Your student_telemetry/ package has been staged inside the primary evidence pack on your workstation. Normally you would hand that directory to our SIEM and the ingestion layer would do the rest.

We do not have that luxury this week.

Infrastructure is migrating our Wazuh stack to a new dedicated cluster. The migration window is 48 hours starting now. During that window, the SOC has no centralized platform. Endpoints are still producing telemetry. Sarah Park negotiated a shared directory where every source system is dropping raw exports every 15 minutes. Right now it contains multiple different formats from five different sources, nobody has touched it, and I have a pile of investigation requests that cannot wait until Wednesday.

I need you to build an evidence pipeline. Start from the raw exports. Parse them. Normalize them into a single schema you design yourself. Clean the dirty records that always come with real logs. Enrich every event with asset context so I can tell at a glance whether a given alert hit a critical system or a test box. Index the whole thing into a timeline my Tier 1 team can actually read. Wrap it into a pipeline script that runs end to end with one command, because by Wednesday I want to be able to rerun the whole thing against a fresh drop in under five minutes.

Your Module 2 student_telemetry/ is already staged at ~/evidence_pack_primary/student_telemetry/. Treat it as one more source on top of the baseline evidence pack Infrastructure left you. The primary evidence pack is at ~/evidence_pack_primary/ on your workstation.

One more thing. Robert Kim wants the pipeline specification, not a novel. Two pages, stages in, stages out, failure modes. If anyone on my team cannot read the spec and rebuild the pipeline from it, the spec is wrong.

Get this right. Everything we do for the next four weeks runs on what you build today.

-- James Chen

---


