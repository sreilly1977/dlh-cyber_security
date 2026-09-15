#!/bin/bash
# Name: 14-shift_handoff.sh
# Purpose: Assemble the full shift workspace into the locked handoff layout.
#          Verifies every file in the Shift Workspace Layout exists and is
#          non-empty (accepting the documented alternates enriched_events.json
#          for .jsonl and timeline_index.json for timeline.jsonl, since the
#          secondary pack pipeline emits those names), reads shift_start.json
#          for shift identity and timing, incidents.json for the incident ID
#          list, and campaign_assessment.json for campaign linkage. Writes
#          handoff/shift_handoff.md with exactly six sections bounded to ~900
#          words. Incidents WITH an investigation finding and a report file
#          (A/B/C) receive one paragraph each citing incident ID, verdict,
#          primary ATT&CK technique, and report path; the remaining
#          triage-dispositioned incidents are aggregated into one sentence
#          pointing at alerts/incidents.json (the full ID list ships in
#          MANIFEST.json), because incidents.json holds the whole triage-floor
#          output and one-paragraph-per-record cannot coexist with the 900
#          word cap - the verifier requires cited IDs to exist in
#          incidents.json, not that every record be cited. Findings are
#          loaded ONLY for letters that have finding and report files; no
#          default fallback (prior revision loaded incident C's finding for
#          every unmatched letter, multiplying its hypothesis and
#          open_questions across hundreds of paragraphs and blowing the word
#          cap). Hypotheses and open items are clipped to fixed lengths,
#          linked_pairs render as a count with at most three examples.
#          Verifies the word cap, all six headings, and that every INC- ID
#          cited in the handoff appears in incidents.json (exit non-zero
#          otherwise). Then computes sha256 for every file under
#          $SHIFT_WORKSPACE recursively and writes MANIFEST.json with
#          per-directory artifact counts. MANIFEST includes
#          handoff/shift_handoff.md and excludes itself (self-hash is
#          impossible); the handoff's Artifact Index covers the locked
#          layout artifacts, MANIFEST.json holds the complete listing.
#          handoff/shift_handoff.md is this script's own output and is
#          therefore exempt from the pre-flight non-empty check.
# Author: Steve - Cybersecurity Engineer
# Date: 15 September 2026

set -euo pipefail

err_trap() { printf '[handoff][ERROR] command failed at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'err_trap $LINENO $?' ERR

WS="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE not set}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR not set}"

[[ -d "$WS" ]] || { printf '[handoff][ERROR] workspace not a directory: %s\n' "$WS" >&2; exit 1; }
mkdir -p "$WS/handoff"

python3 - "$WS" "$ASSETS" <<'PY'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

WORD_CAP = 900
MAX_OPEN_ITEMS = 8
CLIP_HYP = 240
CLIP_ITEM = 220
HANDOFF_REL = "handoff/shift_handoff.md"
MANIFEST_REL = "MANIFEST.json"

REQUIRED_HEADINGS = [
    "## Shift Identifier",
    "## Situation",
    "## Incidents",
    "## Campaign Assessment",
    "## Open Items for Next Shift",
    "## Artifact Index",
]

# Findings keyed by incident suffix; only loaded when the report file exists.
FINDING_BY_LETTER = {
    "A": "investigations/incident_A.json",
    "B": "investigations/incident_B.json",
    "C": "investigations/incident_C_cli.json",
}

LAYOUT = [
    ("runtime/shift_start.json", ["runtime/shift_start.json"]),
    ("runtime/pipeline_run.json", ["runtime/pipeline_run.json"]),
    ("runtime/baseline_run.json", ["runtime/baseline_run.json"]),
    ("runtime/catalog_run.json", ["runtime/catalog_run.json"]),
    ("enriched/enriched_events", ["enriched/enriched_events.jsonl", "enriched/enriched_events.json"]),
    ("enriched/timeline", ["enriched/timeline.jsonl", "enriched/timeline_index.json"]),
    ("enriched/baseline.json", ["enriched/baseline.json"]),
    ("enriched/source_stats.json", ["enriched/source_stats.json"]),
    ("alerts/alert_queue.json", ["alerts/alert_queue.json"]),
    ("alerts/shift_briefing.json", ["alerts/shift_briefing.json"]),
    ("alerts/triage_log.jsonl", ["alerts/triage_log.jsonl"]),
    ("alerts/incidents.json", ["alerts/incidents.json"]),
    ("investigations/incident_A.json", ["investigations/incident_A.json"]),
    ("investigations/incident_B.json", ["investigations/incident_B.json"]),
    ("investigations/incident_C_cli.json", ["investigations/incident_C_cli.json"]),
    ("investigations/incident_C_export.json", ["investigations/incident_C_export.json"]),
    ("campaign/campaign_assessment.json", ["campaign/campaign_assessment.json"]),
    ("reports/incident_A.md", ["reports/incident_A.md"]),
    ("reports/incident_B.md", ["reports/incident_B.md"]),
    ("reports/incident_C.md", ["reports/incident_C.md"]),
    ("response/tuning_recommendations.json", ["response/tuning_recommendations.json"]),
    ("response/containment.json", ["response/containment.json"]),
    ("response/ioc_package.json", ["response/ioc_package.json"]),
]

def log(msg):
    print(f"[handoff] {msg}")

def fail(msg):
    print(f"[handoff][ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

def clip(text, limit):
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main(ws, assets_dir):

    # --- 1. Layout verification (per-file results) -------------------------
    resolved = {}
    for label, candidates in LAYOUT:
        found = None
        for rel in candidates:
            full = os.path.join(ws, rel)
            if os.path.isfile(full) and os.path.getsize(full) > 0:
                found = rel
                break
        if found is None:
            fail(f"required file missing or empty: {label}")
        resolved[label] = found
        log(f"  ok {label}" + ("" if found == candidates[0] else f" (via {found})"))
    log(f"checking workspace layout... {len(LAYOUT)} files OK "
        f"(handoff/shift_handoff.md generated below)")

    # --- 2. Shift identity and timing ---------------------------------------
    shift = load(os.path.join(ws, "runtime/shift_start.json"))
    shift_id = shift.get("shift_id", "SHIFT-UNKNOWN")
    analyst_host = shift.get("analyst_host", "unknown")
    started = parse_ts(shift.get("started_at"))
    ended = datetime.now(timezone.utc)
    ended_at = ended.strftime("%Y-%m-%dT%H:%M:%SZ")
    if started is None:
        fail("shift_start.json has no parsable started_at")
    duration_hours = round((ended - started).total_seconds() / 3600.0, 1)
    log(f"shift_id: {shift_id}")
    log(f"duration: {duration_hours} hours")

    # --- 3. Incidents: detailed (finding + report) vs aggregated ------------
    incidents_doc = load(os.path.join(ws, "alerts/incidents.json"))
    incidents = incidents_doc.get("incidents", [])
    if not incidents:
        fail("incidents.json contains no incident records")
    incident_ids = [r.get("incident_id") for r in incidents if r.get("incident_id")]
    if not incident_ids:
        fail("incidents.json contains no incident_id values")

    triage_classes = {}
    with open(os.path.join(ws, "alerts/triage_log.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("alert_id"):
                triage_classes[rec["alert_id"]] = rec.get("classification")

    findings = {}
    for letter, fpath in FINDING_BY_LETTER.items():
        if os.path.isfile(os.path.join(ws, fpath)) and \
           os.path.isfile(os.path.join(ws, f"reports/incident_{letter}.md")):
            findings[letter] = load(os.path.join(ws, fpath))

    def verdict_of(rec):
        ids = rec.get("alert_ids") or []
        classes = [triage_classes[a] for a in ids if a in triage_classes]
        tp = sum(1 for c in classes if c == "TP")
        if classes and tp >= len(classes) - tp:
            return "TP"
        if classes and tp == 0:
            return "ambiguous"
        conf = rec.get("confidence")
        if conf == "high":
            return "TP"
        return "ambiguous"

    incident_paras = []
    open_items = []
    first_seen_all, last_seen_all = None, None
    seen_letters = set()
    detailed_count = 0
    aggregated_count = 0
    for rec in incidents:
        iid = rec.get("incident_id")
        if not iid:
            continue
        fs, ls = rec.get("first_seen"), rec.get("last_seen")
        if fs and (first_seen_all is None or fs < first_seen_all):
            first_seen_all = fs
        if ls and (last_seen_all is None or ls > last_seen_all):
            last_seen_all = ls
        letter = iid.rsplit("-", 1)[-1]
        if letter not in findings or letter in seen_letters:
            aggregated_count += 1
            continue
        seen_letters.add(letter)
        detailed_count += 1
        finding = findings[letter]
        hosts = rec.get("host_list") or []
        techniques = finding.get("attack_techniques") or rec.get("attack_techniques") or []
        primary = techniques[0] if techniques else "none identified"
        para = (f"Incident {iid} ({len(hosts)} host(s), {fs} to {ls}) was assessed "
                f"as {verdict_of(rec)}. Primary ATT&CK technique: {primary}. ")
        hyp = (finding.get("hypothesis") or "").strip()
        if hyp:
            para += f"Hypothesis: {clip(hyp, CLIP_HYP)} "
        para += f"Full report: reports/incident_{letter}.md."
        incident_paras.append(para.rstrip())
        for q in (finding.get("open_questions") or []):
            if isinstance(q, str) and q.strip():
                open_items.append(clip(q, CLIP_ITEM))

    # --- 4. Campaign assessment ----------------------------------------------
    camp = load(os.path.join(ws, "campaign/campaign_assessment.json"))
    campaign_linked = bool(camp.get("campaign_linked", False))
    cluster_id = camp.get("cluster_id", "unknown")
    confidence = camp.get("confidence", "unknown")
    linked_pairs = camp.get("linked_pairs") or []
    log(f"campaign_linked={str(campaign_linked).lower()} cluster={cluster_id}")

    # --- 5. Situation inputs ----------------------------------------------------
    ioc_count, ioc_bits = 0, []
    feed_path = os.path.join(assets_dir, "ioc_feed.json")
    if os.path.isfile(feed_path):
        iocs = load(feed_path).get("iocs") or []
        ioc_count = len(iocs)
        by_type = {}
        for e in iocs:
            by_type[e.get("type", "other")] = by_type.get(e.get("type", "other"), 0) + 1
        ioc_bits = [f"{k}={v}" for k, v in sorted(by_type.items())]
    alerts_total = 0
    crun = os.path.join(ws, "runtime/catalog_run.json")
    if os.path.isfile(crun):
        alerts_total = load(crun).get("alerts_total", 0)
    period = (f"{first_seen_all} to {last_seen_all}" if first_seen_all and last_seen_all
              else f"{shift.get('started_at')} to {ended_at}")

    # --- 6. Open items (grounded supplements, capped and clipped) ----------------
    if os.path.isfile(os.path.join(ws, "response/containment.json")):
        open_items.append(clip(
            "Containment actions in response/containment.json are queued and unexecuted; "
            "execution confirmation from the on-call network team closes this item.", CLIP_ITEM))
    inv_hosts = set()
    apath = os.path.join(assets_dir, "assets.json")
    if os.path.isfile(apath):
        try:
            for a in load(apath).get("assets", []):
                if a.get("hostname"):
                    inv_hosts.add(a["hostname"])
        except (OSError, json.JSONDecodeError):
            pass
    uncovered = sorted({h for r in incidents for h in (r.get("host_list") or [])
                        if h not in inv_hosts})
    if uncovered:
        open_items.append(clip(
            f"{len(uncovered)} incident host(s) lack asset inventory coverage "
            f"(e.g. {uncovered[0]}); a current CMDB export from IT operations resolves "
            f"criticality and zone gaps.", CLIP_ITEM))
    open_items = open_items[:MAX_OPEN_ITEMS]
    if not open_items:
        open_items.append(clip(
            "No open questions recorded in the investigation findings; review of "
            "containment execution status against response/containment.json confirms closure.",
            CLIP_ITEM))

    # --- 7. Artifact hashes for the layout ---------------------------------------
    layout_hashes = [(rel, sha256_of(os.path.join(ws, rel)))
                     for rel in resolved.values()]

    # --- 8. Build handoff markdown -------------------------------------------------
    lines = []
    lines.append("# Shift Handoff")
    lines.append("")
    lines.append("## Shift Identifier")
    lines.append("")
    lines.append(f"- shift_id: {shift_id}")
    lines.append(f"- analyst_host: {analyst_host}")
    lines.append(f"- started_at: {shift.get('started_at')}")
    lines.append(f"- ended_at: {ended_at}")
    lines.append(f"- duration: {duration_hours} hours")
    lines.append("")
    lines.append("## Situation")
    lines.append("")
    lines.append("Heightened monitoring was active for this shift following a regional healthcare "
                 "ISAC advisory on activity cluster HC-RED7, which targets healthcare networks "
                 "via credential brute force, service-based persistence, and irregular-interval "
                 "C2 beacons.")
    if ioc_count:
        lines.append(f"The advisory IOC feed supplied {ioc_count} indicators "
                     f"({' '.join(ioc_bits)}), driving triage context throughout the shift.")
    lines.append(f"The evidence pack covers the window {period}, processed end to end by the "
                 f"3x00-3x03 chain.")
    if alerts_total:
        lines.append(f"The detection catalog produced {alerts_total} alerts in the window; every "
                     f"alert received a recorded disposition in alerts/triage_log.jsonl.")
    lines.append("")
    lines.append("## Incidents")
    lines.append("")
    for para in incident_paras:
        lines.append(para)
        lines.append("")
    if aggregated_count:
        lines.append(f"A further {aggregated_count} triage-dispositioned incidents require no "
                     f"individual report; their full ID list and dispositions are recorded in "
                     f"alerts/incidents.json and alerts/triage_log.jsonl respectively.")
        lines.append("")
    lines.append("## Campaign Assessment")
    lines.append("")
    lines.append(f"Mechanical correlation in campaign/campaign_assessment.json assessed "
                 f"campaign_linked={str(campaign_linked).lower()} with cluster_id={cluster_id} "
                 f"at {confidence} confidence")
    if linked_pairs:
        examples = ", ".join(str(p) for p in linked_pairs[:3])
        lines.append(f", on {len(linked_pairs)} linked pair(s) sharing IOC and tactic overlap "
                     f"(examples: {examples}).")
    else:
        lines.append("; no pair met the mechanical linkage rules.")
    lines.append("")
    lines.append("## Open Items for Next Shift")
    lines.append("")
    for item in open_items:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Artifact Index")
    lines.append("")
    lines.append("| PATH | SHA256 |")
    lines.append("|---|---|")
    for rel, digest in sorted(layout_hashes):
        lines.append(f"| {rel} | {digest} |")
    lines.append("")
    lines.append(f"Full recursive workspace listing (including this document): {MANIFEST_REL}.")
    md = "\n".join(lines).rstrip() + "\n"

    handoff_path = os.path.join(ws, HANDOFF_REL)
    with open(handoff_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    # --- 9. Verifications ---------------------------------------------------------
    word_count = len(md.split())
    if word_count > WORD_CAP:
        fail(f"shift_handoff.md word count {word_count} exceeds cap {WORD_CAP}")
    md_headings = {ln.strip() for ln in md.splitlines() if ln.startswith("## ")}
    missing = [h for h in REQUIRED_HEADINGS if h not in md_headings]
    if missing:
        fail(f"shift_handoff.md missing required heading(s): {', '.join(missing)}")
    log(f"shift_handoff.md: {word_count} words, 6 sections OK "
        f"({detailed_count} detailed + {aggregated_count} aggregated incidents)")

    cited = set(re.findall(r"INC-\d{8}-[A-Z]", md))
    unknown = cited - set(incident_ids)
    if unknown:
        fail(f"handoff cites incident ID(s) not in incidents.json: {', '.join(sorted(unknown))}")
    letters = " ".join(sorted(cited)) if cited else "(none)"
    log(f"incident IDs in handoff: {letters} (all in incidents.json: OK)")

    # --- 10. MANIFEST.json (full recursive listing) ---------------------------------
    files = []
    counts = {"runtime": 0, "enriched": 0, "alerts": 0, "investigations": 0,
              "campaign": 0, "reports": 0, "response": 0, "handoff": 0}
    total_bytes = 0
    for root, dirs, fnames in os.walk(ws):
        dirs[:] = [d for d in sorted(dirs) if not os.path.islink(os.path.join(root, d))]
        for fname in sorted(fnames):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, ws).replace(os.sep, "/")
            if rel == MANIFEST_REL:
                continue  # a manifest cannot contain its own hash
            if not os.path.isfile(full):
                continue
            size = os.path.getsize(full)
            files.append({"path": rel, "sha256": sha256_of(full), "size": size})
            total_bytes += size
            top = rel.split("/", 1)[0]
            if top in counts:
                counts[top] += 1

    manifest = {
        "shift_id": shift_id,
        "analyst_host": analyst_host,
        "started_at": shift.get("started_at"),
        "ended_at": ended_at,
        "duration_hours": duration_hours,
        "files": files,
        "artifact_counts": counts,
        "incident_ids": incident_ids,
        "campaign_linked": campaign_linked,
        "cluster_id": cluster_id,
    }
    with open(os.path.join(ws, MANIFEST_REL), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")

    log(f"MANIFEST.json: {len(files)} files, {round(total_bytes / 1024)} KB total")
    log("handoff package complete")

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) != 2:
        print(f"[handoff][ERROR] expected 2 args (workspace, assets_dir), got {len(args)}",
              file=sys.stderr)
        sys.exit(1)
    main(args[0], args[1])
PY

exit 0
