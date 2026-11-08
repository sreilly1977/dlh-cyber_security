#!/usr/bin/env python3
# Name: audit_iam.py
# Purpose: Process the MedDefense AD account inventory (accounts.csv), apply the six
#          required IAM checks (dormant privileged, MFA coverage, service account
#          over-privilege, departed/transferred, disabled-with-groups, high-risk
#          no-MFA), score every finding against severity_model.md, and write a
#          machine-readable findings report (iam_findings.json) plus a
#          human-readable summary to stdout. Every finding is traceable to one
#          inventory row and one named check.
# Author: Steve - Cybersecurity Engineer
# Date: 08 November 2026
#
# Usage:
#   python3 audit_iam.py [--input accounts.csv] [--output iam_findings.json]
#
# Documented design decisions (for defensibility):
#   - Dormancy checks apply only to ENABLED accounts. A disabled account cannot
#     authenticate, so its residual risk is retained group membership, which is
#     handled by check_disabled_with_groups.
#   - Dormant privileged users are High per severity_model.md. Dormant
#     privileged service accounts are Critical because a standing privileged
#     service credential repeats the prior Cobalt Strike incident path.
#   - Departure keywords ("contract ended", "left organization") on a privileged
#     account are Critical (a departed person holding Domain Admins). Other
#     lifecycle keywords ("transferred from", "migration complete") are High,
#     pending the manual review this check mandates.

import argparse
import csv
import json
import re
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_VERSION = "1.0"
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")

# Lifecycle keywords from the task specification (matched case-insensitively).
DEPARTURE_KEYWORDS = ("contract ended", "left organization")
LIFECYCLE_KEYWORDS = ("transferred from", "migration complete")
ALL_LIFECYCLE_KEYWORDS = DEPARTURE_KEYWORDS + LIFECYCLE_KEYWORDS

PRIVILEGED_ADMIN_GROUPS = ("Domain Admins", "Server Admins")


# ---------------------------------------------------------------------------
# Inventory helpers
# ---------------------------------------------------------------------------

def to_bool(value):
    """Parse TRUE/FALSE inventory fields."""
    return str(value).strip().upper() == "TRUE"


def group_list(account):
    """Split the privileged_groups field into a clean list."""
    raw = account.get("privileged_groups", "") or ""
    return [g.strip() for g in re.split(r"[;,]", raw) if g.strip()]


def in_group(account, group):
    return group in group_list(account)


def is_user(account):
    return str(account.get("account_type", "")).strip().lower() == "user"


def is_service(account):
    return str(account.get("account_type", "")).strip().lower() == "service"


def is_enabled(account):
    return to_bool(account.get("enabled", ""))


def days_since_login(account):
    try:
        return int(str(account.get("last_login_days_ago", "")).strip())
    except ValueError:
        return None


def has_mfa(account):
    return to_bool(account.get("mfa_enrolled", ""))


def admin_membership(account):
    """Return the privileged admin groups this account belongs to."""
    return [g for g in PRIVILEGED_ADMIN_GROUPS if in_group(account, g)]


def evidence_for(account):
    """Standard evidence string: account, type, enabled, login, MFA, groups, source."""
    return (
        "enabled={}; account_type={}; privileged_groups={}; "
        "last_login_days_ago={}; mfa_enrolled={}; description={}".format(
            account.get("enabled", ""),
            account.get("account_type", ""),
            account.get("privileged_groups", ""),
            account.get("last_login_days_ago", ""),
            account.get("mfa_enrolled", ""),
            account.get("description", ""),
        )
    )


# ---------------------------------------------------------------------------
# Required checks. Each returns a list of findings (usually zero or one).
# ---------------------------------------------------------------------------

def check_dormant_privileged(account, dormancy_threshold_days=90):
    """
    Users in Domain Admins / Server Admins with no login beyond the threshold
    are flagged High. Service accounts in those groups with no login beyond
    365 days are flagged separately as dormant_service_privileged (Critical).
    Disabled accounts are excluded: see header design decisions.
    """
    findings = []
    if not is_enabled(account) or not admin_membership(account):
        return findings
    days = days_since_login(account)
    if days is None:
        return findings

    if is_user(account) and days > dormancy_threshold_days:
        findings.append({
            "account": account["username"],
            "check": "check_dormant_privileged",
            "severity": "High",
            "title": "Dormant privileged user account "
                     "({} days since last login)".format(days),
            "evidence": evidence_for(account),
            "remediation": (
                "Confirm ownership and business need; remove the privileged "
                "group membership if none exists. If the account is still "
                "required, enforce MFA and replace standing privilege with "
                "just-in-time elevation."
            ),
        })
    elif is_service(account) and days > 365:
        findings.append({
            "account": account["username"],
            "check": "check_dormant_privileged",
            "subtype": "dormant_service_privileged",
            "severity": "Critical",
            "title": "Dormant privileged service account "
                     "({} days since last login)".format(days),
            "evidence": evidence_for(account),
            "remediation": (
                "Disable immediately and audit recent activity; identify the "
                "owning team. If no function is confirmed, delete the account. "
                "Any replacement workload must receive short-TTL dynamic "
                "credentials (Vault) instead of a standing privileged service "
                "credential, which repeats the prior incident path."
            ),
        })
    return findings


def check_mfa_coverage(account):
    """Enabled user accounts in Domain Admins / Server Admins without MFA."""
    findings = []
    if not (is_user(account) and is_enabled(account)):
        return findings
    if admin_membership(account) and not has_mfa(account):
        findings.append({
            "account": account["username"],
            "check": "check_mfa_coverage",
            "severity": "High",
            "title": "Privileged account ({}) without MFA enrollment".format(
                "; ".join(admin_membership(account))),
            "evidence": evidence_for(account),
            "remediation": (
                "Enroll the account holder in MFA immediately and enforce MFA "
                "for all privileged logins; alternatively remove the "
                "privileged membership if it is no longer required."
            ),
        })
    return findings


def check_service_account_overpriv(account):
    """Service accounts: Domain Admins = Critical, Server Admins = Medium."""
    findings = []
    if not is_service(account):
        return findings

    if in_group(account, "Domain Admins"):
        remediation = (
            "Remove the Domain Admins membership and re-scope the automation "
            "to the minimum required permissions, or migrate it to "
            "short-TTL dynamic credentials via Vault (see "
            "pam_migration_candidates.csv)."
        )
        if account["username"] == "svc_epic_int":
            remediation = (
                "Disable immediately; audit all actions taken under this "
                "account in the past 90 days; remove Domain Admins membership; "
                "if no function confirmed within 30 days, delete the account"
            )
        findings.append({
            "account": account["username"],
            "check": "check_service_account_overpriv",
            "severity": "Critical",
            "title": "Service account with Domain Admin membership",
            "evidence": evidence_for(account),
            "remediation": remediation,
        })
    elif in_group(account, "Server Admins"):
        findings.append({
            "account": account["username"],
            "check": "check_service_account_overpriv",
            "severity": "Medium",
            "title": "Service account with Server Admin membership",
            "evidence": evidence_for(account),
            "remediation": (
                "Re-scope the agent to read-only access for its stated function "
                "and issue least-privilege credentials; evaluate a scoped role "
                "per pam_migration_candidates.csv."
            ),
        })
    elif in_group(account, "Workstation Admins"):
        findings.append({
            "account": account["username"],
            "check": "check_service_account_overpriv",
            "severity": "Low",
            "title": "Service account with Workstation Admin membership",
            "evidence": evidence_for(account),
            "remediation": (
                "Evaluate the agent for a scoped management role or "
                "just-in-time elevation; confirm Workstation Admins is truly "
                "required for the agent function."
            ),
        })
    return findings


def check_departed_or_transferred(account):
    """
    Scan the description for lifecycle keywords and flag for manual review
    with the matched keyword. Departure keywords on a privileged account are
    Critical; everything else is High.
    """
    findings = []
    description = (account.get("description", "") or "").lower()
    matched = [kw for kw in ALL_LIFECYCLE_KEYWORDS if kw in description]
    if not matched:
        return findings

    departure = any(kw in DEPARTURE_KEYWORDS for kw in matched)
    privileged = bool(admin_membership(account))
    severity = "Critical" if (departure and privileged) else "High"

    findings.append({
        "account": account["username"],
        "check": "check_departed_or_transferred",
        "severity": severity,
        "title": "Departed or transferred account flagged for manual review "
                 "(keyword: '{}')".format(matched[0]),
        "evidence": evidence_for(account),
        "remediation": (
            "Manual review: confirm employment or transfer status with HR. "
            "If departed or transferred, disable the account, strip all "
            "privileged group memberships, and synchronize off-boarding "
            "across every connected system."
        ),
    })
    return findings


def check_disabled_with_groups(account):
    """Accounts that are disabled but still hold group memberships."""
    findings = []
    if not is_enabled(account) and group_list(account):
        findings.append({
            "account": account["username"],
            "check": "check_disabled_with_groups",
            "severity": "Medium",
            "title": "Disabled account retaining privileged group memberships",
            "evidence": evidence_for(account),
            "remediation": (
                "Strip all privileged group memberships from the disabled "
                "account now; retain the disabled account for the standard "
                "retention period, then delete it. Update the off-boarding "
                "process to remove groups at disablement."
            ),
        })
    return findings


def check_no_mfa_high_risk(account):
    """
    Enabled user accounts without MFA, Low severity; escalated to Medium when
    the description references repeated security failures.
    """
    findings = []
    if not (is_user(account) and is_enabled(account)):
        return findings
    if has_mfa(account):
        return findings

    description = account.get("description", "") or ""
    repeated_failures = re.search(r"failures?", description, re.IGNORECASE)
    severity = "Medium" if repeated_failures else "Low"
    title = "Enabled user account without MFA enrollment"
    remediation = (
        "Enroll the account holder in MFA and include the account in the "
        "next access review cycle."
    )
    if repeated_failures:
        title = ("Enabled user account without MFA and repeated security "
                 "failures")
        remediation = (
            "Prioritize MFA enrollment; given the repeated security failures, "
            "combine with targeted phishing and security awareness "
            "follow-up, and consider conditional access restrictions."
        )

    findings.append({
        "account": account["username"],
        "check": "check_no_mfa_high_risk",
        "severity": severity,
        "title": title,
        "evidence": evidence_for(account),
        "remediation": remediation,
    })
    return findings


CHECK_ORDER = (
    check_dormant_privileged,
    check_mfa_coverage,
    check_service_account_overpriv,
    check_departed_or_transferred,
    check_disabled_with_groups,
    check_no_mfa_high_risk,
)


# ---------------------------------------------------------------------------
# Audit driver
# ---------------------------------------------------------------------------

def audit(accounts):
    """Run every check against every account; assign sequential finding IDs."""
    findings = []
    for row_index, account in enumerate(accounts):
        for check_index, check in enumerate(CHECK_ORDER):
            for finding in check(account):
                finding["_row"] = row_index
                finding["_check_order"] = check_index
                findings.append(finding)

    severity_rank = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (
        severity_rank[f["severity"]], f["_row"], f["_check_order"]))

    ordered = []
    for number, finding in enumerate(findings, start=1):
        ordered.append(OrderedDict([
            ("finding_id", "IAM-{:03d}".format(number)),
            ("account", finding["account"]),
            ("check", finding["check"]),
            ("severity", finding["severity"]),
            ("title", finding["title"]),
            ("evidence", finding["evidence"]),
            ("remediation", finding["remediation"]),
        ]))
    return ordered


def build_report(accounts, findings):
    counts = OrderedDict((name, 0) for name in SEVERITY_ORDER)
    for finding in findings:
        counts[finding["severity"]] += 1
    return OrderedDict([
        ("audit_metadata", OrderedDict([
            ("script_version", SCRIPT_VERSION),
            ("accounts_processed", len(accounts)),
            ("audit_timestamp",
             datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
            ("findings_count", counts),
        ])),
        ("findings", findings),
    ])


def print_summary(report):
    metadata = report["audit_metadata"]
    findings = report["findings"]

    print("IAM audit findings written to iam_findings.json")
    print()
    print("{:<20}: {}".format("Accounts processed",
                              metadata["accounts_processed"]))
    print("{:<20}: {}".format("Critical findings",
                              metadata["findings_count"]["Critical"]))
    print("{:<20}: {}".format("High findings",
                              metadata["findings_count"]["High"]))
    print("{:<20}: {}".format("Medium findings",
                              metadata["findings_count"]["Medium"]))
    print("{:<20}: {}".format("Low findings",
                              metadata["findings_count"]["Low"]))
    print()

    for severity in SEVERITY_ORDER:
        matching = [f for f in findings if f["severity"] == severity]
        if not matching:
            continue
        print("{}:".format(severity))
        for finding in matching:
            print("  [{}] {}: {}".format(
                finding["finding_id"], finding["account"], finding["title"]))
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Audit the MedDefense IAM account inventory and emit "
                    "severity-scored findings.")
    parser.add_argument("--input", default="accounts.csv",
                        help="path to the account inventory CSV")
    parser.add_argument("--output", default="iam_findings.json",
                        help="path for the JSON findings report")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        raise SystemExit("Inventory file not found: {}".format(input_path))

    with input_path.open(newline="", encoding="utf-8") as handle:
        accounts = list(csv.DictReader(handle))
    if not accounts:
        raise SystemExit("Inventory file is empty: {}".format(input_path))

    findings = audit(accounts)
    report = build_report(accounts, findings)

    with Path(args.output).open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")

    print_summary(report)


if __name__ == "__main__":
    main()
