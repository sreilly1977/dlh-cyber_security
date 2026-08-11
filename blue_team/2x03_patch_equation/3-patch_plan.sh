#!/bin/bash
#
# Name:        3-patch_plan.sh
# Purpose:     Cross-reference vulnerability inventory with service dependency map for patch plan
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Input files
readonly VULN_FILE="${BASE_DIR}/vulnerability_inventory.json"
readonly DEPS_FILE="${BASE_DIR}/service_dependency_map.json"

# Output
readonly OUTPUT_FILE="${BASE_DIR}/patch_plan.json"

# Weights (constants as required by task)
readonly CVSS_WEIGHT=0.8
readonly KEV_WEIGHT=1.5
readonly CRITICALITY_WEIGHT=0.5
readonly EXPOSURE_WEIGHT=1.0

log() {
    echo "[*] $*"
}

validate_inputs() {
    local missing=0
    for f in "$VULN_FILE" "$DEPS_FILE"; do
        if [[ ! -f "$f" ]]; then
            log "ERROR: Missing input: $f"
            missing=1
        fi
    done
    [[ $missing -eq 1 ]] && exit 1
}

build_patch_plan() {
    log "Cross-referencing vulnerability inventory with service dependency map..."

    local jq_program
    jq_program=$(mktemp)

    cat > "$jq_program" <<'JQEOF'
def crit_val:
  if . == "critical" then 4
  elif . == "high" then 3
  elif . == "medium" then 2
  else 1 end;

def exposure_rank:
  if .is_kernel or .is_systemd then 1.0
  elif (.affected | length) == 0 then 0.1
  elif any(.affected[]; .service | test("apache|ssh|nginx|mysql|postgres|redis|docker")) then 0.8
  else 0.4
  end;

def max_crit:
  if (.affected | length) == 0 then 0
  else (.affected | map(.criticality | crit_val) | max)
  end;

def compute_bucket:
  if . >= 7 then "emergency"
  elif . >= 4 then "urgent"
  else "scheduled"
  end;

def get_affected_services:
  if .is_kernel then ["(kernel-wide)"]
  elif .is_systemd then ["(system-wide)"]
  elif (.affected | length) == 0 then []
  else [.affected[].service]
  end
;

# Build entries from vulnerability inventory
[
  ($vuln[0].packages // [])[] |
  . as $pkg |

  # Find all services that depend on this package
  ([ $deps[0].services[] | select(
      any(.linked_packages[]?; . == $pkg.package) or
      (.owning_package // "") == $pkg.package
  ) ]) as $affected_svcs |

  # Determine if kernel-related (requires reboot)
  ($pkg.package | test("^linux-image|^linux-headers|^linux-modules|^linux-generic")) as $is_kernel |

  # Determine if systemd itself (requires reboot)
  ($pkg.package == "systemd" or $pkg.package == "systemd-sysv") as $is_systemd |

  # Build context object for helper functions
  {
    package: $pkg.package,
    affected: $affected_svcs,
    is_kernel: $is_kernel,
    is_systemd: $is_systemd,
    max_cvss: ($pkg.max_cvss // 0),
    in_cisa_kev: ($pkg.in_cisa_kev // false),
    cves: ($pkg.cves // []),
    installed_version: ($pkg.installed_version // "")
  } as $ctx |

  # Compute exposure rank
  ($ctx | exposure_rank) as $exposure |

  # Compute max criticality of linked services
  ($ctx | max_crit) as $mc |

  # Compute priority score
  (
    ($cvss_w * $ctx.max_cvss) +
    ($kev_w * (if $ctx.in_cisa_kev == true then 1 else 0 end)) +
    ($crit_w * $mc) +
    ($exp_w * $exposure)
  ) as $score |

  # Build output entry
  {
    package: $ctx.package,
    score: ($score * 100 | floor / 100),
    bucket: ($score | compute_bucket),
    affected_services: ($ctx | get_affected_services),
    requires_restart: (
      if ($ctx.affected | length) == 0 then false
      else any($ctx.affected[]; .restart_required_on_patch == true)
      end
    ),
    requires_reboot: ($ctx.is_kernel or $ctx.is_systemd),
    rollback_target_version: $ctx.installed_version,
    cves: $ctx.cves,
    max_cvss: $ctx.max_cvss,
    in_cisa_kev: $ctx.in_cisa_kev
  }
] |

# Sort by score descending, then package name ascending (deterministic)
sort_by(-.score, .package) |

# Add rank field
to_entries |
map(.value + {rank: (.key + 1)}) |

# Extract plan and compute summary
. as $plan |

{
  generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
  weights: {
    cvss: $cvss_w,
    kev: $kev_w,
    criticality: $crit_w,
    exposure: $exp_w
  },
  plan: $plan,
  summary: {
    total_patches: ($plan | length),
    emergency: ([$plan[] | select(.bucket == "emergency")] | length),
    urgent: ([$plan[] | select(.bucket == "urgent")] | length),
    scheduled: ([$plan[] | select(.bucket == "scheduled")] | length),
    requires_reboot: (any($plan[]; .requires_reboot == true)),
    requires_restart: (any($plan[]; .requires_restart == true))
  }
}
JQEOF

    # Execute jq with slurpfile for both inputs
    jq -n \
        --slurpfile vuln "$VULN_FILE" \
        --slurpfile deps "$DEPS_FILE" \
        --argjson cvss_w "$CVSS_WEIGHT" \
        --argjson kev_w "$KEV_WEIGHT" \
        --argjson crit_w "$CRITICALITY_WEIGHT" \
        --argjson exp_w "$EXPOSURE_WEIGHT" \
        -f "$jq_program" > "$OUTPUT_FILE"

    rm -f "$jq_program"

    # Print summary
    local emergency_count
    local urgent_count
    local scheduled_count
    local requires_reboot

    emergency_count=$(jq '.summary.emergency' "$OUTPUT_FILE")
    urgent_count=$(jq '.summary.urgent' "$OUTPUT_FILE")
    scheduled_count=$(jq '.summary.scheduled' "$OUTPUT_FILE")
    requires_reboot=$(jq -r '.summary.requires_reboot' "$OUTPUT_FILE")

    echo "Emergency: ${emergency_count}   Urgent: ${urgent_count}   Scheduled: ${scheduled_count}"

    if [[ "$requires_reboot" == "true" ]]; then
        echo "Reboot required by plan: yes (kernel update present)"
    else
        echo "Reboot required by plan: no"
    fi

    log "Report saved to: $OUTPUT_FILE"
}

main() {
    log "Building patch plan..."

    validate_inputs

    build_patch_plan

    log "Patch plan complete."
}

main "$@"
