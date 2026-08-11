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
    log "Validating input files..."

    if [[ ! -f "$VULN_FILE" ]]; then
        log "ERROR: Missing input file: $VULN_FILE"
        exit 1
    fi

    if [[ ! -f "$DEPS_FILE" ]]; then
        log "ERROR: Missing input file: $DEPS_FILE"
        exit 1
    fi

    log "Input files validated."
}

build_patch_plan() {
    log "Loading vulnerability inventory..."

    local vuln_count
    vuln_count=$(jq '.packages | length' "$VULN_FILE" 2>/dev/null || echo 0)
    log "Found $vuln_count vulnerable packages"

    log "Loading service dependency map..."
    local deps_count
    deps_count=$(jq '.services | length' "$DEPS_FILE" 2>/dev/null || echo 0)
    log "Found $deps_count services in dependency map"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    log "Computing priority scores..."

    local jq_program
    jq_program=$(mktemp)

    cat > "$jq_program" <<'JQEOF'
def crit_val:
  if . == "critical" then 4
  elif . == "high" then 3
  elif . == "medium" then 2
  else 1 end;

[
  ($vuln[0].packages // [])[] |
  . as $pkg |

  # Find affected services from dependency map
  [($deps[0].services // [])[] | select(
      any(.linked_packages[]?; . == $pkg.package) or
      (.owning_package // "") == $pkg.package
  )] as $affected |

  # Kernel detection
  (($pkg.package | test("^linux-image|^linux-headers|^linux-modules|^linux-generic")) // false) as $is_kernel |

  # Systemd detection
  ((($pkg.package == "systemd") or ($pkg.package == "systemd-sysv")) // false) as $is_systemd |

  # Exposure rank
  (
    if $is_kernel then 1.0
    elif $is_systemd then 1.0
    elif (($affected | length) == 0) then 0.1
    elif ([$affected[] | select(.service | test("apache|ssh|nginx|mysql|postgres|redis|docker"))] | length) > 0 then 0.8
    else 0.4
    end
  ) as $exposure |

  # Max criticality
  (
    if (($affected | length) == 0) then 0
    else ([$affected[].criticality | crit_val] | max)
    end
  ) as $max_crit |

  # KEV value
  (if ($pkg.in_cisa_kev == true) then 1 else 0 end) as $kev_val |

  # Priority score
  (($cvss_w * ($pkg.max_cvss // 0)) +
   ($kev_w * $kev_val) +
   ($crit_w * $max_crit) +
   ($exp_w * $exposure)) as $score |

  # Bucket
  (
    if $score >= 7 then "emergency"
    elif $score >= 4 then "urgent"
    else "scheduled"
    end
  ) as $bucket |

  # Affected services list
  (
    if $is_kernel then ["(kernel-wide)"]
    elif $is_systemd then ["(system-wide)"]
    elif (($affected | length) == 0) then []
    else [$affected[].service]
    end
  ) as $svc_list |

  # Requires restart
  (
    if (($affected | length) == 0) then false
    else any($affected[]; .restart_required_on_patch == true)
    end
  ) as $req_restart |

  # Build entry
  {
    package: $pkg.package,
    score: (($score * 100) | floor / 100),
    bucket: $bucket,
    affected_services: $svc_list,
    requires_restart: $req_restart,
    requires_reboot: ($is_kernel or $is_systemd),
    rollback_target_version: ($pkg.installed_version // ""),
    cves: ($pkg.cves // []),
    max_cvss: ($pkg.max_cvss // 0),
    in_cisa_kev: ($pkg.in_cisa_kev // false)
  }
] |

# Sort by score descending, then package name ascending (deterministic)
sort_by(-.score, .package) |

# Add rank
to_entries | map(.value + {rank: (.key + 1)}) |

# Wrap in final structure
. as $plan |
{
  generated_at: $ts,
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

    # Use --slurpfile for BOTH inputs so $vuln and $deps are available
    if ! jq -n \
        --slurpfile vuln "$VULN_FILE" \
        --slurpfile deps "$DEPS_FILE" \
        --arg ts "$timestamp" \
        --argjson cvss_w "$CVSS_WEIGHT" \
        --argjson kev_w "$KEV_WEIGHT" \
        --argjson crit_w "$CRITICALITY_WEIGHT" \
        --argjson exp_w "$EXPOSURE_WEIGHT" \
        -f "$jq_program" > "$OUTPUT_FILE"; then
        log "ERROR: jq processing failed."
        rm -f "$jq_program"
        exit 1
    fi

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
