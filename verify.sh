#!/usr/bin/env bash
# verify.sh — read-only checks. Creates nothing, changes nothing.
#
# Three jobs:
#   1. Permissions: can you read what the scan needs?
#   2. Coverage:    what will be missing from the map, and why?
#   3. Ground truth: does the tool's logic agree with Azure itself?
#
# Usage:
#   ./verify.sh                                   # permissions + coverage
#   ./verify.sh --nic <nic-resource-id>           # + effective rules/routes for one NIC
#   ./verify.sh --flow <vm-name> <rg> <src-ip> <dst-ip> <port>   # + IP flow verify
set -uo pipefail

hr(){ printf '\n\033[1m%s\033[0m\n%s\n' "$1" "$(printf '─%.0s' {1..70})"; }
ok(){ printf '  \033[32m✓\033[0m %s\n' "$1"; }
no(){ printf '  \033[31m✗\033[0m %s\n' "$1"; }
warn(){ printf '  \033[33m!\033[0m %s\n' "$1"; }

command -v az >/dev/null || { echo "az CLI not found"; exit 1; }
command -v jq >/dev/null || { echo "jq not found"; exit 1; }

# az graph query wraps results in {"data":[...]}. Unwrap it, and never let a
# surprise shape turn into a shell arithmetic error.
gq(){ az graph query -q "$1" --first "${2:-1000}" -o json 2>/dev/null | jq -c '.data // .' 2>/dev/null || echo '[]'; }
num(){ local v; v=$(cat); v="${v//[!0-9]/}"; echo "${v:-0}"; }

ME=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")
UPN=$(az account show --query user.name -o tsv 2>/dev/null || echo "unknown")

hr "1. Identity and subscriptions"
echo "  signed in as: $UPN"
SUBS=$(az account list --all -o json 2>/dev/null | jq 'length' 2>/dev/null | num)
ok "$SUBS subscriptions visible"

hr "2. Roles that matter (read-only checks)"
if [ -n "$ME" ]; then
  ROLES=$(az role assignment list --assignee "$ME" --all --include-inherited \
            --query "[].{role:roleDefinitionName, scope:scope}" -o json 2>/dev/null || echo '[]')
  for R in Reader "Network Contributor" "Monitoring Reader" "Log Analytics Reader"; do
    N=$(echo "$ROLES" | jq --arg r "$R" '[.[] | select(.role==$r)] | length')
    if [ "$N" -gt 0 ]; then ok "$R  ($N assignment(s))"; else warn "$R  not directly assigned"; fi
  done
  echo "$ROLES" | jq -r 'group_by(.role)[] | "     \(.[0].role): \(length) scope(s)"' 2>/dev/null | sort
else
  warn "could not resolve your object id (guest or SP?), skipping role listing"
fi
echo
echo "  What each role buys you:"
echo "    Reader            topology, rules, routes, DNS   (required)"
echo "    Monitoring Reader SNAT / firewall health metrics  (METRICS=1)"
echo "    Log Analytics Rdr flow logs                       (WORKSPACE_ID)"
echo "    Network Contrib.  IP flow verify + effective rules (ground-truth checks only)"

hr "3. Resource Graph reach (what the scan will actually see)"
COUNTS=$(gq "Resources | where type startswith 'microsoft.network/' or type startswith 'microsoft.compute/' | summarize c=count() by type | order by c desc" 100)
TOT=$(echo "$COUNTS" | jq '[.[]?.c // 0] | add // 0' 2>/dev/null | num)
ok "$TOT networking/compute resources readable"
echo "$COUNTS" | jq -r '.[:12][]? | "     \(.c)\t\(.type)"' 2>/dev/null

SUBS_WITH=$(gq "Resources | where type =~ 'microsoft.network/virtualnetworks' | summarize by subscriptionId" 500 | jq 'length' 2>/dev/null | num)
echo "     VNets found across $SUBS_WITH subscription(s)"
if [ "$SUBS_WITH" -lt "$SUBS" ]; then
  warn "$((SUBS - SUBS_WITH)) subscription(s) have no readable VNets — either none exist, or you lack Reader there"
fi

hr "4. Coverage gaps: VNets with no flow log"
gq "
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| project vnetId = tolower(id), vnetName = name, sub = subscriptionId
| join kind=leftouter (
    Resources
    | where type =~ 'microsoft.network/networkwatchers/flowlogs'
    | extend target = tolower(tostring(properties.targetResourceId)),
             ta = tostring(properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled)
    | project target, ta
  ) on \$left.vnetId == \$right.target
| where isempty(target) or ta != 'true'
| project vnetName, sub, trafficAnalytics = iff(isempty(ta), 'none', ta)
" 500 > /tmp/_gaps.json
GAPS=$(jq 'length' /tmp/_gaps.json 2>/dev/null | num)
if [ "$GAPS" -eq 0 ]; then ok "every readable VNet has flow logs with traffic analytics on"
else
  warn "$GAPS VNet(s) will show topology but no traffic:"
  jq -r '.[:15][]? | "     \(.vnetName)  (traffic analytics: \(.trafficAnalytics))"' /tmp/_gaps.json 2>/dev/null
fi

hr "5. AVNM: is anything actually managed?"
NM=$(gq "Resources | where type =~ 'microsoft.network/networkmanagers' | project name, subscriptionId" 100)
if [ "$(echo "$NM" | jq 'length' 2>/dev/null | num)" -eq 0 ]; then
  warn "no Network Manager found (AVNM findings will be empty)"
else
  ok "$(echo "$NM" | jq 'length' 2>/dev/null | num) network manager(s)"
  MEM=$(gq "networkresources | where type == 'microsoft.network/networkgroupmemberships' | project id" 1000 | jq 'length' 2>/dev/null | num)
  VNETS=$(gq "Resources | where type =~ 'microsoft.network/virtualnetworks' | project id" 1000 | jq 'length' 2>/dev/null | num)
  ok "$MEM of $VNETS VNets have a network group membership record"
  [ "$MEM" -lt "$VNETS" ] && warn "$((VNETS - MEM)) VNet(s) unmanaged — these appear in Analysis as 'not managed by AVNM'"
fi

hr "6. Ground truth: effective rules and routes for one NIC"
NIC="${NIC_ID:-}"
if [ "${1:-}" = "--nic" ]; then NIC="${2:-}"; fi
if [ -z "$NIC" ]; then
  NIC=$(gq "Resources | where type =~ 'microsoft.network/networkinterfaces' and isnotnull(properties.virtualMachine) | project id | limit 1" 1 | jq -r '.[0].id // empty' 2>/dev/null)
fi
if [ -z "$NIC" ]; then
  warn "no NIC found to test against"
else
  echo "  NIC: $NIC"
  RG=$(echo "$NIC" | sed -n 's#.*/resourceGroups/\([^/]*\)/.*#\1#p')
  NAME=$(basename "$NIC")
  SUB=$(echo "$NIC" | sed -n 's#/subscriptions/\([^/]*\)/.*#\1#p')

  echo
  echo "  Azure's own effective NSG rules (compare with the tool's 'Effective rules' panel):"
  if az network nic list-effective-nsg --ids "$NIC" -o json 2>/dev/null \
      | jq -r '.value[]? | "     [\(.networkSecurityGroup.id | split("/") | last)]",
               (.effectiveSecurityRules[]? | "       #\(.priority) \(.direction) \(.access) \(.protocol) :\(.destinationPortRange) \(.sourceAddressPrefix // "-") -> \(.destinationAddressPrefix // "-")  \(.name)")' 2>/dev/null | head -25; then
    ok "effective NSG rules retrieved"
  else
    warn "could not read effective NSG rules (needs Network Contributor, and the VM must be running)"
  fi

  echo
  echo "  Azure's effective ROUTES — this is the gap the tool cannot see (BGP / peering):"
  if az network nic show-effective-route-table --ids "$NIC" -o json 2>/dev/null \
      | jq -r '.value[]? | "     \(.source)\t\(.addressPrefix | join(","))\t-> \(.nextHopType) \(.nextHopIpAddress | join(","))"' 2>/dev/null | head -20; then
    ok "effective routes retrieved"
    echo "     Anything with source 'VirtualNetworkGateway' or 'Default' is INVISIBLE to the tool,"
    echo "     which only reads user-defined routes. If Troubleshoot says 'allowed' but traffic fails,"
    echo "     look here first."
  else
    warn "could not read effective routes (needs Network Contributor, and the VM must be running)"
  fi
fi

hr "7. Ground truth: IP flow verify (the tracer's answer key)"
if [ "${1:-}" = "--flow" ]; then
  VM="${2:-}"; VRG="${3:-}"; SRC="${4:-}"; DST="${5:-}"; PORT="${6:-}"
  echo "  az network watcher test-ip-flow --vm $VM -g $VRG --direction Outbound --protocol TCP --local $SRC:0 --remote $DST:$PORT"
  az network watcher test-ip-flow --vm "$VM" -g "$VRG" --direction Outbound --protocol TCP \
      --local "$SRC:0" --remote "$DST:$PORT" -o json 2>/dev/null \
    | jq -r '"     access: \(.access)\n     rule:   \(.ruleName)"' \
    || warn "test-ip-flow failed (needs Network Contributor; VM must be running)"
  echo
  echo "  Now run the same source/destination/port in the tool's Troubleshoot tab."
  echo "  Same verdict AND same rule name = the evaluation logic is right."
  echo "  Different rule = tell me which, and I will fix the ordering."
else
  echo "  Skipped. Run:  ./verify.sh --flow <vm-name> <vm-rg> <src-ip> <dst-ip> <port>"
  echo "  This is the single best check of the Troubleshoot tab. It asks Azure to evaluate"
  echo "  the flow itself and name the deciding rule."
fi

hr "Summary"
echo "  Required for the map:        Reader                (checked above)"
echo "  Required for traffic:        Log Analytics Reader  + flow logs w/ traffic analytics"
echo "  Required for METRICS=1:      Monitoring Reader"
echo "  Required only for verify:    Network Contributor   (test-ip-flow, effective rules)"
echo
echo "  Nothing in this script or the mapper writes to Azure."
