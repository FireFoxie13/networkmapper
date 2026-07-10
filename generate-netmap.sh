#!/usr/bin/env bash
# generate-netmap.sh — SolarWinds-NTM-style discovery scan for Azure.
# Runs Resource Graph discovery across every subscription you can see,
# pulls public DNS records (Cloudflare detection), optionally pulls
# VNet flow logs, and emits a self-contained dated HTML topology map.
#
# Usage:
#   ./generate-netmap.sh                                     # network topology + DNS
#   WORKSPACE_ID=<guid>[,<guid>...] ./generate-netmap.sh     # + traffic w/ ports, bytes, denied flows
#   FLOW_WINDOW=7d WORKSPACE_ID=... ./generate-netmap.sh      # how far back to pull flows (default 24h)
#   ALL_RESOURCES=1 ./generate-netmap.sh                     # + every resource of every type, grouped by resource group
#   METRICS=1 ./generate-netmap.sh                           # + CPU / throughput / disk from Azure Monitor (needs Monitoring Reader)
#
# Schedule it (cron / Azure Automation / GitHub Actions) and the map
# stays current — same idea as NTM scheduled scans.
#
# Requires: az CLI (logged in), jq, python3. For flows: az extension log-analytics.
set -euo pipefail

TEMPLATE="${TEMPLATE:-azure-net-map.html}"
STAMP=$(date +%Y-%m-%d_%H%M)
OUT="azure-net-map-${STAMP}.html"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ ! -f "$TEMPLATE" ]; then
  echo "ERROR: template '$TEMPLATE' not found. Put azure-net-map.html in this directory (or set TEMPLATE=path)." >&2
  exit 1
fi

echo "[1/6] Discovering topology via Resource Graph (all visible subscriptions)..."
QUERY="Resources | where type in~ ('microsoft.network/virtualnetworks','microsoft.network/networksecuritygroups','microsoft.network/routetables','microsoft.network/networkinterfaces','microsoft.network/loadbalancers','microsoft.network/applicationgateways','microsoft.network/publicipaddresses','microsoft.network/azurefirewalls','microsoft.network/firewallpolicies','microsoft.network/firewallpolicies/rulecollectiongroups','microsoft.network/ipgroups','microsoft.network/applicationsecuritygroups','microsoft.network/applicationgatewaywebapplicationfirewallpolicies','microsoft.network/networkmanagers','microsoft.network/networkmanagers/networkgroups','microsoft.network/networkmanagers/connectivityconfigurations','microsoft.network/networkmanagers/securityadminconfigurations','microsoft.network/networkmanagers/securityadminconfigurations/rulecollections','microsoft.network/networkmanagers/securityadminconfigurations/rulecollections/rules','microsoft.network/frontdoors','microsoft.network/frontdoorwebapplicationfirewallpolicies','microsoft.network/privateendpoints','microsoft.network/privatelinkservices','microsoft.network/bastionhosts','microsoft.network/natgateways','microsoft.network/virtualnetworkgateways','microsoft.network/localnetworkgateways','microsoft.network/expressroutecircuits','microsoft.network/connections','microsoft.network/virtualwans','microsoft.network/virtualhubs','microsoft.network/dnsresolvers','microsoft.network/dnsresolvers/inboundendpoints','microsoft.network/dnsresolvers/outboundendpoints','microsoft.network/dnsforwardingrulesets','microsoft.network/dnsforwardingrulesets/virtualnetworklinks','microsoft.network/privatednszones','microsoft.network/privatednszones/virtualnetworklinks','microsoft.network/dnszones','microsoft.network/trafficmanagerprofiles','microsoft.cdn/profiles','microsoft.compute/virtualmachines','microsoft.compute/virtualmachinescalesets','microsoft.containerservice/managedclusters','microsoft.web/sites','microsoft.web/serverfarms','microsoft.sql/servers','microsoft.storage/storageaccounts','microsoft.keyvault/vaults','microsoft.documentdb/databaseaccounts','microsoft.cache/redis','microsoft.servicebus/namespaces','microsoft.eventhub/namespaces','microsoft.containerregistry/registries') | project id, name, type, kind, properties"

echo "[]" > "$TMP/topo.json"
SKIP=0
while : ; do
  az graph query -q "$QUERY" --first 1000 --skip "$SKIP" -o json > "$TMP/page.json"
  COUNT=$(jq '.data | length' "$TMP/page.json")
  jq -s '.[0] + .[1].data' "$TMP/topo.json" "$TMP/page.json" > "$TMP/topo2.json" && mv "$TMP/topo2.json" "$TMP/topo.json"
  echo "    page: $COUNT resources (total so far: $(jq 'length' "$TMP/topo.json"))"
  [ "$COUNT" -lt 1000 ] && break
  SKIP=$((SKIP + 1000))
done
TOTAL=$(jq 'length' "$TMP/topo.json")

echo "[2/6] AVNM network group membership (static + dynamic)..."
# Membership lives in the networkresources table, not Resources. Dynamic (Azure Policy)
# membership is only visible here, so a plain resource query would miss it.
if az graph query -q "networkresources | where type == 'microsoft.network/networkgroupmemberships' | project id, name, type, properties" --first 1000 -o json > "$TMP/ngm.json" 2>/dev/null; then
  NGM=$(jq '.data | length' "$TMP/ngm.json" 2>/dev/null || echo 0)
  if [ "${NGM:-0}" -gt 0 ]; then
    jq -s '.[0] + .[1].data' "$TMP/topo.json" "$TMP/ngm.json" > "$TMP/topo2.json" && mv "$TMP/topo2.json" "$TMP/topo.json"
  fi
  echo "    $NGM membership records"
else
  echo "    unavailable (no AVNM, or no read access to networkresources)"
fi
TOTAL=$(jq 'length' "$TMP/topo.json")

# AVNM security admin rules are child resources that Resource Graph does not always
# index. If the graph query returned none, enumerate them through the management API.
# Reader is enough; these are GET calls.
NMGRS=$(jq -r '.[] | select(.type|ascii_downcase == "microsoft.network/networkmanagers") | .id' "$TMP/topo.json" 2>/dev/null || true)
HAVE_RC=$(jq '[.[] | select(.type|ascii_downcase|test("securityadminconfigurations/rulecollections$"))] | length' "$TMP/topo.json" 2>/dev/null || echo 0)
if [ -n "${NMGRS:-}" ] && [ "${HAVE_RC:-0}" -eq 0 ]; then
  echo "    AVNM security admin rules (Resource Graph returned none, asking the API)..."
  : > "$TMP/adminrules.json"
  API="2024-05-01"
  while IFS= read -r NMID; do
    [ -z "$NMID" ] && continue
    CFGS=$(az rest --method get --url "https://management.azure.com${NMID}/securityAdminConfigurations?api-version=${API}" -o json 2>/dev/null | jq -r '.value[]?.id' || true)
    while IFS= read -r CFG; do
      [ -z "$CFG" ] && continue
      RCS=$(az rest --method get --url "https://management.azure.com${CFG}/ruleCollections?api-version=${API}" -o json 2>/dev/null || echo '{}')
      echo "$RCS" | jq -c '.value[]?' >> "$TMP/adminrules.json" 2>/dev/null || true
      RCIDS=$(echo "$RCS" | jq -r '.value[]?.id' || true)
      while IFS= read -r RCID; do
        [ -z "$RCID" ] && continue
        az rest --method get --url "https://management.azure.com${RCID}/rules?api-version=${API}" -o json 2>/dev/null \
          | jq -c '.value[]?' >> "$TMP/adminrules.json" 2>/dev/null || true
      done <<< "$RCIDS"
    done <<< "$CFGS"
  done <<< "$NMGRS"
  ARN=$(wc -l < "$TMP/adminrules.json" | tr -d ' ')
  if [ "${ARN:-0}" -gt 0 ]; then
    jq -s '.' "$TMP/adminrules.json" > "$TMP/ar.json"
    jq -s '.[0] + .[1]' "$TMP/topo.json" "$TMP/ar.json" > "$TMP/topo2.json" && mv "$TMP/topo2.json" "$TMP/topo.json"
    echo "      $ARN security admin rule object(s) added"
  else
    echo "      none returned (no security admin configuration, or no read access)"
  fi
fi

echo "[3/6] Pulling public DNS records from every DNS zone..."
echo "[]" > "$TMP/dns.json"
az network dns zone list --query "[].[resourceGroup,name]" -o tsv 2>/dev/null | while IFS=$'\t' read -r g z; do
  [ -z "$g" ] && continue
  az network dns record-set list -g "$g" -z "$z" -o json 2>/dev/null || echo "[]"
done | jq -s 'add // []' > "$TMP/dns.json" || echo "[]" > "$TMP/dns.json"
DNSN=$(jq 'length' "$TMP/dns.json")

echo "[4/6] Flow logs..."
echo "[]" > "$TMP/flows.json"
if [ -n "${WORKSPACE_ID:-}" ]; then
  # WORKSPACE_ID may be a comma-separated list; results are merged.
  # Time-bucketed so the UI can show the last 30 min / 1h / 6h / 24h / 7d.
  # FLOW_WINDOW controls how far back the scan reaches (default 24h; try 7d).
  #
  # AclRule / AclGroup are Azure's own verdict: which NSG rule or AVNM security admin
  # rule allowed or denied the flow. PrivateEndpointResourceId attributes traffic that
  # terminates on a private endpoint (it cannot be captured at the endpoint itself).
  #
  # DEDUPLICATION: when flow logging is on at both ends, the same flow is recorded
  # twice (distinguished by FlowDirection / MacAddress). Summing both would double the
  # counts, so we aggregate per direction and then take the max.
  #
  # SIZE: we pick the busiest 2,000 allowed conversations AND up to 3,000 denied ones,
  # then bucket only those, so the payload stays bounded no matter how long the window
  # is — without ever discarding denied traffic, which is the whole point.
  FW="${FLOW_WINDOW:-24h}"
  # NTANetAnalytics leaves SrcIp/DestIp BLANK for AzurePublic and ExternalPublic flows
  # (documented behaviour: the address is public, so it is reported in Src/DestPublicIps
  # instead, bar-delimited as "<IP> | started | ended | outPkts | inPkts | outBytes | inBytes").
  # The old query grouped on the blank IP, so every public/external flow — inbound Cloudflare
  # WAF, egress to SaaS, Azure service traffic: ~89% of bytes here — collapsed to one empty
  # row and the mapper dropped it. Recover the real address into SrcIp/DestIp, and carry the
  # Azure-provided enrichment (service tag, country, region, L7) so the map can NAME the far
  # end (e.g. "Cloudflare", "Storage.centralus") instead of a bare IP.
  KQL="let W = ${FW};
let base = NTANetAnalytics
| where TimeGenerated > ago(W) and SubType == 'FlowLog'
| extend SrcIp  = iif(isempty(SrcIp),  extract(@'^\s*([0-9A-Fa-f:.]+)', 1, tostring(SrcPublicIps)),  SrcIp)
| extend DestIp = iif(isempty(DestIp), extract(@'^\s*([0-9A-Fa-f:.]+)', 1, tostring(DestPublicIps)), DestIp)
| where isnotempty(SrcIp) and isnotempty(DestIp);
let denied = base
| where FlowStatus == 'Denied'
| summarize F = count() by SrcIp, DestIp, DestPort, L4Protocol, FlowStatus
| top 3000 by F
| project SrcIp, DestIp, DestPort, L4Protocol, FlowStatus;
let allowed = base
| where FlowStatus != 'Denied'
| summarize F = count() by SrcIp, DestIp, DestPort, L4Protocol, FlowStatus
| top 2000 by F
| project SrcIp, DestIp, DestPort, L4Protocol, FlowStatus;
// Denied flows are rare next to allowed ones, so a plain top-by-count would drop them
// entirely. Select them separately and always keep them.
let busiest = union denied, allowed;
base
| join kind=inner busiest on SrcIp, DestIp, DestPort, L4Protocol, FlowStatus
| summarize Flows = count(),
            BytesSrcToDest = sum(BytesSrcToDest),
            BytesDestToSrc = sum(BytesDestToSrc),
            SrcServiceTags = take_any(SrcServiceTags),
            DestServiceTags = take_any(DestServiceTags),
            Country = take_any(Country),
            AzureRegion = take_any(AzureRegion),
            L7Protocol = take_any(L7Protocol)
    by Bucket = bin(TimeGenerated, 30m), SrcIp, DestIp, DestPort, L4Protocol, FlowStatus,
       AclRule, AclGroup, FlowType, PrivateEndpointResourceId
| summarize Flows = max(Flows),
            BytesSrcToDest = max(BytesSrcToDest),
            BytesDestToSrc = max(BytesDestToSrc),
            SrcServiceTags = take_any(SrcServiceTags),
            DestServiceTags = take_any(DestServiceTags),
            Country = take_any(Country),
            AzureRegion = take_any(AzureRegion),
            L7Protocol = take_any(L7Protocol)
    by Bucket, SrcIp, DestIp, DestPort, L4Protocol, FlowStatus,
       AclRule, AclGroup, FlowType, PrivateEndpointResourceId
| top 20000 by Flows"
  : > "$TMP/flows_raw.json"
  OLDIFS=$IFS; IFS=','
  for WS in $WORKSPACE_ID; do
    IFS=$OLDIFS
    WS=$(printf '%s' "$WS" | tr -d '[:space:]')
    [ -z "$WS" ] && continue
    if az monitor log-analytics query -w "$WS" --analytics-query "$KQL" -o json > "$TMP/ws.json" 2>/dev/null; then
      N=$(jq 'length' "$TMP/ws.json" 2>/dev/null || echo 0)
      D=$(jq '[.[] | select(.FlowStatus=="Denied")] | length' "$TMP/ws.json" 2>/dev/null || echo 0)
      echo "    ${WS:0:8}…  $N rows, $D denied  (window ${FW})"
      jq -c '.[]' "$TMP/ws.json" >> "$TMP/flows_raw.json" 2>/dev/null || true
    else
      echo "    ${WS:0:8}…  query failed (no access, or NTANetAnalytics not present)" >&2
    fi
    IFS=','
  done
  IFS=$OLDIFS
  jq -s '.' "$TMP/flows_raw.json" > "$TMP/flows.json" 2>/dev/null || echo "[]" > "$TMP/flows.json"
  echo "    $(jq 'length' "$TMP/flows.json") flow rows total"

  # ---- Azure Firewall decisions. These are NOT in NTANetAnalytics: the firewall writes
  # structured logs to its own tables, one per rule type. RuleType (the table name) tells
  # you whether a network rule, application rule, NAT rule, threat-intel hit or an IDPS
  # signature made the call. ActionReason='Default Action' means no rule matched.
  echo "    Azure Firewall rule logs..."
  FWKQL="let W = ${FW};
union isfuzzy=true AZFWNetworkRule, AZFWApplicationRule, AZFWNatRule, AZFWThreatIntel, AZFWIdpsSignature
| where TimeGenerated > ago(W)
| extend Dest = iff(isnotempty(tostring(DestinationIp)), tostring(DestinationIp), tostring(Fqdn))
| extend RuleType = Type
| summarize Hits = count() by Bucket = bin(TimeGenerated, 30m), RuleType, SourceIp, Dest, DestinationPort,
            Protocol, Action, ActionReason, Rule, RuleCollection, RuleCollectionGroup, Policy
| top 20000 by Hits"
  : > "$TMP/fw_raw.json"
  OLDIFS=$IFS; IFS=','
  for WS in $WORKSPACE_ID; do
    IFS=$OLDIFS
    WS=$(printf '%s' "$WS" | tr -d '[:space:]')
    [ -z "$WS" ] && continue
    if az monitor log-analytics query -w "$WS" --analytics-query "$FWKQL" -o json > "$TMP/fw.json" 2>/dev/null; then
      N=$(jq 'length' "$TMP/fw.json" 2>/dev/null || echo 0)
      D=$(jq '[.[] | select(.Action=="Deny")] | length' "$TMP/fw.json" 2>/dev/null || echo 0)
      [ "${N:-0}" -gt 0 ] && echo "      ${WS:0:8}…  $N firewall rows, $D denied"
      jq -c '.[]' "$TMP/fw.json" >> "$TMP/fw_raw.json" 2>/dev/null || true
    fi
    IFS=','
  done
  IFS=$OLDIFS
  jq -s '.' "$TMP/fw_raw.json" > "$TMP/fwlogs.json" 2>/dev/null || echo "[]" > "$TMP/fwlogs.json"
  FWN=$(jq 'length' "$TMP/fwlogs.json")
  if [ "${FWN:-0}" -eq 0 ]; then
    echo "      no firewall logs (enable structured logs: AZFWNetworkRule / AZFWApplicationRule)"
  else
    echo "      $FWN firewall rule decisions"
  fi

  # ---- Azure's own rule recommendations. Traffic Analytics evaluates observed flows and
  # publishes a verdict per traffic pattern: Allow, Block, or Advisory (review). This is
  # Microsoft's authoritative take on "should this be allowed — is the rule legitimate?".
  # https://learn.microsoft.com/azure/azure-monitor/reference/tables/ntarulerecommendation
  echo "    Azure rule recommendations (NTARuleRecommendation)..."
  RECOKQL="let W = ${FW};
NTARuleRecommendation
| where TimeGenerated > ago(W)
| summarize arg_max(TimeGenerated, *) by RecommendedRuleName, RecommendedAction, RuleScope, L4Protocol, DestPortsRanges
| project TimeGenerated, RecommendedAction, RecommendedRuleName, RuleScope, L4Protocol, DestPortsRanges, PortCategory,
          SrcPublicIpCidrs, DestPublicIpCidrs, SrcServiceTagsList, DestServiceTagsList, SrcSubscriptionId, DestSubscriptionId
| top 5000 by TimeGenerated"
  : > "$TMP/recos_raw.json"
  OLDIFS=$IFS; IFS=','
  for WS in $WORKSPACE_ID; do
    IFS=$OLDIFS
    WS=$(printf '%s' "$WS" | tr -d '[:space:]')
    [ -z "$WS" ] && continue
    if az monitor log-analytics query -w "$WS" --analytics-query "$RECOKQL" -o json > "$TMP/reco.json" 2>/dev/null; then
      jq -c '.[]' "$TMP/reco.json" >> "$TMP/recos_raw.json" 2>/dev/null || true
    fi
    IFS=','
  done
  IFS=$OLDIFS
  jq -s '.' "$TMP/recos_raw.json" > "$TMP/recos.json" 2>/dev/null || echo "[]" > "$TMP/recos.json"
  echo "    $(jq 'length' "$TMP/recos.json") rule recommendations (Allow / Block / Advisory)"
else
  echo "    skipped (set WORKSPACE_ID to one or more Log Analytics workspace GUIDs, comma-separated)"
  echo "[]" > "$TMP/fwlogs.json"
  echo "[]" > "$TMP/recos.json"
fi
[ -f "$TMP/fwlogs.json" ] || echo "[]" > "$TMP/fwlogs.json"
[ -f "$TMP/recos.json" ] || echo "[]" > "$TMP/recos.json"

echo "[5/6] Subscription names + inventory..."
az account list --all --query "[].{subscriptionId:id,name:name}" -o json > "$TMP/subs.json" || echo "[]" > "$TMP/subs.json"
echo "    $(jq 'length' "$TMP/subs.json") subscriptions"
if [ -n "${ALL_RESOURCES:-}" ]; then
  echo "    full inventory scan (every resource of every type)..."
  INVQ="Resources | project id, name, type"
  SKIP=0
  while : ; do
    az graph query -q "$INVQ" --first 1000 --skip "$SKIP" -o json > "$TMP/invpage.json"
    ICOUNT=$(jq '.data | length' "$TMP/invpage.json")
    jq -s '.[0] + .[1].data' "$TMP/topo.json" "$TMP/invpage.json" > "$TMP/topo2.json" && mv "$TMP/topo2.json" "$TMP/topo.json"
    [ "$ICOUNT" -lt 1000 ] && break
    SKIP=$((SKIP + 1000))
  done
  TOTAL=$(jq 'length' "$TMP/topo.json")
  echo "    inventory merged (total: $TOTAL)"
fi

# Optional: ./maps/sites.json maps your on-prem CIDRs to names, e.g.
#   [{"name":"Reston DC","cidr":"10.200.0.0/16"}]
# (the container runs with ./maps as its working directory)
if [ -f sites.json ]; then cp sites.json "$TMP/sites.json"; else echo "[]" > "$TMP/sites.json"; fi

echo "[6/6] Network metrics (SNAT, throughput, health, hybrid links)..."
echo "[]" > "$TMP/metrics.json"
if [ -n "${METRICS:-}" ]; then
  # Types that emit network-relevant metrics. NSGs and route tables emit none.
  MTYPES="'microsoft.network/azurefirewalls','microsoft.network/loadbalancers','microsoft.network/applicationgateways','microsoft.network/natgateways','microsoft.network/virtualnetworkgateways','microsoft.network/expressroutecircuits','microsoft.network/publicipaddresses','microsoft.network/privateendpoints','microsoft.network/connections','microsoft.compute/virtualmachines','microsoft.compute/virtualmachinescalesets'"

  az graph query -q "Resources | where type in~ ($MTYPES) | project id, type, location, subscriptionId" --first 1000 -o json \
    | jq -r '.data[] | [.subscriptionId,.location,(.type|ascii_downcase),.id] | @tsv' > "$TMP/mres.tsv" || true

  # What we WANT. The script intersects this with what Azure says each type actually
  # supports, so a wrong or renamed metric can never fail the whole batch call.
  wishlist_for() {
    case "$1" in
      microsoft.network/azurefirewalls)
        printf '%s\n' "SNATPortUtilization" "FirewallHealth" "FirewallLatencyPng" "Throughput" "DataProcessed" "ObservedCapacity";;
      microsoft.network/loadbalancers)
        printf '%s\n' "UsedSnatPorts" "AllocatedSnatPorts" "SnatConnectionCount" "DipAvailability" "VipAvailability" "ByteCount" "PacketCount";;
      microsoft.network/applicationgateways)
        printf '%s\n' "UnhealthyHostCount" "HealthyHostCount" "Throughput" "FailedRequests" "ComputeUnits" "BackendConnectTime";;
      microsoft.network/natgateways)
        printf '%s\n' "SNATConnectionCount" "TotalConnectionCount" "PacketDropCount" "DatapathAvailability" "ByteCount";;
      microsoft.network/virtualnetworkgateways)
        printf '%s\n' "TunnelIngressBytes" "TunnelEgressBytes" "TunnelTotalFlowCount" "BgpPeerStatus" "TunnelPeakPackets";;
      microsoft.network/expressroutecircuits)
        printf '%s\n' "BgpAvailability" "ArpAvailability" "BitsInPerSecond" "BitsOutPerSecond";;
      microsoft.network/publicipaddresses)
        printf '%s\n' "ByteCount" "PacketCount" "BytesDroppedDDoS" "IfUnderDDoSAttack";;
      microsoft.network/privateendpoints)
        printf '%s\n' "PEBytesIn" "PEBytesOut";;
      microsoft.network/connections)
        printf '%s\n' "TunnelAverageBandwidth" "TunnelEgressBytes" "TunnelIngressBytes";;
      microsoft.compute/virtualmachines|microsoft.compute/virtualmachinescalesets)
        printf '%s\n' "Percentage CPU" "Network In Total" "Network Out Total";;
      *) echo "";;
    esac
  }

  : > "$TMP/metrics_raw.json"
  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  AGO=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

  cut -f1-3 "$TMP/mres.tsv" | sort -u | while IFS=$'\t' read -r sub loc rtype; do
    [ -z "$sub" ] && continue
    WISH=$(wishlist_for "$rtype"); [ -z "$WISH" ] && continue

    SAMPLE=$(awk -F'\t' -v s="$sub" -v l="$loc" -v t="$rtype" '$1==s && $2==l && $3==t {print $4; exit}' "$TMP/mres.tsv")
    [ -z "$SAMPLE" ] && continue

    # Ask Azure which metrics this type really supports, then keep only wished-for ones.
    AVAIL=$(az monitor metrics list-definitions --resource "$SAMPLE" --query "[].name.value" -o tsv 2>/dev/null)
    [ -z "$AVAIL" ] && { echo "    no metric definitions for $rtype (skipping)"; continue; }

    # Match the wishlist (newline-delimited, may contain spaces) against what exists.
    NAMES=""
    while IFS= read -r want; do
      [ -z "$want" ] && continue
      HIT=$(printf '%s\n' "$AVAIL" | grep -ixF "$want" | head -1 || true)
      [ -n "$HIT" ] && NAMES="${NAMES:+$NAMES,}$HIT"
    done <<< "$WISH"
    [ -z "$NAMES" ] && { echo "    none of the wanted metrics exist on $rtype"; continue; }

    awk -F'\t' -v s="$sub" -v l="$loc" -v t="$rtype" '$1==s && $2==l && $3==t {print $4}' "$TMP/mres.tsv" | split -l 50 - "$TMP/batch_"
    for f in "$TMP"/batch_*; do
      [ -f "$f" ] || continue
      IDS=$(jq -R -s -c 'split("\n")|map(select(length>0))' < "$f")
      ENC_NAMES=$(printf '%s' "$NAMES" | sed 's/ /%20/g')
      URL="https://${loc}.metrics.monitor.azure.com/subscriptions/${sub}/metrics:getBatch?metricnamespace=${rtype}&api-version=2023-10-01&interval=PT1H&aggregation=average,maximum&timespan=${AGO}/${NOW}&metricnames=${ENC_NAMES}"
      az rest --method post --url "$URL" --resource "https://metrics.monitor.azure.com" \
        --headers "Content-Type=application/json" --body "{\"resourceids\":${IDS}}" -o json 2>/dev/null \
        | jq -c '.values[]? | .resourceid as $rid | .value[]? | {resourceId:$rid, metric:.name.value, unit:.unit,
            avg:([.timeseries[]?.data[]?.average // empty] | if length>0 then (add/length) else null end),
            max:([.timeseries[]?.data[]?.maximum // empty] | if length>0 then max else null end)}' >> "$TMP/metrics_raw.json" || true
      rm -f "$f"
    done
    echo "    $rtype ($loc): $NAMES"
  done
  jq -s '.' "$TMP/metrics_raw.json" > "$TMP/metrics.json" 2>/dev/null || echo "[]" > "$TMP/metrics.json"
  echo "    $(jq 'length' "$TMP/metrics.json") metric series collected"
else
  echo "    skipped (set METRICS=1; needs the Monitoring Reader role)"
fi

# The tool otherwise reads AUTHORED user-defined routes. The EFFECTIVE route table — UDRs,
# BGP-learned and system routes as Azure actually applies them — is only available per-NIC
# via Network Watcher, so it is opt-in (one call per NIC). This closes the "reads UDRs, not
# the effective route table" caveat when enabled.
echo "[6b/6] Effective routes (per NIC, Network Watcher)..."
echo "[]" > "$TMP/effroutes.json"
if [ -n "${EFFECTIVE_ROUTES:-}" ]; then
  : > "$TMP/effroutes_raw.json"
  jq -r '.[] | select((.type|ascii_downcase)=="microsoft.network/networkinterfaces") | .id' "$TMP/topo.json" \
  | while read -r NICID; do
      [ -z "$NICID" ] && continue
      az network nic show-effective-route-table --ids "$NICID" -o json 2>/dev/null \
        | jq -c --arg nic "$NICID" '{nicId:$nic, routes:[.value[]? | {prefix:((.addressPrefix // [])[0] // ""), nextHopType:.nextHopType, nextHopIp:((.nextHopIpAddress // [])[0] // ""), source:.source, state:.state}]}' \
        >> "$TMP/effroutes_raw.json" 2>/dev/null || true
    done
  jq -s '[.[] | select(.routes | length > 0)]' "$TMP/effroutes_raw.json" > "$TMP/effroutes.json" 2>/dev/null || echo "[]" > "$TMP/effroutes.json"
  echo "    $(jq 'length' "$TMP/effroutes.json") NIC effective-route tables"
else
  echo "    skipped (set EFFECTIVE_ROUTES=1; one Network Watcher call per NIC, needs Reader on the NICs)"
fi
[ -f "$TMP/effroutes.json" ] || echo "[]" > "$TMP/effroutes.json"

jq -n \
  --slurpfile t "$TMP/topo.json" \
  --slurpfile d "$TMP/dns.json" \
  --slurpfile f "$TMP/flows.json" \
  --slurpfile s "$TMP/subs.json" \
  --slurpfile st "$TMP/sites.json" \
  --slurpfile mt "$TMP/metrics.json" \
  --slurpfile fw "$TMP/fwlogs.json" \
  --slurpfile rc "$TMP/recos.json" \
  --slurpfile er "$TMP/effroutes.json" \
  --arg scanned "$STAMP" --arg scannedIso "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{topology:$t[0], dns:$d[0], flows:$f[0], subs:$s[0], sites:$st[0], metrics:$mt[0], fwlogs:$fw[0], recos:$rc[0], effectiveRoutes:$er[0], scanned:$scanned, scannedIso:$scannedIso}' > "$TMP/embed.json"

python3 - "$TEMPLATE" "$TMP/embed.json" "$OUT" << 'PYEOF'
import sys, json
template, embed, out = sys.argv[1], sys.argv[2], sys.argv[3]
html = open(template, encoding="utf-8").read()
data = open(embed, encoding="utf-8").read()
marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
if marker not in html:
    sys.exit("ERROR: embed marker not found in template — is this the right azure-net-map.html?")
html = html.replace(marker, "const EMBEDDED=" + data + ";")
open(out, "w", encoding="utf-8").write(html)
PYEOF

echo ""
echo "Done: $OUT  ($TOTAL resources, $DNSN DNS record sets)"
echo "Open it in any browser. Rerun this script any time for a fresh scan."
