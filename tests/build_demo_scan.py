#!/usr/bin/env python3
"""Comprehensive demo scan that exercises every tab at once, so the tool can be
evaluated end to end: the rich fix-scan estate (NSG / AVNM / firewall rules, a
blackhole route, a load balancer) PLUS external connections (inbound Cloudflare
WAF by IP, a DNS hostname CNAME'd to cdn.cloudflare.net, outbound Azure service
tags), metric-driven health (SNAT exhaustion, unhealthy backend), and an orphan.
Built by augmenting the fix-scan payload, then re-embedded through the real
//__NETMAP_EMBED__ marker."""
import json, re, subprocess, sys, os, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
subprocess.run([sys.executable, os.path.join(HERE, "build_fix_scan.py")], check=True,
               stdout=subprocess.DEVNULL)

p = json.loads(re.search(r'const EMBEDDED=(\{.*?\});',
                         open("fix-scan.html", encoding="utf-8").read(), re.S).group(1))

def find(t):
    return next((x for x in p["topology"] if x["type"] == t), None)
lb = find("microsoft.network/loadbalancers")
fw = find("microsoft.network/azurefirewalls")
nic = find("microsoft.network/networkinterfaces")
web_ip = nic["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"]  # 172.22.52.70
sub_a = p["subs"][0]["subscriptionId"]

now = datetime.datetime.now(datetime.timezone.utc)
bkt = (now - datetime.timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")

def flow(src, dst, port, status, count, ftype, rule="", grp="", bo=0, bi=0,
         src_tags="", dst_tags="", country=""):
    return {"Bucket": bkt, "SrcIp": src, "DestIp": dst, "DestPort": port, "L4Protocol": "T",
            "FlowStatus": status, "Flows": count, "BytesSrcToDest": bo, "BytesDestToSrc": bi,
            "AclRule": rule, "AclGroup": grp, "FlowType": ftype,
            "SrcServiceTags": src_tags, "DestServiceTags": dst_tags, "Country": country}

# ---- external / public connections (what the fixed KQL now recovers) ----
p["flows"] += [
    flow("104.16.5.20", web_ip, 443, "Allowed", 5200, "ExternalPublic",
         rule="allow-https-in", grp="delinea-prod-rds-cus-nsg", bo=9_000_000, bi=1_200_000_000, country="US"),
    flow("162.158.10.5", web_ip, 8080, "Denied", 30, "ExternalPublic",
         rule="deny-nonstd-in", grp="delinea-prod-rds-cus-nsg", country="US"),
    flow(web_ip, "20.60.40.8", 443, "Allowed", 2100, "AzurePublic",
         rule="allow-storage", grp="delinea-prod-rds-cus-nsg", bo=260_000_000, bi=9_000_000,
         dst_tags="20.60.40.0/22 | Storage.CentralUS"),
    flow(web_ip, "13.107.213.40", 443, "Allowed", 700, "AzurePublic",
         rule="allow-afd", grp="delinea-prod-rds-cus-nsg", bo=31_000_000, bi=140_000_000,
         dst_tags="13.107.213.0/24 | AzureFrontDoor.Backend"),
]

# ---- DNS: a hostname proxied through Cloudflare, and a direct A record ----
p["dns"] = [
    {"name": "identity", "fqdn": "identity.dayforcenow.us.",
     "type": "Microsoft.Network/dnszones/CNAME",
     "properties": {"CNAMERecord": {"cname": "identity.dayforcenow.us.cdn.cloudflare.net."}}},
    {"name": "rds", "fqdn": "rds.dayforcenow.us.",
     "type": "Microsoft.Network/dnszones/A",
     "properties": {"ARecords": [{"ipv4Address": web_ip}]}},
]

# ---- metrics: SNAT exhaustion on the firewall, unhealthy backend on the LB ----
p["metrics"] = []
if fw:
    p["metrics"] += [
        {"resourceId": fw["id"], "metric": "SNATPortUtilization", "avg": 92, "max": 99, "unit": "%"},
        {"resourceId": fw["id"], "metric": "FirewallHealth", "avg": 96, "max": 96, "unit": "%"},
    ]
if lb:
    p["metrics"] += [
        {"resourceId": lb["id"], "metric": "UnhealthyHostCount", "avg": 1, "max": 2, "unit": "count"},
        {"resourceId": lb["id"], "metric": "DipAvailability", "avg": 55, "max": 60, "unit": "%"},
    ]

# ---- Azure's own rule recommendations (NTARuleRecommendation) ----
p["recos"] = [
    {"RecommendedAction": "Block", "RecommendedRuleName": "block-inbound-8080",
     "RuleScope": "VirtualNetwork", "L4Protocol": "TCP", "DestPortsRanges": "8080",
     "PortCategory": "NonStandard", "SrcPublicIpCidrs": "162.158.0.0/15",
     "DestPublicIpCidrs": "", "SrcServiceTagsList": "", "DestServiceTagsList": ""},
    {"RecommendedAction": "Allow", "RecommendedRuleName": "allow-https-cloudflare",
     "RuleScope": "VirtualNetwork", "L4Protocol": "TCP", "DestPortsRanges": "443",
     "PortCategory": "Web", "SrcPublicIpCidrs": "104.16.0.0/13", "DestPublicIpCidrs": "",
     "SrcServiceTagsList": "", "DestServiceTagsList": ""},
    {"RecommendedAction": "Advisory", "RecommendedRuleName": "review-storage-egress",
     "RuleScope": "SubscriptionId", "L4Protocol": "TCP", "DestPortsRanges": "443",
     "PortCategory": "Web", "SrcPublicIpCidrs": "", "DestPublicIpCidrs": "",
     "SrcServiceTagsList": "", "DestServiceTagsList": "20.60.40.0/22 | Storage.CentralUS"},
]

# ---- effective routes for the web NIC (UDR + BGP + system, as Azure applies them) ----
p["effectiveRoutes"] = [
    {"nicId": nic["id"], "routes": [
        {"prefix": "172.22.0.0/16", "nextHopType": "VnetLocal", "nextHopIp": "", "source": "Default"},
        {"prefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance", "nextHopIp": "172.22.0.4", "source": "User"},
        {"prefix": "172.30.0.0/16", "nextHopType": "None", "nextHopIp": "", "source": "User"},
        {"prefix": "10.0.0.0/8", "nextHopType": "VirtualNetworkGateway", "nextHopIp": "", "source": "VirtualNetworkGateway"},
    ]},
]

# ---- an orphaned, unassociated public IP (billable, attached to nothing) ----
p["topology"].append({
    "id": f"/subscriptions/{sub_a}/resourcegroups/iam101-delinea-prod-centralus/providers/microsoft.network/publicipaddresses/orphan-legacy-pip",
    "name": "orphan-legacy-pip", "type": "microsoft.network/publicipaddresses", "properties": {}})

marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
html = open("azure-net-map.html", encoding="utf-8").read()
assert html.count(marker) == 1, "embed marker missing or duplicated"
open("demo-scan.html", "w", encoding="utf-8").write(
    html.replace(marker, "const EMBEDDED=" + json.dumps(p) + ";"))
print(f"wrote demo-scan.html: {len(p['topology'])} resources, {len(p['flows'])} flows, "
      f"{len(p['metrics'])} metrics, {len(p['dns'])} DNS records")
