#!/usr/bin/env python3
"""Demo fixture showing external / public connections the fixed KQL now recovers:
 - inbound Cloudflare WAF traffic (ExternalPublic, Cloudflare-owned source IP),
 - outbound to an Azure service tag (AzurePublic, DestServiceTags = Storage.CentralUS),
 - outbound to a generic external IP carrying only a country.
Rows are shaped exactly like the patched generate-netmap.sh output (public address
already lifted into SrcIp/DestIp, plus Src/DestServiceTags and Country). Injected
through the real //__NETMAP_EMBED__ marker."""
import json, datetime

SUB = "aaaa1111-1111-1111-1111-111111111111"
RG  = "web-prod-centralus"

def rid(provider, name):
    return f"/subscriptions/{SUB}/resourcegroups/{RG}/providers/{provider}/{name}".lower()

VNET = rid("microsoft.network/virtualnetworks", "web-prod-centralus-vnet")
SN   = VNET + "/subnets/web-prod-cus"

def nic(name, ip):
    return {"id": rid("microsoft.network/networkinterfaces", name),
            "name": name, "type": "microsoft.network/networkinterfaces",
            "properties": {"ipConfigurations": [
                {"properties": {"privateIPAddress": ip, "subnet": {"id": SN}}}]}}

topology = [
    {"id": VNET, "name": "web-prod-centralus-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["10.20.0.0/16"]},
                    "subnets": [{"id": SN, "name": "web-prod-cus",
                                 "properties": {"addressPrefix": "10.20.0.0/24"}}]}},
    nic("azh1web01-nic", "10.20.0.10"),
    nic("azh1web02-nic", "10.20.0.11"),
    nic("azh1api01-nic", "10.20.0.20"),
]

now = datetime.datetime.now(datetime.timezone.utc)
bkt = (now - datetime.timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")

def flow(src, dst, port, status, count, ftype, rule="", grp="",
         bo=0, bi=0, src_tags="", dst_tags="", country=""):
    return {"Bucket": bkt, "SrcIp": src, "DestIp": dst, "DestPort": port, "L4Protocol": "T",
            "FlowStatus": status, "Flows": count, "BytesSrcToDest": bo, "BytesDestToSrc": bi,
            "AclRule": rule, "AclGroup": grp, "FlowType": ftype,
            "SrcServiceTags": src_tags, "DestServiceTags": dst_tags, "Country": country}

flows = [
    # Inbound Cloudflare WAF → web tier (Cloudflare-owned source IPs, ExternalPublic).
    flow("104.16.5.20", "10.20.0.10", 443, "Allowed", 4200, "ExternalPublic",
         rule="allow-https-in", grp="web-nsg", bo=8_000_000, bi=920_000_000, country="US"),
    flow("172.64.32.9", "10.20.0.11", 443, "Allowed", 3600, "ExternalPublic",
         rule="allow-https-in", grp="web-nsg", bo=6_500_000, bi=740_000_000, country="US"),
    # A Cloudflare source that an NSG denied (shows a red/denied external edge).
    flow("162.158.10.5", "10.20.0.20", 8080, "Denied", 22, "ExternalPublic",
         rule="deny-nonstd-in", grp="web-nsg", country="US"),
    # Outbound to Azure Storage (AzurePublic) — Azure tags the owner.
    flow("10.20.0.20", "20.60.40.8", 443, "Allowed", 1800, "AzurePublic",
         rule="allow-storage", grp="web-nsg", bo=210_000_000, bi=9_000_000,
         dst_tags="20.60.40.0/22 | Storage.CentralUS"),
    # Outbound to Azure Front Door backend (AzurePublic, another service tag).
    flow("10.20.0.10", "13.107.213.40", 443, "Allowed", 640, "AzurePublic",
         rule="allow-afd", grp="web-nsg", bo=30_000_000, bi=120_000_000,
         dst_tags="13.107.213.0/24 | AzureFrontDoor.Backend"),
    # Outbound to a generic external endpoint carrying only a country (no provider match).
    flow("10.20.0.20", "203.0.113.50", 443, "Allowed", 120, "ExternalPublic",
         rule="allow-out", grp="web-nsg", bo=5_000_000, bi=40_000_000, country="GB"),
    # A little internal traffic so the estate is not purely external.
    flow("10.20.0.10", "10.20.0.20", 8443, "Allowed", 900, "IntraVNet",
         rule="allow-app", grp="web-nsg", bo=40_000_000, bi=60_000_000),
]

payload = {
    "topology": topology, "dns": [], "flows": flows,
    "subs": [{"subscriptionId": SUB, "name": "web Prod"}],
    "sites": [], "metrics": [], "fwlogs": [],
    "scanned": now.strftime("%Y-%m-%d_%H%M"), "scannedIso": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
}

marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
html = open("azure-net-map.html", encoding="utf-8").read()
assert html.count(marker) == 1, "embed marker missing or duplicated"
html = html.replace(marker, "const EMBEDDED=" + json.dumps(payload) + ";")
open("ext-scan.html", "w", encoding="utf-8").write(html)
print("wrote ext-scan.html:", len(topology), "topology items,", len(flows),
      "flows (Cloudflare in, Storage/AFD out, external country)")
