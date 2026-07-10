#!/usr/bin/env python3
"""Dense-mesh fixture for run_fix_tests.py (the Untangle / label-collision check).
63 NICs in one subnet wired into a dense mesh of flows, so at default spread the
overview labels pile up and the 'Untangle' spread level can measurably thin them.
Written as hairball-new.html through the real //__NETMAP_EMBED__ marker."""
import json, datetime

SUB = "dddd4444-4444-4444-4444-444444444444"   # mesh subscription
RG  = "mesh-prod-centralus"
N   = 63

def rid(provider, name):
    return f"/subscriptions/{SUB}/resourcegroups/{RG}/providers/{provider}/{name}".lower()

VNET = rid("microsoft.network/virtualnetworks", "mesh-prod-centralus-vnet")
SN   = VNET + "/subnets/mesh-prod-cus"

def nic(name, ip):
    return {"id": rid("microsoft.network/networkinterfaces", name),
            "name": name, "type": "microsoft.network/networkinterfaces",
            "properties": {"ipConfigurations": [
                {"properties": {"privateIPAddress": ip, "subnet": {"id": SN}}}]}}

topology = [
    {"id": VNET, "name": "mesh-prod-centralus-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["10.60.0.0/16"]},
                    "subnets": [{"id": SN, "name": "mesh-prod-cus",
                                 "properties": {"addressPrefix": "10.60.0.0/20"}}]}},
]

ips = []
for i in range(N):
    name = f"azmesh{i:02d}-node-centralus-nic"
    ip = f"10.60.{i // 254}.{(i % 254) + 1}"
    topology.append(nic(name, ip)); ips.append(ip)

now = datetime.datetime.now(datetime.timezone.utc)
bkt = (now - datetime.timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")

def flow(src, dst, port, count):
    return {"Bucket": bkt, "SrcIp": src, "DestIp": dst, "DestPort": port, "L4Protocol": "T",
            "FlowStatus": "Allowed", "Flows": count, "BytesSrcToDest": 500_000,
            "BytesDestToSrc": 1_500_000, "AclRule": "allow-mesh", "AclGroup": "",
            "FlowType": "IntraVNet"}

# Ring + chords: every node connects to its +1, +7, and +19 neighbours (mod N).
# This keeps all 63 nodes in one connected, visually dense component.
flows = []
for i in range(N):
    for step in (1, 7, 19):
        j = (i + step) % N
        flows.append(flow(ips[i], ips[j], 443, 5 + (i + step) % 11))

payload = {
    "topology": topology, "dns": [], "flows": flows,
    "subs": [{"subscriptionId": SUB, "name": "mesh Dense Test"}],
    "sites": [], "metrics": [], "fwlogs": [],
    "scanned": now.strftime("%Y-%m-%d_%H%M"), "scannedIso": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
}

marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
html = open("azure-net-map.html", encoding="utf-8").read()
assert html.count(marker) == 1, "embed marker missing or duplicated"
html = html.replace(marker, "const EMBEDDED=" + json.dumps(payload) + ";")
open("hairball-new.html", "w", encoding="utf-8").write(html)
print("wrote hairball-new.html:", N, "NICs,", len(flows), "mesh flows")
