#!/usr/bin/env python3
"""Stress fixture for run_stress.py: one NIC (azh0stress00-nic-with-long-name) with
12 distinct source neighbours and 12 distinct destination neighbours, plus the subnet
it is attached to (which adds the 13th destination row). One source flow is denied by
an AVNM security admin rule so the deps view prints exactly one 'blocked at AVNM...'
note. Injected through the real //__NETMAP_EMBED__ marker, exactly like build_scan.py."""
import json, datetime

SUB = "cccc3333-3333-3333-3333-333333333333"   # stress subscription
RG  = "stress-prod-centralus"

def rid(provider, name):
    return f"/subscriptions/{SUB}/resourcegroups/{RG}/providers/{provider}/{name}".lower()

VNET = rid("microsoft.network/virtualnetworks", "stress-prod-centralus-vnet")
SN   = VNET + "/subnets/stress-prod-cus"

def nic(name, ip):
    return {"id": rid("microsoft.network/networkinterfaces", name),
            "name": name, "type": "microsoft.network/networkinterfaces",
            "properties": {"ipConfigurations": [
                {"properties": {"privateIPAddress": ip, "subnet": {"id": SN}}}]}}

CENTRAL = "azh0stress00-nic-with-long-name"
CENTRAL_IP = "10.44.0.10"

topology = [
    {"id": VNET, "name": "stress-prod-centralus-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["10.44.0.0/16"]},
                    "subnets": [{"id": SN, "name": "stress-prod-cus",
                                 "properties": {"addressPrefix": "10.44.0.0/20"}}]}},
    nic(CENTRAL, CENTRAL_IP),
]

# 12 sources -> central, 12 destinations <- central. Distinct IPs, realistic-length names.
src_ips, dst_ips = [], []
for i in range(1, 13):
    s = f"azh1src{i:02d}-app-centralus-nic"
    sip = f"10.44.1.{i}"
    topology.append(nic(s, sip)); src_ips.append(sip)
for i in range(1, 13):
    d = f"azh1dst{i:02d}-svc-centralus-nic"
    dip = f"10.44.2.{i}"
    topology.append(nic(d, dip)); dst_ips.append(dip)

now = datetime.datetime.now(datetime.timezone.utc)
bkt = (now - datetime.timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
AVNM_G = "rc-gusa-global-denies"
AVNM_R = "out-deny-unauthorized-spoke-to-spoke"

def flow(src, dst, port, proto, status, count, rule="", grp="", bo=0, bi=0):
    return {"Bucket": bkt, "SrcIp": src, "DestIp": dst, "DestPort": port, "L4Protocol": proto,
            "FlowStatus": status, "Flows": count, "BytesSrcToDest": bo, "BytesDestToSrc": bi,
            "AclRule": rule, "AclGroup": grp, "FlowType": "IntraVNet"}

flows = []
# 12 sources into the central NIC; the first one is denied by AVNM (the single note).
for k, sip in enumerate(src_ips):
    if k == 0:
        flows.append(flow(sip, CENTRAL_IP, 445, "T", "Denied", 7, AVNM_R, AVNM_G))
    else:
        flows.append(flow(sip, CENTRAL_IP, 443, "T", "Allowed", 20 + k, "allow-web", "", 1_000_000, 4_000_000))
# 12 destinations from the central NIC.
for k, dip in enumerate(dst_ips):
    flows.append(flow(CENTRAL_IP, dip, 443, "T", "Allowed", 10 + k, "allow-web", "", 800_000, 3_000_000))

payload = {
    "topology": topology, "dns": [], "flows": flows,
    "subs": [{"subscriptionId": SUB, "name": "stress Load Test"}],
    "sites": [], "metrics": [], "fwlogs": [],
    "scanned": now.strftime("%Y-%m-%d_%H%M"), "scannedIso": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
}

marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
html = open("azure-net-map.html", encoding="utf-8").read()
assert html.count(marker) == 1, "embed marker missing or duplicated"
html = html.replace(marker, "const EMBEDDED=" + json.dumps(payload) + ";")
open("stress-scan.html", "w", encoding="utf-8").write(html)
print("wrote stress-scan.html:", len(topology), "topology items,", len(flows),
      "flow rows (12 sources, 12+subnet destinations, 1 AVNM deny)")
