#!/usr/bin/env python3
"""Inject a synthetic scan payload into the patched template using the same marker
replacement generate-netmap.sh uses. Mirrors the user's screenshot: azh1delrds01-nic
with denied flows blocked by AVNM rule rc-gusa-global-denies /
out-deny-unauthorized-spoke-to-spoke, resources across two subscriptions and VNets."""
import json, datetime

SUB_A = "aaaa1111-1111-1111-1111-111111111111"   # iam101 Identity Management
SUB_B = "bbbb2222-2222-2222-2222-222222222222"   # guss101 Directory Services
RG_A  = "iam101-delinea-prod-centralus"
RG_B  = "guss101-dirsvcs-prod"

def rid(sub, rg, provider, name):
    return f"/subscriptions/{sub}/resourcegroups/{rg}/providers/{provider}/{name}".lower()

VNET_A = rid(SUB_A, RG_A, "microsoft.network/virtualnetworks", "iam101-cyber-prod-centralus-vnet")
SN_A   = VNET_A + "/subnets/delinea-prod-rds-cus"
VNET_B = rid(SUB_B, RG_B, "microsoft.network/virtualnetworks", "guss101-dirsvcs-prod-net-centralus-addc-vnet")
SN_B   = VNET_B + "/subnets/addc"
LB     = rid(SUB_A, RG_A, "microsoft.network/loadbalancers", "delinea-prod-rds-cus-ilb")

def nic(sub, rg, name, ip, subnet, pools=None):
    ipc = {"properties": {"privateIPAddress": ip, "subnet": {"id": subnet}}}
    if pools:
        ipc["properties"]["loadBalancerBackendAddressPools"] = [{"id": p + "/backendaddresspools/bep"} for p in pools]
    return {"id": rid(sub, rg, "microsoft.network/networkinterfaces", name),
            "name": name, "type": "microsoft.network/networkinterfaces",
            "properties": {"ipConfigurations": [ipc]}}

topology = [
    {"id": VNET_A, "name": "iam101-cyber-prod-centralus-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["172.22.52.0/24"]},
                    "subnets": [{"id": SN_A, "name": "delinea-prod-rds-cus",
                                 "properties": {"addressPrefix": "172.22.52.0/25"}}],
                    "virtualNetworkPeerings": [{"properties": {"remoteVirtualNetwork": {"id": VNET_B}}}]}},
    {"id": VNET_B, "name": "guss101-dirsvcs-prod-net-centralus-addc-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["172.22.2.0/24"]},
                    "subnets": [{"id": SN_B, "name": "addc",
                                 "properties": {"addressPrefix": "172.22.2.0/25"}}]}},
    {"id": LB, "name": "delinea-prod-rds-cus-ilb", "type": "microsoft.network/loadbalancers", "properties": {}},
    nic(SUB_A, RG_A, "azh1delrds01-nic",  "172.22.52.70", SN_A, pools=[LB]),
    nic(SUB_A, RG_A, "azh1delapp01-nic",  "172.22.52.68", SN_A),
    nic(SUB_A, RG_A, "delinea-rds-app",   "172.22.52.64", SN_A),
    nic(SUB_B, RG_B, "azh1dfgus1dc07-nic","172.22.2.8",  SN_B),
    nic(SUB_B, RG_B, "azh1dfgus1dc08-nic","172.22.2.6",  SN_B),
    {"id": rid(SUB_A, RG_A, "microsoft.network/publicipaddresses", "orphan-test-pip"),
     "name": "orphan-test-pip", "type": "microsoft.network/publicipaddresses", "properties": {}},
]

now = datetime.datetime.now(datetime.timezone.utc)
bkt = (now - datetime.timedelta(minutes=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
AVNM_G = "rc-gusa-global-denies"
AVNM_R = "out-deny-unauthorized-spoke-to-spoke"
NSG_G  = f"{SUB_B}/{RG_B}/guss101-dirsvcs-prod-net-centralus-addc-nsg"
NSG_R  = "nsgsr-deny-rfc1918-to-vnet-inbound"

def flow(src, dst, port, proto, status, count, rule="", grp="", bo=0, bi=0):
    return {"Bucket": bkt, "SrcIp": src, "DestIp": dst, "DestPort": port, "L4Protocol": proto,
            "FlowStatus": status, "Flows": count, "BytesSrcToDest": bo, "BytesDestToSrc": bi,
            "AclRule": rule, "AclGroup": grp, "FlowType": "IntraVNet"}

flows = [
    flow("172.22.52.68", "172.22.52.70", 137, "U", "Denied", 23, AVNM_R, AVNM_G),
    flow("172.22.52.68", "172.22.52.70", 5671, "T", "Denied", 24, AVNM_R, AVNM_G),
    flow("172.20.52.235", "172.22.52.70", 3389, "T", "Denied", 1, NSG_R, NSG_G),
    flow("172.22.52.70", "172.22.2.8", 123, "U", "Denied", 2, NSG_R, NSG_G),
    flow("172.22.52.70", "172.22.2.6", 389, "T", "Denied", 2, NSG_R, NSG_G),
    flow("172.22.52.70", "172.22.52.68", 137, "U", "Denied", 12, AVNM_R, AVNM_G),
    flow("172.22.52.70", "172.22.52.64", 443, "T", "Allowed", 98, "allow-web", NSG_G, 5_000_000, 42_000_000),
    flow("172.22.52.70", "172.22.52.68", 443, "T", "Allowed", 33, "allow-web", NSG_G, 900_000, 4_000_000),
    flow("172.22.52.64", "172.22.2.8", 636, "T", "Allowed", 15, "allow-ldaps", NSG_G, 120_000, 340_000),
]

payload = {
    "topology": topology, "dns": [], "flows": flows,
    "subs": [{"subscriptionId": SUB_A, "name": "iam101 Identity Management"},
             {"subscriptionId": SUB_B, "name": "guss101 Directory Services"}],
    "sites": [], "metrics": [], "fwlogs": [],
    "scanned": now.strftime("%Y-%m-%d_%H%M"), "scannedIso": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
}

marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
html = open("azure-net-map.html", encoding="utf-8").read()
assert html.count(marker) == 1, "embed marker missing or duplicated"
html = html.replace(marker, "const EMBEDDED=" + json.dumps(payload) + ";")
open("scan-under-test.html", "w", encoding="utf-8").write(html)
print("wrote scan-under-test.html:", len(topology), "topology items,", len(flows), "flow rows")
