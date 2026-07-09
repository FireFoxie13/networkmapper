#!/usr/bin/env python3
"""Scan with real AVNM admin rules, NSG rules and a blackhole route table, so the
remediation engine has to resolve genuine owners, names and priorities.
Mirrors the GUSA shape: AVNM rc-gusa-global-denies blocks spoke-to-spoke,
the addc NSG blocks RFC1918 inbound, and a UDR blackholes a legacy prefix."""
import json, datetime

SUB_A = "aaaa1111-1111-1111-1111-111111111111"
SUB_B = "bbbb2222-2222-2222-2222-222222222222"
RG_A  = "iam101-delinea-prod-centralus"
RG_B  = "guss101-dirsvcs-prod"
RG_NM = "guss101-avnm-prod"

def rid(sub, rg, prov, name):
    return f"/subscriptions/{sub}/resourcegroups/{rg}/providers/{prov}/{name}".lower()

RG_FW  = "gusa-hub-prod"

VNET_A = rid(SUB_A, RG_A, "microsoft.network/virtualnetworks", "iam101-cyber-prod-centralus-vnet")
SN_A   = VNET_A + "/subnets/delinea-prod-rds-cus"
VNET_B = rid(SUB_B, RG_B, "microsoft.network/virtualnetworks", "guss101-dirsvcs-prod-net-centralus-addc-vnet")
SN_B   = VNET_B + "/subnets/addc"
NSG_B  = rid(SUB_B, RG_B, "microsoft.network/networksecuritygroups", "guss101-dirsvcs-prod-net-centralus-addc-nsg")
NSG_A  = rid(SUB_A, RG_A, "microsoft.network/networksecuritygroups", "delinea-prod-rds-cus-nsg")
LB_A   = rid(SUB_A, RG_A, "microsoft.network/loadbalancers", "delinea-prod-rds-cus-ilb")
RT_A   = rid(SUB_A, RG_A, "microsoft.network/routetables", "iam101-delinea-prod-rt")
NM     = rid(SUB_B, RG_NM, "microsoft.network/networkmanagers", "gusa-avnm-prod")
RC     = NM + "/securityadminconfigurations/gusa-global/rulecollections/rc-gusa-global-denies"
FW     = rid(SUB_B, RG_FW, "microsoft.network/azurefirewalls", "gusa-hub-fw")
FWPOL  = rid(SUB_B, RG_FW, "microsoft.network/firewallpolicies", "gusa-hub-fwpolicy")
FWRCG  = FWPOL + "/rulecollectiongroups/gusa-default-rcg"

def nic(sub, rg, name, ip, subnet, pool=None):
    ipc = {"properties": {"privateIPAddress": ip, "subnet": {"id": subnet}}}
    if pool: ipc["properties"]["loadBalancerBackendAddressPools"] = [{"id": pool + "/backendaddresspools/bep"}]
    return {"id": rid(sub, rg, "microsoft.network/networkinterfaces", name), "name": name,
            "type": "microsoft.network/networkinterfaces",
            "properties": {"ipConfigurations": [ipc]}}

topology = [
    {"id": VNET_A, "name": "iam101-cyber-prod-centralus-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["172.22.52.0/24"]},
                    "subnets": [{"id": SN_A, "name": "delinea-prod-rds-cus",
                                 "properties": {"addressPrefix": "172.22.52.64/27", "routeTable": {"id": RT_A},
                                                "networkSecurityGroup": {"id": NSG_A}}}]}},
    {"id": VNET_B, "name": "guss101-dirsvcs-prod-net-centralus-addc-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["172.22.2.0/24"]},
                    "subnets": [{"id": SN_B, "name": "addc",
                                 "properties": {"addressPrefix": "172.22.2.0/25",
                                                "networkSecurityGroup": {"id": NSG_B}}}]}},
    # The NSG that blocks RFC1918 inbound to the DCs
    {"id": NSG_B, "name": "guss101-dirsvcs-prod-net-centralus-addc-nsg",
     "type": "microsoft.network/networksecuritygroups",
     "properties": {"securityRules": [
        {"name": "allow-ldaps-from-sanctioned", "properties": {"priority": 900, "direction": "Inbound",
            "access": "Allow", "protocol": "Tcp", "destinationPortRange": "636",
            "sourceAddressPrefix": "172.22.60.0/24", "destinationAddressPrefix": "172.22.2.0/25"}},
        {"name": "nsgsr-deny-rfc1918-to-vnet-inbound", "properties": {"priority": 980, "direction": "Inbound",
            "access": "Deny", "protocol": "*", "destinationPortRange": "*",
            "sourceAddressPrefixes": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "destinationAddressPrefix": "172.22.2.0/25"}},
     ]}},
    # Route table with a blackhole for a legacy prefix
    {"id": RT_A, "name": "iam101-delinea-prod-rt", "type": "microsoft.network/routetables",
     "properties": {"routes": [
        {"name": "kill-legacy-dmz", "properties": {"addressPrefix": "172.30.0.0/16", "nextHopType": "None"}},
        {"name": "to-hub-fw", "properties": {"addressPrefix": "0.0.0.0/0",
            "nextHopType": "VirtualAppliance", "nextHopIpAddress": "172.22.0.4"}},
     ]}},
    # AVNM security admin rule collection with the global deny
    {"id": RC, "name": "rc-gusa-global-denies",
     "type": "microsoft.network/networkmanagers/securityadminconfigurations/rulecollections",
     "properties": {"rules": [
        {"name": "in-deny-unauthorized-spoke-to-spoke", "properties": {"priority": 3090, "direction": "Inbound",
            "access": "Deny", "protocol": "Any", "destinationPortRanges": ["0-65535"],
            "sources": [{"addressPrefix": "172.16.0.0/13"}], "destinations": [{"addressPrefix": "172.16.0.0/13"}]}},
        {"name": "out-deny-unauthorized-spoke-to-spoke", "properties": {"priority": 3091, "direction": "Outbound",
            "access": "Deny", "protocol": "Any", "destinationPortRanges": ["0-65535"],
            "sources": [{"addressPrefix": "172.16.0.0/13"}], "destinations": [{"addressPrefix": "172.16.0.0/13"}]}},
     ]}},
    # Azure Firewall + policy + a rule collection group with a deny collection
    {"id": FW, "name": "gusa-hub-fw", "type": "microsoft.network/azurefirewalls",
     "properties": {"firewallPolicy": {"id": FWPOL}}},
    {"id": FWPOL, "name": "gusa-hub-fwpolicy", "type": "microsoft.network/firewallpolicies",
     "properties": {"threatIntelMode": "Deny"}},
    {"id": FWRCG, "name": "gusa-default-rcg",
     "type": "microsoft.network/firewallpolicies/rulecollectiongroups",
     "properties": {"priority": 200, "ruleCollections": [
        {"name": "sanctioned-egress", "priority": 300, "action": {"type": "Allow"},
         "rules": [{"name": "allow-updates", "ipProtocols": ["TCP"],
                    "sourceAddresses": ["172.22.52.0/24"], "destinationAddresses": ["10.60.0.0/16"],
                    "destinationPorts": ["443"]}]},
        {"name": "block-legacy", "priority": 400, "action": {"type": "Deny"},
         "rules": [{"name": "deny-smb-egress", "ipProtocols": ["TCP"],
                    "sourceAddresses": ["172.16.0.0/12"], "destinationAddresses": ["10.70.0.0/16"],
                    "destinationPorts": ["445"]}]},
     ]}},
    {"id": NSG_A, "name": "delinea-prod-rds-cus-nsg", "type": "microsoft.network/networksecuritygroups",
     "properties": {"securityRules": [
        {"name": "allow-https-out", "properties": {"priority": 200, "direction": "Outbound",
            "access": "Allow", "protocol": "Tcp", "destinationPortRange": "443",
            "sourceAddressPrefix": "172.22.52.64/27", "destinationAddressPrefix": "*"}},
        {"name": "deny-ntp-out", "properties": {"priority": 300, "direction": "Outbound",
            "access": "Deny", "protocol": "Udp", "destinationPortRange": "123",
            "sourceAddressPrefix": "172.22.52.64/27", "destinationAddressPrefix": "*"}},
     ]}},
    {"id": LB_A, "name": "delinea-prod-rds-cus-ilb", "type": "microsoft.network/loadbalancers",
     "properties": {"backendAddressPools": [{"name": "bep", "properties": {"backendIPConfigurations": [
            {"id": rid(SUB_A, RG_A, "microsoft.network/networkinterfaces", "azh1delrds01-nic")+"/ipconfigurations/ipconfig1"}]}}],
                    "probes": [{"name": "tcp-3389", "properties": {"protocol": "Tcp", "port": 3389}}]}},
    nic(SUB_A, RG_A, "azh1delrds01-nic",   "172.22.52.70", SN_A, pool=LB_A),
    nic(SUB_A, RG_A, "azh1delapp01-nic",   "172.22.52.68", SN_A),
    nic(SUB_B, RG_B, "azh1dfgus1dc07-nic", "172.22.2.8",   SN_B),
]

now = datetime.datetime.now(datetime.timezone.utc)
bkt = (now - datetime.timedelta(minutes=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
NSG_G = f"{SUB_B}/{RG_B}/guss101-dirsvcs-prod-net-centralus-addc-nsg"

def flow(src, dst, port, proto, status, cnt, rule="", grp="", bo=0, bi=0):
    return {"Bucket": bkt, "SrcIp": src, "DestIp": dst, "DestPort": port, "L4Protocol": proto,
            "FlowStatus": status, "Flows": cnt, "BytesSrcToDest": bo, "BytesDestToSrc": bi,
            "AclRule": rule, "AclGroup": grp, "FlowType": "IntraVNet"}

flows = [
    # AVNM deny: AMQP between two Delinea components
    flow("172.22.52.68", "172.22.52.70", 5671, "T", "Denied", 24,
         "out-deny-unauthorized-spoke-to-spoke", "rc-gusa-global-denies"),
    # NSG deny: NTP to a domain controller (the legitimate-traffic case)
    flow("172.22.52.70", "172.22.2.8", 123, "U", "Denied", 2,
         "nsgsr-deny-rfc1918-to-vnet-inbound", NSG_G),
    # allowed, plus an allowed flow into the blackholed prefix (becomes a route drop)
    flow("172.22.52.70", "172.30.4.4", 443, "T", "Allowed", 40, "allow-web", NSG_G, 90000, 0),
    flow("172.22.52.70", "172.22.52.68", 443, "T", "Allowed", 98, "allow-web", NSG_G, 5_000_000, 42_000_000),
    # firewall cases: a network-rule deny, an application-rule deny, a threat-intel block
    flow("172.22.52.70", "10.70.5.5", 445, "T", "Allowed", 6, "", "", 4000, 0),
    flow("172.22.52.70", "10.80.1.1", 443, "T", "Allowed", 3, "", "", 2000, 0),
    flow("172.22.52.70", "10.90.9.9", 443, "T", "Allowed", 1, "", "", 500, 0),
]

def fwlog(src, dst, port, action, rule, coll, grp, table, reason=""):
    return {"Bucket": bkt, "SourceIp": src, "Dest": dst, "DestinationPort": port, "Protocol": "TCP",
            "Action": action, "ActionReason": reason, "Rule": rule, "RuleCollection": coll,
            "RuleCollectionGroup": grp, "Policy": "gusa-hub-fwpolicy", "RuleType": table, "Hits": 6}

fwlogs = [
    fwlog("172.22.52.70", "10.70.5.5", 445, "Deny", "deny-smb-egress", "block-legacy",
          "gusa-default-rcg", "AZFWNetworkRule"),
    fwlog("172.22.52.70", "updates.contoso-legacy.com", 443, "Deny", "deny-unsanctioned-fqdn", "block-web",
          "gusa-default-rcg", "AZFWApplicationRule"),
    fwlog("172.22.52.70", "10.90.9.9", 443, "Deny", "", "", "", "AZFWThreatIntel", "ThreatIntel"),
]

payload = {
    "topology": topology, "dns": [], "flows": flows,
    "subs": [{"subscriptionId": SUB_A, "name": "iam101 Identity Management"},
             {"subscriptionId": SUB_B, "name": "guss101 Directory Services"}],
    "sites": [], "metrics": [], "fwlogs": fwlogs,
    "scanned": now.strftime("%Y-%m-%d_%H%M"), "scannedIso": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
}

marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
html = open("azure-net-map.html", encoding="utf-8").read()
assert html.count(marker) == 1
open("fix-scan.html", "w", encoding="utf-8").write(html.replace(marker, "const EMBEDDED=" + json.dumps(payload) + ";"))
print("wrote fix-scan.html: AVNM rc + NSG rules + blackhole route +", len(flows), "flows")
