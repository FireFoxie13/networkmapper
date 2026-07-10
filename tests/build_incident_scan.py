#!/usr/bin/env python3
"""Reproduces the azh5pcosql01f incident: a SQL Always On DR replica whose
databases are up and whose cluster/AG transport flows fine, but which cannot
open its databases because it cannot reach its TDE key in Key Vault. The vault
refuses everything except its private endpoint, and the DR VNet resolves through
a custom DNS forwarder that is not linked to the privatelink zone — so the
replica resolves the public name and is refused above the network.

Exercises all four checks:
  1. private endpoint DNS reachability   (vault PE, zone linked to primary only)
  2. deny-only service reachability       (vault + storage, networkAcls Deny)
  3. compute / NIC facts                  (power state, per-NIC DNS override)
  4. "it is not the network" verdicts     (firewall Allow -> NOT BLOCKED,
                                           firewall Deny  -> BLOCKED + fix box)

Writes two files that differ only in one firewall log row's action:
  incident-scan.html          firewall logged Allow  -> Network path NOT BLOCKED
  incident-scan-blocked.html  firewall logged Deny   -> Network path BLOCKED
"""
import json, datetime

SUB_P = "11110000-1111-1111-1111-111111111111"   # primary / hub region
SUB_D = "22220000-2222-2222-2222-222222222222"   # DR region
RG_P  = "azg5-sql-prod-eastus"
RG_D  = "azh5-sql-dr-westus"
RG_H  = "azg5-hub-prod"

def rid(sub, rg, prov, name):
    return f"/subscriptions/{sub}/resourcegroups/{rg}/providers/{prov}/{name}".lower()

# ---- VNets / subnets ----
VNET_P = rid(SUB_P, RG_P, "microsoft.network/virtualnetworks", "azg5-sql-primary-vnet")
SN_P   = VNET_P + "/subnets/sql-pri"
VNET_D = rid(SUB_D, RG_D, "microsoft.network/virtualnetworks", "azh5-sql-dr-vnet")
SN_D   = VNET_D + "/subnets/sql-dr"

# ---- services + their private endpoints ----
KV     = rid(SUB_P, RG_P, "microsoft.keyvault/vaults", "azg5pcosqlkv01")
KV_PE  = rid(SUB_P, RG_P, "microsoft.network/privateendpoints", "azg5pcosqlkv01-pe")
KV_PE_NIC = rid(SUB_P, RG_P, "microsoft.network/networkinterfaces", "azg5pcosqlkv01-pe-nic")
SA     = rid(SUB_P, RG_P, "microsoft.storage/storageaccounts", "azg5pcosqlsa01")
SA_PE  = rid(SUB_P, RG_P, "microsoft.network/privateendpoints", "azg5pcosqlsa01-pe")

# ---- private DNS zones ----
ZONE_KV   = rid(SUB_P, RG_P, "microsoft.network/privatednszones", "privatelink.vaultcore.azure.net")
ZONE_BLOB = rid(SUB_P, RG_P, "microsoft.network/privatednszones", "privatelink.blob.core.windows.net")

# ---- firewall (hub) ----
FW    = rid(SUB_P, RG_H, "microsoft.network/azurefirewalls", "azg5-hub-fw")
FWPOL = rid(SUB_P, RG_H, "microsoft.network/firewallpolicies", "azg5-hub-fwpolicy")
FWRCG = FWPOL + "/rulecollectiongroups/hub-rcg"

# ---- VMs / NICs ----
VM_PRI     = rid(SUB_P, RG_P, "microsoft.compute/virtualmachines", "azg5pcosql01d")
NIC_PRI    = rid(SUB_P, RG_P, "microsoft.network/networkinterfaces", "azg5pcosql01d-nic")
VM_DR      = rid(SUB_D, RG_D, "microsoft.compute/virtualmachines", "azh5pcosql01f")
NIC_DR     = rid(SUB_D, RG_D, "microsoft.network/networkinterfaces", "azh5pcosql01f-nic")
VM_DRAPP   = rid(SUB_D, RG_D, "microsoft.compute/virtualmachines", "azh5dr-app01")
NIC_DRAPP  = rid(SUB_D, RG_D, "microsoft.network/networkinterfaces", "azh5dr-app01-nic")
VM_OLD     = rid(SUB_D, RG_D, "microsoft.compute/virtualmachines", "azh5dr-old01")
NIC_OLD    = rid(SUB_D, RG_D, "microsoft.network/networkinterfaces", "azh5dr-old01-nic")

KV_PE_IP = "172.20.10.20"
SA_PE_IP = "172.20.10.21"
KV_FQDN  = "azg5pcosqlkv01.privatelink.vaultcore.azure.net"


def vnetlink(zone, name, vnet):
    return {"id": zone + "/virtualnetworklinks/" + name, "name": name,
            "type": "microsoft.network/privatednszones/virtualnetworklinks",
            "properties": {"virtualNetwork": {"id": vnet}}}


def nic(nid, ip, subnet, primary=True, dns=None, vm=None):
    p = {"ipConfigurations": [{"name": "ipconfig1", "properties": {
            "privateIPAddress": ip, "primary": True, "subnet": {"id": subnet}}}],
         "primary": primary, "enableIPForwarding": False, "enableAcceleratedNetworking": True}
    if dns: p["dnsSettings"] = {"dnsServers": dns}
    if vm:  p["virtualMachine"] = {"id": vm}
    return {"id": nid, "name": nid.split("/")[-1], "type": "microsoft.network/networkinterfaces",
            "properties": p}


def vm(vid, size, power, nic_id, os_name="Windows Server 2019 Datacenter", os_ver="10.0.17763",
       hyperv="V2", lic="Windows_Server"):
    return {"id": vid, "name": vid.split("/")[-1], "type": "microsoft.compute/virtualmachines",
            "properties": {
                "hardwareProfile": {"vmSize": size},
                "licenseType": lic,
                "networkProfile": {"networkInterfaces": [{"id": nic_id, "properties": {"primary": True}}]},
                "storageProfile": {"osDisk": {"osType": "Windows"}},
                "extended": {"instanceView": {
                    "powerState": {"code": "PowerState/" + power.split()[-1].lower(),
                                   "displayStatus": power},
                    "osName": os_name, "osVersion": os_ver, "hyperVGeneration": hyperv}}}}


def kvlike(rid_, name, typ, fqdns=None):
    return {"id": rid_, "name": name, "type": typ,
            "properties": {"networkAcls": {"defaultAction": "Deny",
                                           "virtualNetworkRules": [], "ipRules": []},
                           "publicNetworkAccess": "Disabled"}}


def pe(pid, subnet, target, group, fqdn, ip, pe_nic=None):
    p = {"subnet": {"id": subnet},
         "privateLinkServiceConnections": [{"name": "conn", "properties": {
             "privateLinkServiceId": target, "groupIds": [group]}}],
         "customDnsConfigs": [{"fqdn": fqdn, "ipAddresses": [ip]}]}
    if pe_nic: p["networkInterfaces"] = [{"id": pe_nic}]
    return {"id": pid, "name": pid.split("/")[-1], "type": "microsoft.network/privateendpoints",
            "properties": p}


topology = [
    # ---- VNets: DR uses a custom DNS forwarder; primary uses default Azure DNS ----
    {"id": VNET_P, "name": "azg5-sql-primary-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["172.20.10.0/24"]},
                    "subnets": [{"id": SN_P, "name": "sql-pri",
                                 "properties": {"addressPrefix": "172.20.10.0/27"}}],
                    "virtualNetworkPeerings": [{"name": "pri-to-dr",
                        "properties": {"peeringState": "Connected",
                                       "remoteVirtualNetwork": {"id": VNET_D}}}]}},
    {"id": VNET_D, "name": "azh5-sql-dr-vnet", "type": "microsoft.network/virtualnetworks",
     "properties": {"addressSpace": {"addressPrefixes": ["172.21.10.0/24"]},
                    "dhcpOptions": {"dnsServers": ["172.21.10.4"]},
                    "subnets": [{"id": SN_D, "name": "sql-dr",
                                 "properties": {"addressPrefix": "172.21.10.0/27"}}],
                    "virtualNetworkPeerings": [{"name": "dr-to-pri",
                        "properties": {"peeringState": "Connected",
                                       "remoteVirtualNetwork": {"id": VNET_P}}}]}},

    # ---- deny-only services ----
    kvlike(KV, "azg5pcosqlkv01", "microsoft.keyvault/vaults"),
    kvlike(SA, "azg5pcosqlsa01", "microsoft.storage/storageaccounts"),

    # ---- private endpoints in the primary subnet ----
    pe(KV_PE, SN_P, KV, "vault", KV_FQDN, KV_PE_IP, KV_PE_NIC),
    pe(SA_PE, SN_P, SA, "blob", "azg5pcosqlsa01.privatelink.blob.core.windows.net", SA_PE_IP),

    # ---- private DNS zones + links: vaultcore -> primary only (the bug);
    #      blob -> primary AND dr (the healthy control) ----
    {"id": ZONE_KV,   "name": "privatelink.vaultcore.azure.net",     "type": "microsoft.network/privatednszones", "properties": {}},
    {"id": ZONE_BLOB, "name": "privatelink.blob.core.windows.net",   "type": "microsoft.network/privatednszones", "properties": {}},
    vnetlink(ZONE_KV,   "link-pri", VNET_P),
    vnetlink(ZONE_BLOB, "link-pri", VNET_P),
    vnetlink(ZONE_BLOB, "link-dr",  VNET_D),

    # ---- firewall + policy + a deny collection the blocked variant cites ----
    {"id": FW, "name": "azg5-hub-fw", "type": "microsoft.network/azurefirewalls",
     "properties": {"firewallPolicy": {"id": FWPOL}}},
    {"id": FWPOL, "name": "azg5-hub-fwpolicy", "type": "microsoft.network/firewallpolicies",
     "properties": {"threatIntelMode": "Alert"}},
    {"id": FWRCG, "name": "hub-rcg", "type": "microsoft.network/firewallpolicies/rulecollectiongroups",
     "properties": {"priority": 200, "ruleCollections": [
        {"name": "block-cross-region", "priority": 400, "action": {"type": "Deny"},
         "rules": [{"name": "deny-cross-region-kv", "ipProtocols": ["TCP"],
                    "sourceAddresses": ["172.21.10.0/24"], "destinationAddresses": ["172.20.10.20/32"],
                    "destinationPorts": ["443"]}]},
     ]}},

    # ---- compute: primary DC running; DR replica running (DBs up) with a per-NIC
    #      DNS override; a neighbour without the override; a deallocated old box ----
    vm(VM_PRI,   "Standard_E8s_v5",  "VM running",     NIC_PRI),
    nic(NIC_PRI, "172.20.10.10", SN_P, primary=True, vm=VM_PRI),

    vm(VM_DR,    "Standard_E8s_v5",  "VM running",     NIC_DR),
    nic(NIC_DR,  "172.21.10.10", SN_D, primary=True, dns=["172.21.10.4"], vm=VM_DR),

    vm(VM_DRAPP, "Standard_D2s_v5",  "VM running",     NIC_DRAPP),
    nic(NIC_DRAPP, "172.21.10.11", SN_D, primary=True, vm=VM_DRAPP),

    vm(VM_OLD,   "Standard_D2s_v3",  "VM deallocated", NIC_OLD),
    nic(NIC_OLD, "172.21.10.12", SN_D, primary=True, vm=VM_OLD),
]

now = datetime.datetime.now(datetime.timezone.utc)
bkt = (now - datetime.timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


def flow(src, dst, port, proto, status, cnt, bo=1000, bi=1000):
    return {"Bucket": bkt, "SrcIp": src, "DestIp": dst, "DestPort": port, "L4Protocol": proto,
            "FlowStatus": status, "Flows": cnt, "BytesSrcToDest": bo, "BytesDestToSrc": bi,
            "AclRule": "", "AclGroup": "", "FlowType": "IntraVNet"}


# The healthy plumbing the operator sees: cluster heartbeat (3343), AG log
# transport (5022) and the SQL endpoint (1433) all flow DR -> primary and back.
flows = [
    flow("172.21.10.10", "172.20.10.10", 3343, "T", "Allowed", 120),
    flow("172.21.10.10", "172.20.10.10", 5022, "T", "Allowed", 88, 4_000_000, 40_000_000),
    flow("172.21.10.10", "172.20.10.10", 1433, "T", "Allowed", 54),
]


def fwlog(action, rule):
    # One firewall decision for DR -> Key Vault private endpoint on 443. The Allow
    # variant is the NOT-BLOCKED case; the Deny variant is the BLOCKED case.
    return {"Bucket": bkt, "SourceIp": "172.21.10.10", "Dest": KV_PE_IP, "DestinationPort": 443,
            "Protocol": "TCP", "Action": action, "ActionReason": "",
            "Rule": rule, "RuleCollection": "block-cross-region",
            "RuleCollectionGroup": "hub-rcg", "Policy": "azg5-hub-fwpolicy",
            "RuleType": "AZFWNetworkRule", "Hits": 33}


def payload(fwlogs):
    return {"topology": topology, "dns": [], "flows": flows,
            "subs": [{"subscriptionId": SUB_P, "name": "azg5 SQL Primary"},
                     {"subscriptionId": SUB_D, "name": "azh5 SQL DR"}],
            "sites": [], "metrics": [], "fwlogs": fwlogs,
            "scanned": now.strftime("%Y-%m-%d_%H%M"), "scannedIso": now.strftime("%Y-%m-%dT%H:%M:%SZ")}


marker = "const EMBEDDED=null;//__NETMAP_EMBED__"
html = open("azure-net-map.html", encoding="utf-8").read()
assert html.count(marker) == 1

for fname, fwlogs in [("incident-scan.html",         [fwlog("Allow", "allow-dr-to-kv-pe")]),
                      ("incident-scan-blocked.html", [fwlog("Deny",  "deny-cross-region-kv")])]:
    open(fname, "w", encoding="utf-8").write(
        html.replace(marker, "const EMBEDDED=" + json.dumps(payload(fwlogs)) + ";"))

print("wrote incident-scan.html + incident-scan-blocked.html:",
      len(topology), "topology items,", len(flows), "flows")
