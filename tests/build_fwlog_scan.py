#!/usr/bin/env python3
"""A firewall policy with NO rule collection groups in the scan, exactly as Azure
Resource Graph returns it in the user's tenant, plus firewall logs. The Rules tab
must rebuild the enforced rules from the logs alone."""
import json, datetime
SUB="aaaa1111-1111-1111-1111-111111111111"; RG="hub-prod"
def rid(p,n): return f"/subscriptions/{SUB}/resourcegroups/{RG}/providers/{p}/{n}".lower()
FW=rid("microsoft.network/azurefirewalls","hub-fw")
POL=rid("microsoft.network/firewallpolicies","hub-fwpolicy")
VNET=rid("microsoft.network/virtualnetworks","v"); SN=VNET+"/subnets/s"
topo=[
 {"id":VNET,"name":"v","type":"microsoft.network/virtualnetworks","properties":{
   "addressSpace":{"addressPrefixes":["10.5.0.0/16"]},
   "subnets":[{"id":SN,"name":"s","properties":{"addressPrefix":"10.5.1.0/24"}}]}},
 {"id":FW,"name":"hub-fw","type":"microsoft.network/azurefirewalls","properties":{"firewallPolicy":{"id":POL}}},
 {"id":POL,"name":"hub-fwpolicy","type":"microsoft.network/firewallpolicies","properties":{"threatIntelMode":"Deny"}},
 {"id":rid("microsoft.network/networkinterfaces","app01-nic"),"name":"app01-nic",
  "type":"microsoft.network/networkinterfaces",
  "properties":{"ipConfigurations":[{"properties":{"privateIPAddress":"10.5.1.10","subnet":{"id":SN}}}]}},
]
now=datetime.datetime.now(datetime.timezone.utc)
def bkt(h): return (now-datetime.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")
def fwlog(h,src,dst,port,action,rule,coll,table,hits):
    return {"Bucket":bkt(h),"SourceIp":src,"Dest":dst,"DestinationPort":str(port),"Protocol":"TCP",
            "Action":action,"ActionReason":"","Rule":rule,"RuleCollection":coll,
            "RuleCollectionGroup":"hub-fwpolicy","Policy":"hub-fwpolicy","RuleType":table,"Hits":str(hits)}
fwlogs=[
 fwlog(20,"10.5.1.10","74.179.222.82",9092,"Deny","deny-smb-egress","Blocking-Rule-Collection","AZFWNetworkRule",22721),
 fwlog(2, "10.5.1.10","74.179.222.82",9092,"Deny","deny-smb-egress","Blocking-Rule-Collection","AZFWNetworkRule",19004),
 fwlog(6, "10.5.1.10","20.75.229.143",443,"Allow","allow-web","Environment-Rules","AZFWNetworkRule",5120),
]
payload={"topology":topo,"dns":[],"flows":[],"subs":[{"subscriptionId":SUB,"name":"test sub"}],
 "sites":[],"metrics":[],"fwlogs":fwlogs,
 "scanned":now.strftime("%Y-%m-%d_%H%M"),"scannedIso":now.strftime("%Y-%m-%dT%H:%M:%SZ")}
m="const EMBEDDED=null;//__NETMAP_EMBED__"
h=open("azure-net-map.html",encoding="utf-8").read()
assert h.count(m)==1
open("fwlog-scan.html","w",encoding="utf-8").write(h.replace(m,"const EMBEDDED="+json.dumps(payload)+";"))
print("wrote fwlog-scan.html: policy with no rule collections +",len(fwlogs),"firewall log rows")
