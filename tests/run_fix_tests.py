#!/usr/bin/env python3
"""Remediation engine, Rules-tab traffic expansion, and layout untangling.
Runs against fix-scan.html (AVNM + NSG + firewall + route table) and
hairball-new.html (63-node dense mesh)."""
import subprocess, sys, time
from playwright.sync_api import sync_playwright

PORT = 8130
server = subprocess.Popen(["python3", "-m", "http.server", str(PORT), "--bind", "127.0.0.1"],
                          cwd=".", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.0)
results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (("  -- " + str(detail)[:260]) if (detail and not ok) else ""))

BENIGN = ("icons/manifest.json", "favicon.ico")
try:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1500, "height": 950}, ignore_https_errors=True)
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        def on_console(m):
            if m.type != "error": return
            loc = m.location or {}
            url = loc.get("url", "") if isinstance(loc, dict) else ""
            if any(b in url or b in m.text for b in BENIGN): return
            errors.append(m.text)
        page.on("console", on_console)

        page.goto(f"http://127.0.0.1:{PORT}/fix-scan.html")
        page.wait_for_timeout(2400)
        check("fix scan loads with zero errors", not errors, errors[:2])

        fx = page.evaluate("""() => {const o={};
          for(const e of fullGraph.edges){ if(e.kind!=='traffic'||!e.rows)continue;
            for(const r of e.rows) if(r.denied){const f=remediationFor(r); o[f.layer]=f;} }
          return o;}""")

        # ---------- AVNM ----------
        a = fx.get("AVNM security admin rule")
        check("AVNM: refuses to suggest an NSG fix", a and "not help" in a["order"] and "nsg rule create" not in a["actions"][0]["cmd"])
        check("AVNM: real manager / config / collection resolved",
              a and all(x in a["actions"][0]["cmd"] for x in ["gusa-avnm-prod", "gusa-global", "rc-gusa-global-denies"]))
        check("AVNM: allow priority sits ahead of the deny", a and "--priority 3081" in a["actions"][0]["cmd"])
        check("AVNM: no invalid address-prefix flags",
              a and "--source-address-prefix " not in a["actions"][0]["cmd"] and "--sources '[" in a["actions"][0]["cmd"])
        check("AVNM: post-commit targets the configuration, not the collection",
              a and a["actions"][0]["cmd"].rstrip().endswith("/securityadminconfigurations/gusa-global"))

        # ---------- NSG ----------
        n = fx.get("Network security group")
        check("NSG: real rg + nsg name", n and "-g guss101-dirsvcs-prod" in n["actions"][0]["cmd"])
        check("NSG: allow priority ahead of the deny", n and "--priority 970" in n["actions"][0]["cmd"])
        check("NSG: scoped to observed port and protocol",
              n and "--destination-port-ranges 123" in n["actions"][0]["cmd"] and "--protocol UDP" in n["actions"][0]["cmd"])
        check("NSG: source scoped to its subnet, not 0.0.0.0/0",
              n and "--source-address-prefixes 172.22.52.64/27" in n["actions"][0]["cmd"])
        check("NSG: offers narrowing the deny as an alternative", n and len(n["actions"]) == 2)
        check("NSG: warns an AVNM deny would still win", n and "AVNM" in n["order"])

        # ---------- route ----------
        rt = fx.get("Route table")
        check("Route: names the real route, no placeholder",
              rt and "kill-legacy-dmz" in rt["actions"][0]["cmd"] and "<route-name>" not in rt["actions"][0]["cmd"])
        check("Route: explains no deny is logged", rt and "nothing is logged as a deny" in rt["order"])

        # ---------- firewall: all three tables ----------
        fw = page.evaluate("""() => {
          const mk=o=>Object.assign({srcIp:'172.22.52.70',dstIp:'10.70.5.5',port:445,proto:'TCP',count:6,denied:true},o);
          return {
            net: remediationFor(mk({fwRule:'deny-smb-egress',fwPolicy:'gusa-hub-fwpolicy',fwTable:'AZFWNetworkRule',
                 fwCollection:'block-legacy',fwGroup:'gusa-default-rcg',aclRule:'deny-smb-egress',aclGroup:'gusa-hub-fwpolicy'})),
            app: remediationFor(mk({dstIp:'10.80.1.1',port:443,fwRule:'deny-unsanctioned-fqdn',fwPolicy:'gusa-hub-fwpolicy',
                 fwTable:'AZFWApplicationRule',fwCollection:'block-web',fwGroup:'gusa-default-rcg',
                 fwDest:'updates.contoso-legacy.com',aclRule:'deny-unsanctioned-fqdn',aclGroup:'gusa-hub-fwpolicy'})),
            ti:  remediationFor(mk({dstIp:'10.90.9.9',port:443,fwPolicy:'gusa-hub-fwpolicy',fwTable:'AZFWThreatIntel',
                 fwReason:'ThreatIntel',aclGroup:'gusa-hub-fwpolicy',fwRule:''}))};}""")
        c0, c1 = fw["net"]["actions"][0]["cmd"], fw["net"]["actions"][1]["cmd"]
        check("FW network rule: real policy + rcg + collection priority ahead of the deny",
              "--policy-name gusa-hub-fwpolicy" in c0 and "--rule-collection-group-name gusa-default-rcg" in c0
              and "--collection-priority 390" in c0)
        check("FW: add-filter-collection names the rule with --rule-name", "--rule-name allow-445-tcp" in c0)
        check("FW: collection rule add uses --name, no duplicate --rule-name",
              "--name allow-445-tcp" in c1 and "--rule-name" not in c1)
        check("FW: network rule uses --ip-protocols", "--ip-protocols TCP" in c0)
        check("FW: refinement names the deny rule and its collection",
              "deny-smb-egress" in fw["net"]["refine"]["what"] and "block-legacy" in fw["net"]["refine"]["what"])
        check("FW application rule: targets the FQDN, not the IP",
              "--target-fqdns updates.contoso-legacy.com" in fw["app"]["actions"][0]["cmd"]
              and "--rule-type ApplicationRule" in fw["app"]["actions"][0]["cmd"])
        check("FW app rule: maps 443 to Https", "--protocols Https=443" in fw["app"]["actions"][0]["cmd"])
        check("Threat intel: allowlists one address, never flips the mode",
              "--ip-addresses 10.90.9.9" in fw["ti"]["actions"][0]["cmd"]
              and "--threat-intel-mode" not in fw["ti"]["actions"][0]["cmd"])
        check("Threat intel: explicitly warns against Alert mode", "not fix this by setting" in fw["ti"]["refine"]["why"])
        check("FW: explains routing and evaluation order",
              "route already steers" in fw["net"]["order"] and "network rule" in fw["net"]["order"])

        # ---------- panel rendering ----------
        page.evaluate("() => {const n=fullGraph.nodes.find(x=>x.name==='azh1delrds01-nic'); selected=n.id; renderPanel();}")
        page.wait_for_timeout(400)
        check("panel renders a fix box per deny", page.eval_on_selector_all(".fixBox", "e=>e.length") >= 2)
        check("every action has a copy button", page.eval_on_selector_all(".fixBox .copyFix", "e=>e.length") >= 2)
        check("caveat says nothing writes to Azure",
              "Nothing in this tool writes to Azure" in page.eval_on_selector_all(".fixBox .caveat", "e=>e.map(x=>x.textContent).join(' ')"))

        # ---------- Rules tab: traffic + fix on expansion ----------
        page.click("#tabRules"); page.wait_for_timeout(1200)
        check("rules tab hints that rows expand",
              "Click any rule" in page.eval_on_selector_all(".statusline", "e=>e.map(x=>x.textContent).join(' ')"))
        opened = page.evaluate("""() => {
          const rows=[...document.querySelectorAll('tr.rrow')];
          const target=rows.find(tr=>tr.textContent.includes('nsgsr-deny-rfc1918-to-vnet-inbound'));
          if(!target)return {found:false};
          target.dispatchEvent(new MouseEvent('click',{bubbles:true}));
          const det=document.getElementById('rdet-'+target.getAttribute('data-rule'));
          return {found:true, shown: det && det.style.display!=='none', txt: det?det.innerText:''};
        }""")
        check("clicking a deny rule expands its detail", opened.get("found") and opened.get("shown"), opened)
        check("expanded rule shows the traffic that hit it",
              "traffic that hit this rule" in opened.get("txt", "").lower(), opened.get("txt", "")[:160])
        check("expanded rule shows real flows", "172.22.52.70" in opened.get("txt", ""))
        check("expanded deny rule carries the recommended fix",
              "RECOMMENDED FIX" in opened.get("txt", "").upper() and "az network nsg rule create" in opened.get("txt", ""))
        check("rules tab still error-free", not errors, errors[:2])

        # ---------- firewall rules rebuilt from logs, with times ----------
        # A policy whose rule collections Resource Graph did not return, as in production.
        page.goto(f"http://127.0.0.1:{PORT}/fwlog-scan.html"); page.wait_for_timeout(2400)
        # rule hits are computed lazily, when the Rules tab first renders
        page.evaluate("() => { if(!ruleHitsComputed) computeRuleHits(); }")
        fwr = page.evaluate("""() => {const o=[];
          for(const n of fullGraph.nodes){ if(n.type!=='fwpolicy'||!n.meta.rules)continue;
            for(const x of n.meta.rules) o.push({name:x.name, hits:x.hits, den:x.deniedHits,
              obs:!!x.observed, coll:x.collection, first:x.firstTs, last:x.lastTs, shadowed:!!x.shadowed});}
          return o;}""")
        check("firewall rules are rebuilt when the policy has no rule collections", len(fwr) >= 1, fwr)
        deny = next((x for x in fwr if x["name"] == "deny-smb-egress"), None) or (fwr[0] if fwr else None)
        check("rebuilt firewall rules carry hits and denied counts", deny and deny["hits"] > 0, deny)
        check("rebuilt firewall rules carry first/last seen times", deny and deny["first"] and deny["last"], deny)
        check("rebuilt firewall rules are marked observed", deny and deny["obs"], deny)
        check("rebuilt firewall rules are never judged shadowed", all(not x["shadowed"] for x in fwr))

        # ---------- Rules tab: window control, timestamps, provenance ----------
        page.click("#tabRules"); page.wait_for_timeout(1500)
        check("rules tab has its own time window",
              page.eval_on_selector_all("#ruleWin option", "e=>e.length") == 8)  # 7 presets + Custom range
        check("rules header states the window it counts over",
              "Traffic counts cover" in page.eval_on_selector_all("#rulesView .statusline","e=>e.map(x=>x.textContent).join(' ')"))
        det = page.evaluate("""() => {
          const rows=[...document.querySelectorAll('tr.rrow')];
          const t=rows.find(x=>x.textContent.includes('deny-smb-egress'))||rows.find(x=>x.textContent.includes('Deny'));
          if(!t)return '';
          t.dispatchEvent(new MouseEvent('click',{bubbles:true}));
          const d=document.getElementById('rdet-'+t.getAttribute('data-rule'));
          return d?d.innerText:'';}""")
        check("expanded rule shows first/last seen", "first seen" in det and "last seen" in det, det[:140])
        check("expanded rule stamps each traffic line", det.count(":") > 3 and "hit this rule" in det.lower(), det[:140])
        check("expanded firewall rule explains it was rebuilt from logs",
              "rebuilt from the firewall" in det.lower() or "flows" in det.lower(), det[:140])
        page.select_option("#ruleWin", "60"); page.wait_for_timeout(2500)
        check("rules-tab window applies and syncs with the map control",
              page.evaluate("() => windowMin") == 60 and page.evaluate("() => document.getElementById('timeWin').value") == "60")
        page.select_option("#ruleWin", "0"); page.wait_for_timeout(2500)
        page.click("#tabMap"); page.wait_for_timeout(800)
        check("firewall-log scan renders without errors", not errors, errors[:2])

        # ---------- effective rules: status, traffic, intent ----------
        page.goto(f"http://127.0.0.1:{PORT}/fix-scan.html"); page.wait_for_timeout(2400)
        page.evaluate("""() => {const n=fullGraph.nodes.find(x=>x.name==='azh1delrds01-nic');
            selected=n.id; viewMode='overview'; renderPanel();}""")
        page.wait_for_timeout(600)
        eff = page.eval_on_selector_all("#panel .rule[data-eff]", "e=>e.map(x=>x.innerText.replace(/\\s+/g,' '))")
        check("effective rules render with a status", len(eff) >= 2 and any("denied" in x or "No traffic" in x or "attributable" in x for x in eff), eff[:2])
        det = page.evaluate("""() => {
          const el=[...document.querySelectorAll('#panel .rule[data-eff]')].find(x=>/denied/.test(x.innerText));
          if(!el)return '';
          el.dispatchEvent(new MouseEvent('click',{bubbles:true}));
          const d=document.getElementById(el.getAttribute('data-eff'));
          return d?d.innerText:'';}""")
        check("clicking an effective rule opens its traffic", "DENIED" in det, det[:120])
        check("traffic carries a plain-language intent read",
              any(k in det for k in ["infrastructure","management","noise","application","lateral"]), det[:160])
        check("intent read gives guidance, not a verdict",
              "Check the source" in det or "confirm" in det.lower() or "owner" in det.lower(), det[:160])

        # an AVNM allow rule must never be called unused
        st = page.evaluate("""() => {
          const admin={admin:true,access:'Allow',hits:0,priority:100,name:'x'};
          const deny ={admin:true,access:'Deny', hits:0,priority:100,name:'y'};
          return {allow:ruleStatus(admin).label, deny:ruleStatus(deny).label};}""")
        check("AVNM allow with no hits reads 'Not attributable', not 'No traffic seen'",
              st["allow"] == "Not attributable", st)
        check("AVNM deny with no hits still reads as unused", st["deny"] == "No traffic seen", st)

        # ---------- load balancer troubleshooting ----------
        lb = page.evaluate("""() => {const n=fullGraph.nodes.find(x=>x.type==='lb');
            if(!n)return ''; selected=n.id; renderPanel();
            const p=document.getElementById('panel').innerText;
            const i=p.toUpperCase().indexOf('LOAD BALANCER HEALTH');
            return i>=0?p.slice(i,i+420):'MISSING';}""")
        check("load balancer panel shows pools, members and probes",
              all(w in lb for w in ["Backend pools","Members","Health probes"]), lb[:120])
        check("load balancer names its backends", "azh1delrds01-nic" in lb or "Backends" in lb, lb[:120])
        check("load balancer prompts for METRICS when they are absent", "METRICS" in lb, lb[:200])

        # ---------- layout: Untangle reduces label collisions ----------
        MEASURE = """() => {
          const t=[...document.querySelectorAll('#graph svg g g text')]
            .map(e=>e.getBoundingClientRect()).filter(r=>r.width>0);
          let ov=0;
          for(let i=0;i<t.length;i++)for(let j=i+1;j<t.length;j++){
            const a=t[i],b=t[j];
            const ix=Math.max(0,Math.min(a.x+a.width,b.x+b.width)-Math.max(a.x,b.x));
            const iy=Math.max(0,Math.min(a.y+a.height,b.y+b.height)-Math.max(a.y,b.y));
            if(ix*iy/Math.min(a.width*a.height,b.width*b.height)>0.10) ov++;
          } return ov;}"""
        page.goto(f"http://127.0.0.1:{PORT}/hairball-new.html")
        page.wait_for_timeout(1500)
        page.evaluate("() => {groupBy='none'; document.getElementById('groupBy').value='none'; expanded=new Set(); renderAll();}")
        page.wait_for_timeout(4500)
        normal = page.evaluate(MEASURE)
        check("spread control offers Untangle",
              page.eval_on_selector_all("#spread option", "e=>e.map(o=>o.textContent).join('|')").count("Untangle") >= 1)
        page.evaluate("() => {spread=3.2; renderGraph();}")
        page.wait_for_timeout(4500)
        untangled = page.evaluate(MEASURE)
        check(f"Untangle cuts overlapping labels ({normal} -> {untangled})", untangled < normal * 0.5, (normal, untangled))
        check("dense mesh renders without errors", not errors, errors[:2])

        # =================================================================
        # The azh5pcosql01f incident: four checks on incident-scan.html.
        # =================================================================
        errors.clear()
        page.goto(f"http://127.0.0.1:{PORT}/incident-scan.html")
        page.wait_for_timeout(2400)
        check("incident scan loads with zero errors", not errors, errors[:2])

        ids = page.evaluate("""() => {const o={};
            for(const n of fullGraph.nodes) o[n.name]=n.id; return o;}""")
        def panel(node_id):
            return page.evaluate("(id)=>{selected=id;renderPanel();return document.getElementById('panel').innerText;}", node_id)
        def trace(src, dst, port):
            return page.evaluate("""(a)=>{document.getElementById('tSrc').value=a.src;
                document.getElementById('tDst').value=a.dst;document.getElementById('tPort').value=a.port;
                document.getElementById('tProto').value='TCP';renderTrace();
                const el=document.getElementById('tResult');
                return {txt:el.innerText, fixbox:!!el.querySelector('.fixBox')};}""",
                {"src": src, "dst": dst, "port": port})

        model = page.evaluate("""() => {
            const finds=peDnsFindings();
            const cp=connectivityProblems();
            const kv=fullGraph.nodes.find(n=>n.name==='azg5pcosqlkv01');
            const vaultF=finds.find(f=>f.peName==='azg5pcosqlkv01-pe');
            const blobF=finds.find(f=>f.peName==='azg5pcosqlsa01-pe');
            const pedns=cp.filter(c=>c.kind==='pednsunverif');
            const denyonly=cp.filter(c=>c.kind==='denyonlype');
            return {
              vaultBroken: vaultF?vaultF.broken.map(b=>b.vnetName):[],
              vaultZone: vaultF?vaultF.zoneName:'',
              vaultDenyOnly: vaultF?vaultF.denyOnly:false,
              blobBroken: blobF?blobF.broken.map(b=>b.vnetName):[],
              pednsHigh: pedns.filter(c=>c.sev==='high').map(c=>({title:c.title,detail:c.detail,node:c.nodeId})),
              pednsCmd: pedns.map(c=>c.detail).join(' '),
              vaultId: kv?kv.id:'',
              denyonlyInfo: denyonly.filter(c=>c.sev==='info').map(c=>c.title),
            };}""")

        # ---------- Check 1: private endpoint DNS reachability ----------
        check("Check1: DR VNet flagged as unable to verify the vault private endpoint",
              model["vaultBroken"] == ["azh5-sql-dr-vnet"], model["vaultBroken"])
        check("Check1: the flagged zone is the vaultcore privatelink zone",
              model["vaultZone"] == "privatelink.vaultcore.azure.net", model["vaultZone"])
        check("Check1: healthy side is silent (blob zone links the DR VNet, no flag)",
              model["blobBroken"] == [], model["blobBroken"])
        check("Check1: the finding names the exact Resolve-DnsName command",
              "Resolve-DnsName azg5pcosqlkv01.privatelink.vaultcore.azure.net" in model["pednsCmd"])

        # ---------- Check 2: services that refuse all but their private endpoint ----------
        check("Check2: vault refuses everything except its PE (deny-only)", model["vaultDenyOnly"])
        check("Check2: with a broken client it is a connectivity problem, not an info note",
              len(model["pednsHigh"]) == 1 and model["pednsHigh"][0]["node"] == model["vaultId"]
              and "unreachable" in model["pednsHigh"][0]["title"], model["pednsHigh"])
        check("Check2: a deny-only service with healthy clients gets the info note",
              "Reachable only through its private endpoint: azg5pcosqlsa01" in model["denyonlyInfo"],
              model["denyonlyInfo"])

        # ---------- Check 3: compute / NIC facts ----------
        drnic = panel(ids["azh5pcosql01f-nic"])
        check("Check3: NIC panel names the owning VM", "azh5pcosql01f" in drnic and "Virtual machine" in drnic)
        check("Check3: NIC panel surfaces the per-NIC DNS override", "DNS override 172.21.10.4" in drnic)
        check("Check3: a lone DNS override is flagged against its subnet neighbours",
              "This NIC overrides DNS" in drnic and "neighbours in the subnet do not" in drnic)
        drvm = panel(ids["azh5pcosql01f"])
        check("Check3: VM panel surfaces compute facts", "Standard_E8s_v5" in drvm and "VM running" in drvm)
        check("Check3: each attached NIC is listed once (no duplicate nicOf edge)",
              "NETWORK INTERFACES (1)" in drvm.upper())
        oldvm = panel(ids["azh5dr-old01"])
        check("Check3: a stopped VM is flagged as impaired",
              "VM deallocated" in oldvm and "not running" in oldvm)
        tip = page.evaluate("""(nm)=>{const d=fullGraph.nodes.find(n=>n.name===nm);
            showTip({clientX:100,clientY:100},d);return document.getElementById('tip').innerText;}""",
            "azh5pcosql01f")
        check("Check3: hover box names type, resource group and VNet for a node",
              "Virtual machine" in tip and "azh5-sql-dr-westus" in tip and "azh5-sql-dr-vnet" in tip)

        # ---------- Check 4: "it is not the network" verdicts ----------
        openv = trace("172.21.10.10", "172.20.10.20", 443)
        i_dns = openv["txt"].find("1. DNS resolution")
        i_rbac = openv["txt"].find("3. Authorization")
        check("Check4: firewall Allow yields Network path NOT BLOCKED",
              "NOT BLOCKED" in openv["txt"] and "BLOCKED" in openv["txt"])
        check("Check4: the verdict cites the firewall Allow row",
              "Azure Firewall logged an Allow" in openv["txt"])
        check("Check4: non-network causes lead with DNS",
              i_dns != -1 and i_rbac != -1 and i_dns < i_rbac, (i_dns, i_rbac))
        check("Check4: DNS cause carries a Resolve-DnsName command",
              "Resolve-DnsName azg5pcosqlkv01.privatelink.vaultcore.azure.net" in openv["txt"])
        check("Check4: effective-routes and test-ip-flow are offered as later steps",
              "show-effective-route-table" in openv["txt"] and "test-ip-flow" in openv["txt"])

        unknownv = trace("172.21.10.11", "172.20.10.20", 443)
        check("Check4: no logged evidence yields UNKNOWN, never 'allowed'",
              "UNKNOWN" in unknownv["txt"] and 'not a verdict of "allowed"' in unknownv["txt"])

        errors.clear()
        page.goto(f"http://127.0.0.1:{PORT}/incident-scan-blocked.html")
        page.wait_for_timeout(2000)
        blockedv = trace("172.21.10.10", "172.20.10.20", 443)
        check("Check4: flipping the firewall row to Deny flips the verdict to BLOCKED",
              "BLOCKED" in blockedv["txt"] and "NOT BLOCKED" not in blockedv["txt"])
        check("Check4: the BLOCKED verdict cites the firewall Deny and offers a fix box",
              "Azure Firewall logged a Deny" in blockedv["txt"] and blockedv["fixbox"])
        check("incident-blocked scan renders without errors", not errors, errors[:2])

        browser.close()
finally:
    server.terminate()

fails = [r for r in results if not r[1]]
print(f"\n{len(results)-len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
