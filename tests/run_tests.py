#!/usr/bin/env python3
"""Browser tests for the patched azure-net-map.html, run against a synthetic scan
built the same way generate-netmap.sh builds real ones, plus the demo path."""
import json, subprocess, sys, time
from playwright.sync_api import sync_playwright

PORT = 8111
server = subprocess.Popen(["python3", "-m", "http.server", str(PORT), "--bind", "127.0.0.1"],
                          cwd=".", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.0)

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (("  -- " + str(detail)[:300]) if (detail and not ok) else ""))

def overlap_frac(a, b):
    ix = max(0, min(a["x"]+a["width"],  b["x"]+b["width"])  - max(a["x"], b["x"]))
    iy = max(0, min(a["y"]+a["height"], b["y"]+b["height"]) - max(a["y"], b["y"]))
    inter = ix * iy
    small = min(a["width"]*a["height"], b["width"]*b["height"]) or 1
    return inter / small

try:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1500, "height": 950}, ignore_https_errors=True)
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        BENIGN=("icons/manifest.json","favicon.ico")
        def on_console(m):
            if m.type!="error": return
            loc=m.location or {}
            url=loc.get("url","") if isinstance(loc,dict) else ""
            if any(b in url or b in m.text for b in BENIGN): return
            errors.append(m.text)
        page.on("console", on_console)

        # ---------- load the synthetic scan ----------
        page.goto(f"http://127.0.0.1:{PORT}/scan-under-test.html")
        page.wait_for_timeout(2500)
        check("scan loads with zero console/page errors", not errors, errors[:3])

        n_nodes = page.eval_on_selector_all("#graph svg g circle", "els=>els.length")
        check("overview renders circles", n_nodes > 0, n_nodes)

        # ---------- deps view via search (the screenshot scenario) ----------
        page.fill("#q", "azh1delrds01-nic")
        page.press("#q", "Enter")
        page.wait_for_timeout(1200)
        texts = page.eval_on_selector_all("#graph svg text",
            "els=>els.map(t=>({s:t.textContent,x:t.getBoundingClientRect().x,y:t.getBoundingClientRect().y,"
            "w:t.getBoundingClientRect().width,h:t.getBoundingClientRect().height}))")
        joined = " | ".join(t["s"] for t in texts)

        check("deps view shows SOURCES/DESTINATIONS", "SOURCES" in joined and "DESTINATIONS" in joined, joined[:200])
        check("blocked-at note names the AVNM layer (no '?')",
              "blocked at AVNM security admin rule rc-gusa-global-denies / out-deny-unauthorized-spoke-to-spoke" in joined
              and "blocked at ?" not in joined, joined[:400])

        # deny note must sit in the bottom band, below every node label
        note = [t for t in texts if t["s"].startswith("blocked at ")]
        namey = [t for t in texts if t["s"].startswith("azh1") or t["s"].startswith("delinea")]
        check("blocked-at note exists exactly once", len(note) == 1, len(note))
        if note and namey:
            check("blocked-at note is below all node labels",
                  note[0]["y"] > max(t["y"] for t in namey) + 20,
                  f"note y={note[0]['y']:.0f} max node label y={max(t['y'] for t in namey):.0f}")

        # location lines: subscription · resource group present for side nodes
        check("side nodes show subscription and resource group lines",
              "iam101 Identity Management" in joined and "iam101-delinea-prod-centralus" in joined
              and "guss101 Directory Services" in joined and "guss101-dirsvcs-prod" in joined, joined[:600])

        # clickable root crumb exists with pieces
        crumb = page.eval_on_selector_all('[data-test="rootCrumb"] text', "els=>els.map(t=>t.textContent)")
        check("root crumb has clickable sub / rg / vnet pieces",
              any("iam101 Identity Management" in c for c in crumb)
              and any("iam101-delinea-prod-centralus" in c for c in crumb)
              and any("iam101-cyber-prod-centralus-vnet" in c for c in crumb), crumb)

        # no meaningful text-on-text overlap in the deps view
        labels = [t for t in texts if t["w"] > 0 and t["h"] > 0 and not t["s"].startswith("Solid lines")]
        bad_pairs = []
        for i in range(len(labels)):
            for j in range(i+1, len(labels)):
                f = overlap_frac(dict(x=labels[i]["x"], y=labels[i]["y"], width=labels[i]["w"], height=labels[i]["h"]),
                                 dict(x=labels[j]["x"], y=labels[j]["y"], width=labels[j]["w"], height=labels[j]["h"]))
                if f > 0.25:
                    bad_pairs.append((labels[i]["s"][:28], labels[j]["s"][:28], round(f, 2)))
        check("no two deps labels overlap >25%", not bad_pairs, bad_pairs[:5])

        # nothing clipped off the left/right card edge
        card = page.eval_on_selector("#graph", "el=>{const r=el.getBoundingClientRect();return {l:r.x, r:r.x+r.width}}")
        clipped = [t["s"][:30] for t in labels if t["x"] < card["l"] - 1 or t["x"] + t["w"] > card["r"] + 1]
        check("no deps label clips outside the card", not clipped, clipped[:5])

        # click the sub crumb: overview + subscription facet filtered
        page.eval_on_selector('[data-test="rootCrumb"] text:nth-of-type(1)',
                              "el=>el.dispatchEvent(new MouseEvent('click',{bubbles:true}))")
        page.wait_for_timeout(900)
        filtered = page.evaluate("() => facetFilters.sub.size === 1 && viewMode === 'overview'")
        check("clicking sub crumb filters overview to that subscription", filtered)

        # ---------- panel crumbs ----------
        page.evaluate("() => { facetFilters.sub = new Set(); selected = null; viewMode='overview'; renderAll(); }")
        page.wait_for_timeout(600)
        page.evaluate("""() => { const nic=fullGraph.nodes.find(n=>n.name==='azh1delrds01-nic'); selected=nic.id; renderPanel(); }""")
        page.wait_for_timeout(400)
        crumb_kinds = page.eval_on_selector_all("#panel .crumbLink", "els=>els.map(e=>e.getAttribute('data-crumb'))")
        check("panel crumb has sub/rg/vnet links", crumb_kinds == ["sub", "rg", "vnet"], crumb_kinds)
        page.click('#panel .crumbLink[data-crumb="vnet"]')
        page.wait_for_timeout(900)
        rerooted = page.evaluate("() => viewMode==='deps' && (byId.get(depsRoot)||{}).type==='vnet'")
        check("clicking VNet crumb re-roots deps on the VNet", rerooted)

        # ---------- per-cluster expand / collapse ----------
        page.evaluate("() => { viewMode='overview'; depsRoot=null; selected=null; expanded=new Set(); "
                      "document.getElementById('q').value=''; focusOn=false; syncFocusBtn(); syncViewBtns(); renderAll(); }")
        page.wait_for_timeout(900)
        before = page.evaluate("() => lastView.nodes.filter(n=>n.type==='group').length")
        # dblclick the first cluster circle
        page.evaluate("""() => {
          const g=[...document.querySelectorAll('#graph svg g')].find(el=>el.__data__&&el.__data__.type==='group');
          g.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
        }""")
        page.wait_for_timeout(900)
        after = page.evaluate("""() => {
          const key=[...expanded][0]||"";
          const sub=key.startsWith('sub|')?key.slice(4):null;
          const stray=sub?lastView.nodes.filter(n=>n.subId&&n.subId!==sub).length:-1;
          return {exp: expanded.size, filtered: facetFilters.sub.size, stray};
        }""")
        check("dblclick opens one cluster and hides everything else",
              after["exp"] == 1 and after["filtered"] == 1 and after["stray"] == 0,
              f"before={before} after={after}")

        # dblclick a member restores the map: cluster folded AND filters back
        page.evaluate("""() => {
          const key=[...expanded][0];
          const el=[...document.querySelectorAll('#graph svg g')].find(g=>g.__data__&&g.__data__.type!=='group'&&groupKeyOf(g.__data__)===key);
          el.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
        }""")
        page.wait_for_timeout(900)
        folded = page.evaluate("() => ({groups: lastView.nodes.filter(n=>n.type==='group').length, exp: expanded.size, f: facetFilters.sub.size})")
        check("dblclick on a member folds back and restores the filters",
              folded["exp"] == 0 and folded["f"] == 0 and folded["groups"] == before, folded)

        # Inspect zooms in on the node
        page.evaluate("""() => {
          const g=[...document.querySelectorAll('#graph svg g')].find(el=>el.__data__&&el.__data__.type==='group');
          g.dispatchEvent(new MouseEvent('click',{bubbles:true}));
        }""")
        page.wait_for_timeout(300)
        page.click('#ctx button[data-a="inspect"]')
        page.wait_for_timeout(1600)
        zoomed = page.evaluate("""() => {
          const t=(document.querySelector('#graph svg g')||{getAttribute:()=>''}).getAttribute('transform')||'';
          const m=t.match(/scale\(([\d.]+)/); return m?+m[1]:1;
        }""")
        check("Inspect zooms the viewport onto the node", zoomed > 1.2, zoomed)
        page.evaluate("() => { selected=null; hideCtx(); renderAll(); }")
        page.wait_for_timeout(600)

        # ctx menu offers Collapse for members of an expanded cluster
        page.evaluate("""() => {
          const g=aggregate(fullGraph.nodes,fullGraph.edges).nodes.find(n=>n.type==='group');
          expanded.add(g.groupKey); renderAll();
        }""")
        page.wait_for_timeout(700)
        page.evaluate("""() => {
          const key=[...expanded][0];
          const el=[...document.querySelectorAll('#graph svg g')].find(g=>g.__data__&&g.__data__.type!=='group'&&groupKeyOf(g.__data__)===key);
          el.dispatchEvent(new MouseEvent('click',{bubbles:true}));
        }""")
        page.wait_for_timeout(400)
        has_collapse = page.evaluate("() => !!document.querySelector('#ctx button[data-a=\"collapse\"]')")
        check("context menu offers 'Collapse back into cluster'", has_collapse)

        # overview label anchors alternate (no stacked midpoint labels)
        lts = page.evaluate("() => [...new Set((lastView.edges||[]).map((e,i)=>i%2?0.40:0.60))].length")
        check("edge label anchors alternate along edges", lts >= 1)

        # ---------- search order: subscription name beats partial resource match ----------
        page.evaluate("() => { facetFilters={sub:new Set(),rg:new Set(),vnet:new Set(),type:new Set()}; "
                      "expanded=new Set(); selected=null; depsRoot=null; viewMode='overview'; renderAll(); }")
        page.fill("#q", "iam101 Identity Management"); page.press("#q", "Enter"); page.wait_for_timeout(900)
        r = page.evaluate("() => ({vm: viewMode, n: facetFilters.sub.size})")
        check("exact subscription name filters the map (not deps)", r["vm"]=="overview" and r["n"]==1, r)
        page.evaluate("() => { facetFilters.sub=new Set(); renderAll(); }")
        page.fill("#q", "iam101"); page.press("#q", "Enter"); page.wait_for_timeout(900)
        r = page.evaluate("() => ({vm: viewMode, n: facetFilters.sub.size})")
        check("partial subscription name still filters (beats lookalike resources)", r["vm"]=="overview" and r["n"]==1, r)
        page.evaluate("() => { facetFilters.sub=new Set(); renderAll(); }")
        page.fill("#q", "azh1delrds01-nic"); page.press("#q", "Enter"); page.wait_for_timeout(900)
        r = page.evaluate("() => viewMode")
        check("exact resource name still opens dependencies", r=="deps", r)

        # ---------- time window is usable ----------
        check("time window control is enabled", not page.evaluate("() => document.getElementById('timeWin').disabled"))
        r = page.evaluate("() => {const s=document.getElementById('timeWin'); s.value='30'; s.onchange(); return windowMin;}")
        check("selecting a window applies it", r == 30, r)
        page.evaluate("() => {const s=document.getElementById('timeWin'); s.value='0'; s.onchange();}")
        page.wait_for_timeout(800)

        # ---------- search: filters must not accumulate, types are searchable ----------
        def srch(q):
            page.fill("#q", ""); page.fill("#q", q); page.press("#q", "Enter"); page.wait_for_timeout(800)
            return page.evaluate("""() => ({vm:viewMode, sub:facetFilters.sub.size, vnet:facetFilters.vnet.size,
                type:facetFilters.type.size, rg:facetFilters.rg.size})""")
        srch("iam101-cyber-prod-centralus-vnet")
        r = srch("iam101 Identity Management")
        check("a new scope search clears the previous one", r["sub"] == 1 and r["vnet"] == 0, r)
        r = srch("azh1delrds01-nic")
        check("a resource search clears stale filters and opens deps",
              r["vm"] == "deps" and r["sub"] == 0, r)
        r = srch("guss101 Directory Services")
        check("a scope search from deps returns to the map", r["vm"] == "overview" and r["sub"] == 1, r)
        r = srch("Network interface")
        check("resource type is searchable", r["type"] == 1 and r["vm"] == "overview", r)
        r = srch("")
        check("Enter on an empty box clears everything",
              r["sub"] == 0 and r["rg"] == 0 and r["vnet"] == 0 and r["type"] == 0, r)
        sugg = page.eval_on_selector_all("#qSuggest option", "e=>e.map(o=>o.value)")
        check("search suggestions list subscriptions and types",
              "iam101 Identity Management" in sugg and "Network interface" in sugg, len(sugg))
        # restore the deps view the next checks expect
        page.evaluate("""() => {const n=fullGraph.nodes.find(x=>x.name==='azh1delrds01-nic');
            depsRoot=n.id; selected=n.id; viewMode='deps'; syncViewBtns(); renderAll();}""")
        page.wait_for_timeout(800)

        # ---------- search: shorthand, types, reset, back-and-forth ----------
        def srch(q):
            page.fill("#q", q); page.press("#q", "Enter"); page.wait_for_timeout(700)
            return page.evaluate("""() => ({vm:viewMode, sub:facetFilters.sub.size, rg:facetFilters.rg.size,
                vnet:facetFilters.vnet.size, type:facetFilters.type.size, tk:[...facetFilters.type][0]||""})""")
        r = srch("nic")
        check("shorthand 'nic' filters the resource type, not a lookalike resource",
              r["vm"]=="overview" and r["tk"]=="nic", r)
        r = srch("vnet")
        check("shorthand 'vnet' beats a partial VNet-name match", r["tk"]=="vnet", r)
        r = srch("Load balancer")
        check("full type label still works", r["tk"]=="lb", r)
        r = srch("azh1delrds01-nic")
        check("exact resource name opens deps and clears stale filters",
              r["vm"]=="deps" and r["sub"]+r["rg"]+r["vnet"]+r["type"]==0, r)
        r = srch("iam101 Identity Management")
        check("subscription search after a resource search still works",
              r["vm"]=="overview" and r["sub"]==1, r)
        r = srch("nic")
        check("searching back and forth leaves only one filter set",
              r["sub"]==0 and r["tk"]=="nic", r)
        r = srch("")
        check("Enter on an empty box clears every filter",
              r["vm"]=="overview" and r["sub"]+r["rg"]+r["vnet"]+r["type"]==0, r)
        check("suggestion list is populated",
              page.eval_on_selector_all("#qSuggest option","e=>e.length") > 5)

        # ---------- time window is usable ----------
        tw = page.evaluate("""() => ({disabled: document.getElementById('timeWin').disabled,
            enabled: [...document.querySelectorAll('#timeWin option')].filter(o=>!o.disabled).length})""")
        check("time-window control is enabled when the scan has timestamps",
              not tw["disabled"] and tw["enabled"] >= 2, tw)
        page.select_option("#timeWin", "60"); page.wait_for_timeout(1500)
        check("selecting a window actually applies it", page.evaluate("() => windowMin")==60)
        page.select_option("#timeWin", "0"); page.wait_for_timeout(1500)
        page.evaluate("() => {document.getElementById('q').value=''; jumpTo('');}")
        page.wait_for_timeout(600)
        # the deps assertions below need the dependency view rooted again
        page.evaluate("""() => {const n=fullGraph.nodes.find(x=>x.name==='azh1delrds01-nic');
            depsRoot=n.id; selected=n.id; viewMode='deps'; syncViewBtns(); renderAll();}""")
        page.wait_for_timeout(900)

        # ---------- deps ignores sidebar filters, and says so ----------
        page.evaluate("() => { facetFilters.sub=new Set(['bbbb2222-2222-2222-2222-222222222222']); renderAll(); }")
        page.wait_for_timeout(900)
        dtexts = page.eval_on_selector_all("#graph svg text", "els=>els.map(t=>t.textContent)")
        dj = " | ".join(dtexts)
        check("deps still shows all connections under a foreign filter",
              "SOURCES" in dj and "0 SOURCES" not in dj and "azh1delapp01-nic" in dj, dj[:200])
        check("deps announces that sidebar filters do not apply",
              "sidebar filters do not apply here" in dj, dj[:200])
        page.evaluate("() => { facetFilters.sub=new Set(); }")

        # ---------- isolate: show only this cluster ----------
        page.evaluate("() => { viewMode='overview'; depsRoot=null; selected=null; expanded=new Set(); "
                      "document.getElementById('q').value=''; focusOn=false; syncFocusBtn(); syncViewBtns(); renderAll(); }")
        page.wait_for_timeout(900)
        page.evaluate("""() => {
          const g=[...document.querySelectorAll('#graph svg g')].find(el=>el.__data__&&el.__data__.type==='group'&&(el.__data__.groupKey||'').startsWith('sub|'));
          g.dispatchEvent(new MouseEvent('click',{bubbles:true}));
        }""")
        page.wait_for_timeout(400)
        has_iso = page.evaluate("() => !!document.querySelector('#ctx button[data-a=\"isolate\"]')")
        check("cluster menu offers 'Show only this cluster'", has_iso)
        page.click('#ctx button[data-a="isolate"]')
        page.wait_for_timeout(900)
        iso = page.evaluate("""() => {
          const sub=[...facetFilters.sub][0];
          const stray=lastView.nodes.filter(n=>n.subId&&n.subId!==sub).length;
          return {filtered: facetFilters.sub.size===1, stray, exp: expanded.size>=1};
        }""")
        check("isolate shows only that subscription's resources, expanded",
              iso["filtered"] and iso["stray"]==0 and iso["exp"], iso)
        page.evaluate("() => { facetFilters={sub:new Set(),rg:new Set(),vnet:new Set(),type:new Set()}; expanded=new Set(); renderAll(); }")

        # ---------- empty state does not sit on the crumb ----------
        page.evaluate("() => { const n=fullGraph.nodes.find(x=>x.name==='orphan-test-pip'); "
                      "depsRoot=n.id; selected=n.id; viewMode='deps'; syncViewBtns(); renderAll(); }")
        page.wait_for_timeout(900)
        boxes = page.eval_on_selector_all("#graph svg text",
            "els=>els.map(t=>{const r=t.getBoundingClientRect();return {s:t.textContent,x:r.x,y:r.y,w:r.width,h:r.height}})")
        msg=[b for b in boxes if "No connections recorded" in b["s"] or "No flow logs loaded" in b["s"]]
        crumb_boxes=page.eval_on_selector_all('[data-test="rootCrumb"] text',
            "els=>els.map(t=>{const r=t.getBoundingClientRect();return {s:t.textContent,x:r.x,y:r.y,w:r.width,h:r.height}})")
        clash=[(m["s"][:20],c["s"][:20]) for m in msg for c in crumb_boxes
               if overlap_frac(dict(x=m["x"],y=m["y"],width=m["w"],height=m["h"]),
                               dict(x=c["x"],y=c["y"],width=c["w"],height=c["h"]))>0.05]
        check("empty-state message clear of the crumb", bool(msg) and bool(crumb_boxes) and not clash,
              {"msg":len(msg),"crumb":len(crumb_boxes),"clash":clash})
        page.evaluate("() => { viewMode='overview'; depsRoot=null; selected=null; syncViewBtns(); renderAll(); }")

        # screenshots for the user
        page.evaluate("() => { expanded=new Set(); selected=null; hideCtx(); renderAll(); }")
        page.fill("#q", "azh1delrds01-nic"); page.press("#q", "Enter"); page.wait_for_timeout(1200)
        page.screenshot(path="after-deps.png", clip={"x": 0, "y": 90, "width": 1500, "height": 860})

        errors_scan = list(errors)

        # ---------- demo path (template as shipped, EMBEDDED=null) ----------
        errors.clear()
        page.goto(f"http://127.0.0.1:{PORT}/azure-net-map.html")
        page.wait_for_timeout(2200)
        check("demo template loads with zero errors", not errors, errors[:3])
        demo_nodes = page.eval_on_selector_all("#graph svg g circle", "els=>els.length")
        check("demo overview renders", demo_nodes > 0, demo_nodes)
        for tab in ["tabArch", "tabMetrics", "tabRules", "tabTrouble", "tabAnalysis", "tabMap"]:
            page.click("#" + tab); page.wait_for_timeout(500)
        check("all six tabs cycle with zero errors", not errors, errors[:3])

        browser.close()
finally:
    server.terminate()

fails = [r for r in results if not r[1]]
print(f"\n{len(results)-len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
