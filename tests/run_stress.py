#!/usr/bin/env python3
"""Deps layout under load: 12 sources + 13 destinations on one NIC, panel open."""
import subprocess, sys, time
from playwright.sync_api import sync_playwright

PORT = 8112
server = subprocess.Popen(["python3", "-m", "http.server", str(PORT), "--bind", "127.0.0.1"],
                          cwd=".", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.0)
results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (("  -- " + str(detail)[:400]) if (detail and not ok) else ""))

def overlap_frac(a, b):
    ix = max(0, min(a["x"]+a["w"], b["x"]+b["w"]) - max(a["x"], b["x"]))
    iy = max(0, min(a["y"]+a["h"], b["y"]+b["h"]) - max(a["y"], b["y"]))
    return (ix*iy) / (min(a["w"]*a["h"], b["w"]*b["h"]) or 1)

try:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1500, "height": 950}, ignore_https_errors=True)
        page = ctx.new_page()
        errors = []
        BENIGN = ("icons/manifest.json", "favicon.ico")
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type=="error"
                and not any(b in ((m.location or {}).get("url","") if isinstance(m.location,dict) else "")+m.text for b in BENIGN) else None)

        page.goto(f"http://127.0.0.1:{PORT}/stress-scan.html")
        page.wait_for_timeout(2200)
        page.fill("#q", "azh0stress00-nic-with-long-name")
        page.press("#q", "Enter")
        page.wait_for_timeout(1500)
        check("stress scan deps view loads with zero errors", not errors, errors[:3])

        texts = page.eval_on_selector_all("#graph svg text",
            "els=>els.map(t=>{const r=t.getBoundingClientRect();return {s:t.textContent,x:r.x,y:r.y,w:r.width,h:r.height}})")
        joined = " | ".join(t["s"] for t in texts)
        import re as _re
        hdr=_re.findall(r"(\d+) (SOURCES|DESTINATIONS)", joined)
        counts={k:int(v) for v,k in hdr}
        check("12 sources / >=13 destinations drawn (subnet link adds one row)",
              counts.get("SOURCES",0)==12 and counts.get("DESTINATIONS",0)>=13, hdr)
        labels = [t for t in texts if t["w"] > 0 and t["h"] > 0 and not t["s"].startswith("Solid lines")]
        bad = []
        for i in range(len(labels)):
            for j in range(i+1, len(labels)):
                f = overlap_frac(labels[i], labels[j])
                if f > 0.25:
                    bad.append((labels[i]["s"][:26], labels[j]["s"][:26], round(f,2)))
        check("no two labels overlap >25% at 12x13 rows", not bad, bad[:8])
        card = page.eval_on_selector("#graph", "el=>{const r=el.getBoundingClientRect();return {l:r.x,r:r.x+r.width}}")
        clipped = [t["s"][:30] for t in labels if t["x"] < card["l"]-1 or t["x"]+t["w"] > card["r"]+1]
        check("no label clips at 12x13 rows", not clipped, clipped[:8])
        note = [t for t in texts if t["s"].startswith("blocked at ")]
        check("deny note present once, AVNM named", len(note)==1 and "AVNM security admin rule" in note[0]["s"], note)

        page.screenshot(path="after-deps-stress.png", full_page=False)

        # screenshots of the normal scan for the user
        page.goto(f"http://127.0.0.1:{PORT}/scan-under-test.html")
        page.wait_for_timeout(2000)
        page.fill("#q", "azh1delrds01-nic"); page.press("#q", "Enter"); page.wait_for_timeout(1400)
        page.screenshot(path="after-deps.png")
        page.evaluate("() => { viewMode='overview'; depsRoot=null; document.getElementById('q').value=''; focusOn=false; syncFocusBtn(); syncViewBtns(); renderAll(); }")
        page.wait_for_timeout(1400)
        page.evaluate("""() => {
          const g=[...document.querySelectorAll('#graph svg g')].find(el=>el.__data__&&el.__data__.type==='group');
          if(g) g.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
        }""")
        page.wait_for_timeout(1600)
        page.screenshot(path="after-overview-expanded.png")
        browser.close()
finally:
    server.terminate()

fails = [r for r in results if not r[1]]
print(f"\n{len(results)-len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
