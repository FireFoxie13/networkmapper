#!/usr/bin/env python3
"""Assertion-guarded patcher for azure-net-map.html.
Every patch asserts its exact occurrence count before replacing.
Any mismatch aborts loudly with the patch name. Nothing silently no-ops.
"""
import sys

SRC = "azure-net-map.html"
html = open(SRC, encoding="utf-8").read()
applied = []

def patch(name, old, new, count=1):
    global html
    n = html.count(old)
    if n != count:
        print(f"FAIL {name}: expected {count} occurrence(s), found {n}")
        print("---- old string ----")
        print(old)
        sys.exit(1)
    html = html.replace(old, new)
    applied.append(name)

# ---------------------------------------------------------------- P1
# depNeighbors copies blockRule/blockGroup off the edge but not blockLayer,
# so renderDeps printed "blocked at ?" for every deny. Two branches (src, dst).
patch("P1 blockLayer propagated in depNeighbors",
 'cur.blockRule=e.blockRule||cur.blockRule;cur.blockGroup=e.blockGroup||cur.blockGroup;}',
 'cur.blockRule=e.blockRule||cur.blockRule;cur.blockGroup=e.blockGroup||cur.blockGroup;cur.blockLayer=e.blockLayer||cur.blockLayer;}',
 count=2)

# ---------------------------------------------------------------- P2
# Deps view geometry: taller rows (name + IP + location per node), wider side
# margins so long names stop clipping at the card edge, reserved bottom band.
patch("P2a deps row pitch and height",
"""  const W=el.clientWidth||900;
  const rows=Math.max(sources.length,dests.length,1);
  const H=Math.max(360,rows*46+90);""",
"""  const W=el.clientWidth||900;
  const rows=Math.max(sources.length,dests.length,1);
  const ROW=66;                                   // room for name + IP + location per node
  const H=Math.max(420,rows*ROW+170);             // extra bottom band for the blocked-at note""")

patch("P2b deps margins and yFor",
"""  const cx=W/2, cy=H/2, lx=Math.max(150,W*0.20), rx=Math.min(W-150,W*0.80);
  const yFor=(i,n)=>(H/2)-((n-1)*46)/2+i*46;""",
"""  const cx=W/2, cy=H/2, lx=Math.max(230,W*0.24), rx=Math.min(W-230,W*0.76);
  const yFor=(i,n)=>(H/2)-((n-1)*ROW)/2+i*ROW;""")

# ---------------------------------------------------------------- P3
# halo() helper: white outline painted under the glyphs, as presentation
# attributes (not CSS) so Export PNG keeps it after serialization.
patch("P3 halo helper defined",
"""const edgeMarker=d=>d.kind==="traffic"?(d.denied?"url(#ar-bad)":"url(#ar-traffic)"):null;""",
"""const edgeMarker=d=>d.kind==="traffic"?(d.denied?"url(#ar-bad)":"url(#ar-traffic)"):null;
// White halo under label glyphs so text stays readable where lines cross it.
// Presentation attributes, not CSS, so Export PNG serializes them too.
const halo=t=>t.attr("paint-order","stroke").attr("stroke","#FFFFFF").attr("stroke-width",3).attr("stroke-linejoin","round");""")

# ---------------------------------------------------------------- P4
# Deps labels: pin each edge label beside its OWN node at that node's row
# height, and collect the long "blocked at" strings into a bottom band
# instead of printing them in the middle where they ran under nodes.
patch("P4a denyNotes collector",
"  const depPaths=[];",
"""  const depPaths=[];
  const denyNotes=[];""")

patch("P4b per-node label anchoring, deny note collection",
"""      const lbl=d.denied?(d.label?d.label+" denied":"denied"):d.label;
      if(lbl){
        // Labels sat on top of each other when several sources shared a destination.
        // Anchor each near its OWN node, and stagger by row.
        const near = side==="left" ? 0.32 : 0.68;
        const lx2 = x + (cx-x)*near, ly2 = y + (cy-y)*near;
        const bump = (i%2)? 12 : 0;
        g.append("text").attr("x",lx2).attr("y",ly2-6-bump).attr("text-anchor","middle")
          .attr("font-family",MONO).attr("font-size",9.5).attr("fill",d.denied?"#DC3545":"#5A6678").text(lbl);
        if(d.total) g.append("text").attr("x",lx2).attr("y",ly2+5-bump).attr("text-anchor","middle")
          .attr("font-family",MONO).attr("font-size",8.5).attr("fill","#98A2B0")
          .text(Number(d.total).toLocaleString()+" flows");
        // Only the first denied edge prints the long "blocked at" string; the panel has the rest.
        if(d.denied&&i===0&&(d.blockRule||d.blockGroup))
          g.append("text").attr("x",cx).attr("y",cy+(side==="left"?-58:74)).attr("text-anchor","middle")
            .attr("font-family",MONO).attr("font-size",9).attr("fill","#B02A37")
            .text("blocked at "+(DENY_LAYER[d.blockLayer]||"?")+(d.blockGroup?" "+d.blockGroup:"")+(d.blockRule?" / "+d.blockRule:""));
      }""",
"""      const lbl=d.denied?(d.label?d.label+" denied":"denied"):d.label;
      if(lbl){
        // Pin each label beside its OWN node, on the centre side, at that node's
        // row height. Rows never share a y, so labels can never sit on each other.
        const ax = side==="left" ? x+20 : x-20;
        const anch = side==="left" ? "start" : "end";
        halo(g.append("text")).attr("x",ax).attr("y",y-4).attr("text-anchor",anch)
          .attr("font-family",MONO).attr("font-size",9.5).attr("fill",d.denied?"#DC3545":"#5A6678").text(lbl);
        if(d.total) halo(g.append("text")).attr("x",ax).attr("y",y+8).attr("text-anchor",anch)
          .attr("font-family",MONO).attr("font-size",8.5).attr("fill","#98A2B0")
          .text(Number(d.total).toLocaleString()+" flows");
      }
      // The long "blocked at" strings collect into one reserved band under the whole
      // diagram, where nothing else is drawn — they can no longer run under a node.
      if(d.denied&&(d.blockRule||d.blockGroup))
        denyNotes.push("blocked at "+(DENY_LAYER[d.blockLayer]||"?")+(d.blockGroup?" "+d.blockGroup:"")+(d.blockRule?" / "+d.blockRule:""));""")

patch("P4c deny band drawn under the diagram",
"""  drawSide(sources,lx,"left");
  drawSide(dests,rx,"right");""",
"""  drawSide(sources,lx,"left");
  drawSide(dests,rx,"right");
  if(denyNotes.length){
    const uniq=[...new Set(denyNotes)];
    halo(g.append("text")).attr("x",cx).attr("y",H-28).attr("text-anchor","middle")
      .attr("font-family",MONO).attr("font-size",9).attr("fill","#B02A37")
      .text(uniq[0]+(uniq.length>1?"   (+"+(uniq.length-1)+" more · hover a red line)":""));
  }""")

# ---------------------------------------------------------------- P5
# Deps side nodes: halo on name/IP, plus a third line saying WHERE the
# resource lives (subscription · resource group).
patch("P5 side node name/IP halo + location line",
"""      node.append("text").attr("x",side==="left"?x-17:x+17).attr("y",y+3)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-size",11).attr("font-weight",500).attr("fill","#1B2330")
        .text((nd.name||"").length>28?nd.name.slice(0,27)+"…":nd.name);
      const ipTxt=nd.meta&&(nd.meta.ips||nd.meta.ip||nd.meta.cidr||nd.meta.prefix);
      if(ipTxt) node.append("text").attr("x",side==="left"?x-17:x+17).attr("y",y+14)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-family",MONO).attr("font-size",8.5).attr("fill","#98A2B0")
        .text(String(ipTxt).slice(0,26));""",
"""      halo(node.append("text")).attr("x",side==="left"?x-17:x+17).attr("y",y+3)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-size",11).attr("font-weight",500).attr("fill","#1B2330")
        .text((nd.name||"").length>28?nd.name.slice(0,27)+"…":nd.name);
      const ipTxt=nd.meta&&(nd.meta.ips||nd.meta.ip||nd.meta.cidr||nd.meta.prefix);
      if(ipTxt) halo(node.append("text")).attr("x",side==="left"?x-17:x+17).attr("y",y+14)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-family",MONO).attr("font-size",8.5).attr("fill","#98A2B0")
        .text(String(ipTxt).slice(0,26));
      // Where does it live — subscription · resource group, under the IP.
      const whereTxt=[nd.subId?(subNames[nd.subId]||nd.subId.slice(0,8)):"",nd.rg||""].filter(Boolean).join(" · ");
      if(whereTxt) halo(node.append("text")).attr("x",side==="left"?x-17:x+17).attr("y",y+25)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-size",8.5).attr("fill","#AEB7C4")
        .text(whereTxt.length>38?whereTxt.slice(0,37)+"…":whereTxt);""")

# ---------------------------------------------------------------- P6
# Deps root: clickable subscription › resource group › VNet crumb.
patch("P6 clickable crumb under deps root",
"""  rg2.append("text").attr("x",cx).attr("y",cy+56).attr("text-anchor","middle")
    .attr("font-family",MONO).attr("font-size",9.5).attr("fill","#98A2B0")
    .text(TYPES[root.type].label+(root.meta.ips?" · "+root.meta.ips:root.meta.ip?" · "+root.meta.ip:""));""",
"""  rg2.append("text").attr("x",cx).attr("y",cy+56).attr("text-anchor","middle")
    .attr("font-family",MONO).attr("font-size",9.5).attr("fill","#98A2B0")
    .text(TYPES[root.type].label+(root.meta.ips?" · "+root.meta.ips:root.meta.ip?" · "+root.meta.ip:""));
  // Where the focused resource lives: subscription › resource group › VNet.
  // Each piece is clickable — sub/RG filter the overview map, the VNet re-roots here.
  (function(){
    const vo=vnetOfCache||computeVnetOf();
    const vId=vo.get(root.id);
    const pieces=[];
    if(root.subId)pieces.push({t:subNames[root.subId]||root.subId.slice(0,8),
      go:()=>{facetFilters.sub=new Set([root.subId]);facetOpen.sub=true;viewMode="overview";syncViewBtns();renderAll();}});
    if(root.rg)pieces.push({t:root.rg,
      go:()=>{facetFilters.rg=new Set([root.rg]);facetOpen.rg=true;viewMode="overview";syncViewBtns();renderAll();}});
    if(vId&&vId!==root.id){const vn=(byId.get(vId)||{}).name;
      if(vn)pieces.push({t:vn,go:()=>{depsRoot=vId;selected=vId;renderAll();}});}
    if(!pieces.length)return;
    const cg=rg2.append("g").attr("data-test","rootCrumb");
    let xw=0;
    pieces.forEach((p,i)=>{
      if(i){const sep=cg.append("text").attr("x",xw).attr("y",0).attr("font-size",9.5)
        .attr("fill","#98A2B0").text("  ›  ");xw+=sep.node().getComputedTextLength();}
      const t=halo(cg.append("text")).attr("x",xw).attr("y",0).attr("font-size",9.5)
        .attr("fill","#2F6FEB").attr("text-decoration","underline").style("cursor","pointer")
        .text(p.t.length>34?p.t.slice(0,33)+"…":p.t)
        .on("click",(ev)=>{ev.stopPropagation();p.go();});
      xw+=t.node().getComputedTextLength();
    });
    cg.attr("transform","translate("+(cx-xw/2)+","+(cy+72)+")");
  })();""")

# ---------------------------------------------------------------- P7
# Overview: double-click must not zoom; it expands/collapses one cluster.
patch("P7a disable dblclick zoom",
"""  svg.call(d3.zoom().scaleExtent([0.12,4]).on("zoom",ev=>root.attr("transform",ev.transform)));""",
"""  svg.call(d3.zoom().scaleExtent([0.12,4]).on("zoom",ev=>root.attr("transform",ev.transform)));
  svg.on("dblclick.zoom",null);   // double-click expands / collapses a cluster instead of zooming""")

patch("P7b alternate label anchor points per link",
"""  const nodes=g0.nodes.map(n=>Object.assign({},n));
  const links=g0.edges.map(e2=>Object.assign({},e2));""",
"""  const nodes=g0.nodes.map(n=>Object.assign({},n));
  const links=g0.edges.map(e2=>Object.assign({},e2));
  links.forEach((l,i)=>l._lt=(i%2)?0.40:0.60);   // alternate label anchors so converging edges do not stack labels""")

patch("P7c node dblclick expand/collapse",
"""    .on("click",(ev,d)=>{ev.stopPropagation();selected=d.id;renderPanel();ctxMenu(ev.clientX,ev.clientY,d);})""",
"""    .on("click",(ev,d)=>{ev.stopPropagation();selected=d.id;renderPanel();ctxMenu(ev.clientX,ev.clientY,d);})
    .on("dblclick",(ev,d)=>{ev.stopPropagation();hideCtx();
      if(d.type==="group"){expanded.add(d.groupKey);selected=null;renderAll();return;}
      const k=groupKeyOf(d); if(k&&expanded.has(k)){expanded.delete(k);selected=null;renderAll();}})""")

# ---------------------------------------------------------------- P8
# Overview edge labels: halo + spread the two label kinds to different
# points along the edge (in the tick handler).
patch("P8a port label halo",
"""  const lbl=root.append("g").selectAll("text").data(links.filter(l=>l.label)).join("text")
    .text(d=>d.label).attr("font-size",9.5).attr("font-family",MONO)""",
"""  const lbl=halo(root.append("g").selectAll("text").data(links.filter(l=>l.label)).join("text"))
    .text(d=>d.label).attr("font-size",9.5).attr("font-family",MONO)""")

patch("P8b blocked-at label halo",
"""  const lbl2=root.append("g").selectAll("text")
    .data(links.filter(d=>(d.denied&&(d.blockRule||d.blockGroup))||d.impaired)).join("text")""",
"""  const lbl2=halo(root.append("g").selectAll("text")
    .data(links.filter(d=>(d.denied&&(d.blockRule||d.blockGroup))||d.impaired)).join("text"))""")

patch("P8c node name halo",
"""  node.append("text")
    .text(d=>(d.name||"").length>28?d.name.slice(0,27)+"…":d.name)""",
"""  halo(node.append("text"))
    .text(d=>(d.name||"").length>28?d.name.slice(0,27)+"…":d.name)""")

patch("P8d tick positions use per-link anchor points",
"""    lbl.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2-5);
    lbl2.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2+8);""",
"""    lbl.attr("x",d=>d.source.x+(d.target.x-d.source.x)*d._lt).attr("y",d=>d.source.y+(d.target.y-d.source.y)*d._lt-5);
    lbl2.attr("x",d=>d.source.x+(d.target.x-d.source.x)*(1-d._lt)).attr("y",d=>d.source.y+(d.target.y-d.source.y)*(1-d._lt)+8);""")

# ---------------------------------------------------------------- P9
# Context menu: a resource whose cluster is expanded can fold it back.
patch("P9a ctx menu collapse item",
"""  if(isGroup)html+='<button data-a="expand">Expand cluster</button>';
  else{
    html+='<button data-a="deps">View dependencies</button>';
    html+='<button data-a="focus">Focus on this resource</button>';
  }""",
"""  if(isGroup)html+='<button data-a="expand">Expand cluster</button>';
  else{
    html+='<button data-a="deps">View dependencies</button>';
    html+='<button data-a="focus">Focus on this resource</button>';
    const ck=groupKeyOf(node);
    if(ck&&expanded.has(ck))html+='<button data-a="collapse">Collapse back into cluster</button>';
  }""")

patch("P9b ctx menu collapse handler",
"""    if(a==="expand"){expanded.add(node.groupKey);selected=null;renderAll();}""",
"""    if(a==="expand"){expanded.add(node.groupKey);selected=null;renderAll();}
    if(a==="collapse"){const k=groupKeyOf(node);if(k){expanded.delete(k);selected=null;renderAll();}}""")

# ---------------------------------------------------------------- P10
# Panel crumb: each of subscription / resource group / VNet is clickable.
patch("P10a panel crumb becomes clickable links",
"""  const crumbs=[subLabel,sel.rg,vName].filter(Boolean);
  if(crumbs.length)html+='<div class="crumb">'+crumbs.map(esc).join(" › ")+'</div>';""",
"""  const crumbParts=[];
  if(subLabel)crumbParts.push('<span class="crumbLink" data-crumb="sub" data-val="'+esc(sel.subId)+'" title="Filter the map to this subscription">'+esc(subLabel)+'</span>');
  if(sel.rg)crumbParts.push('<span class="crumbLink" data-crumb="rg" data-val="'+esc(sel.rg)+'" title="Filter the map to this resource group">'+esc(sel.rg)+'</span>');
  if(vName)crumbParts.push('<span class="crumbLink" data-crumb="vnet" data-val="'+esc(vId)+'" title="Open this VNet’s sources and destinations">'+esc(vName)+'</span>');
  if(crumbParts.length)html+='<div class="crumb">'+crumbParts.join(" › ")+'</div>';""")

patch("P10b panel crumb click handlers",
"""  panel.querySelectorAll("[data-nav]").forEach(el=>el.onclick=()=>selectNode(el.getAttribute("data-nav")));""",
"""  panel.querySelectorAll("[data-nav]").forEach(el=>el.onclick=()=>selectNode(el.getAttribute("data-nav")));
  panel.querySelectorAll(".crumbLink").forEach(cl=>cl.onclick=(ev)=>{
    ev.stopPropagation();
    const kind=cl.getAttribute("data-crumb"), val=cl.getAttribute("data-val");
    if(kind==="vnet"){depsRoot=val;selected=val;viewMode="deps";syncViewBtns();renderAll();return;}
    facetFilters[kind]=new Set([val]);facetOpen[kind]=true;viewMode="overview";syncViewBtns();renderAll();
    const info=document.getElementById("focusInfo");
    if(info)info.textContent=(kind==="sub"?"Subscription":"Resource group")+' filtered to "'+cl.textContent+'" · clear it in the sidebar';
  });""")

# ---------------------------------------------------------------- P11
# crumbLink styling
patch("P11 crumbLink CSS",
"""  #panel .crumb{font-size:10.5px;color:var(--faint);margin-bottom:5px;font-family:ui-monospace,Menlo,monospace}""",
"""  #panel .crumb{font-size:10.5px;color:var(--faint);margin-bottom:5px;font-family:ui-monospace,Menlo,monospace}
  #panel .crumbLink{color:#2F6FEB;cursor:pointer;text-decoration:underline;text-underline-offset:2px}
  #panel .crumbLink:hover{color:#1B4FBF}""")

# ---------------------------------------------------------------- P12
# Sidebar help text: document the new gestures.
patch("P12 sidebar help text",
"""'Click a cluster to expand it.<br><br>Click any resource, then <b>View dependencies</b> for its sources and destinations with ports.<br><br>'""",
"""'Double-click a cluster to expand just that one. Double-click one of its resources to fold it back. The toolbar Expand/Collapse buttons work on many clusters at once.<br><br>Click any resource, then <b>View dependencies</b> for its sources and destinations with ports.<br><br>'""")


# ---------------------------------------------------------------- P13
# renderAll rendered the graph BEFORE the detail panel opened, so the SVG was
# sized for the wide card and then squeezed when the panel appeared — right-side
# labels ended up outside the visible card. Panel first, then size the graph.
patch("P13 panel opens before the graph is sized",
"""function renderAll(){renderSidebar();renderGraph();renderPanel();}""",
"""function renderAll(){renderSidebar();renderPanel();renderGraph();}   // panel first: the graph must size to the final card width""")

# ---------------------------------------------------------------- P14
# One truncated "sub \u00b7 rg" line hid the resource group. Two lines, full width.
patch("P14 location shown as two full lines",
"""      // Where does it live — subscription \u00b7 resource group, under the IP.
      const whereTxt=[nd.subId?(subNames[nd.subId]||nd.subId.slice(0,8)):"",nd.rg||""].filter(Boolean).join(" \u00b7 ");
      if(whereTxt) halo(node.append("text")).attr("x",side==="left"?x-17:x+17).attr("y",y+25)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-size",8.5).attr("fill","#AEB7C4")
        .text(whereTxt.length>38?whereTxt.slice(0,37)+"…":whereTxt);""",
"""      // Where does it live — subscription on one line, resource group on the next.
      const trunc34=t2=>t2.length>34?t2.slice(0,33)+"…":t2;
      const whereSub=nd.subId?(subNames[nd.subId]||nd.subId.slice(0,8)):"";
      if(whereSub) halo(node.append("text")).attr("x",side==="left"?x-17:x+17).attr("y",y+25)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-size",8.5).attr("fill","#AEB7C4").text(trunc34(whereSub));
      if(nd.rg) halo(node.append("text")).attr("x",side==="left"?x-17:x+17).attr("y",y+36)
        .attr("text-anchor",side==="left"?"end":"start")
        .attr("font-size",8.5).attr("fill","#AEB7C4").text(trunc34(nd.rg));""")


# ---------------------------------------------------------------- P15
# With the panel open the deps card is narrow; the centre crumb must fit the
# free corridor between the two label columns or it collides with row labels.
patch("P15 crumb truncated to the free centre corridor",
"""    if(!pieces.length)return;
    const cg=rg2.append("g").attr("data-test","rootCrumb");
    let xw=0;
    pieces.forEach((p,i)=>{
      if(i){const sep=cg.append("text").attr("x",xw).attr("y",0).attr("font-size",9.5)
        .attr("fill","#98A2B0").text("  ›  ");xw+=sep.node().getComputedTextLength();}
      const t=halo(cg.append("text")).attr("x",xw).attr("y",0).attr("font-size",9.5)
        .attr("fill","#2F6FEB").attr("text-decoration","underline").style("cursor","pointer")
        .text(p.t.length>34?p.t.slice(0,33)+"…":p.t)
        .on("click",(ev)=>{ev.stopPropagation();p.go();});
      xw+=t.node().getComputedTextLength();
    });
    cg.attr("transform","translate("+(cx-xw/2)+","+(cy+72)+")");""",
"""    if(!pieces.length)return;
    // Fit inside the corridor between the two label columns, whatever the card width.
    const corridor=Math.max(240,(rx-lx)-260);
    const cap=Math.max(10,Math.floor(corridor/pieces.length/6)-3);
    const cut=t2=>t2.length>cap?t2.slice(0,cap-1)+"…":t2;
    const cg=rg2.append("g").attr("data-test","rootCrumb");
    let xw=0;
    pieces.forEach((p,i)=>{
      if(i){const sep=cg.append("text").attr("x",xw).attr("y",0).attr("font-size",9.5)
        .attr("fill","#98A2B0").text(" › ");xw+=sep.node().getComputedTextLength();}
      const t=halo(cg.append("text")).attr("x",xw).attr("y",0).attr("font-size",9.5)
        .attr("fill","#2F6FEB").attr("text-decoration","underline").style("cursor","pointer")
        .text(cut(p.t))
        .on("click",(ev)=>{ev.stopPropagation();p.go();});
      t.append("title").text(p.t);   // hover shows the untruncated name
      xw+=t.node().getComputedTextLength();
    });
    cg.attr("transform","translate("+(cx-xw/2)+","+(cy+72)+")");""")

# ---------------------------------------------------------------- P16
# Search order: an exact resource name or IP wins; then a subscription / RG /
# VNet name (exact, then contains) filters the map; a partial resource-name
# match comes last. Typing "iam101" now shows the subscription instead of
# jumping to whichever resource shares the prefix.
patch("P16 search prefers exact match, then scope, then partial resource",
r'''function jumpToScope(q){
  const ls=low(q.trim());
  if(!ls)return false;
  const tryFacet=(kind,label)=>{
    // facetValues is keyed by id (subscription id, resource-group name, vnet id) and
    // carries the human label. Match the label; filter on the key.
    const vals=facetValues(kind);
    const keys=Object.keys(vals);
    const nameOf=k=>low(vals[k].label||k);
    const key = keys.find(k=>nameOf(k)===ls) || keys.find(k=>nameOf(k).includes(ls));
    if(!key)return false;''',
r'''function jumpToScope(q,mode){
  const ls=low(q.trim());
  if(!ls)return false;
  const tryFacet=(kind,label)=>{
    // facetValues is keyed by id (subscription id, resource-group name, vnet id) and
    // carries the human label. Match the label; filter on the key.
    const vals=facetValues(kind);
    const keys=Object.keys(vals);
    const nameOf=k=>low(vals[k].label||k);
    const key = mode==="partial"
      ? keys.find(k=>nameOf(k).includes(ls))
      : keys.find(k=>nameOf(k)===ls);
    if(!key)return false;''')

patch("P16b jumpTo reordered",
r'''function jumpTo(q){
  const hit=lookup(q);
  const info=document.getElementById("focusInfo");
  if(!hit){
    if(jumpToScope(q))return;
    info.textContent='Nothing matches "'+q+'". Try a VM name, an IP, or a subscription, resource group or VNet name.';
    return;
  }''',
r'''function jumpTo(q){
  const hit=lookup(q);
  const info=document.getElementById("focusInfo");
  // An exact resource name (or an IP) wins outright. Otherwise a subscription,
  // resource group or VNet name filters the map before partial resource names
  // get a say, so "iam101" shows the subscription, not a lookalike resource.
  const exactHit = hit && (isIp(q.trim()) || low(hit.node.name)===low(q.trim()));
  if(!exactHit){
    if(jumpToScope(q,"exact"))return;
    if(jumpToScope(q,"partial"))return;
  }
  if(!hit){
    info.textContent='Nothing matches "'+q+'". Try a VM name, an IP, or a subscription, resource group or VNet name.';
    return;
  }''')

# ---------------------------------------------------------------- P17
# Sidebar facet filters shape the overview; a dependency view must show every
# connection the resource actually has, or "0 sources" becomes a lie.
patch("P17a deps ignores sidebar filters",
r'''  let {sources,dests}=depNeighbors(depsRoot);
  const keep=n=>{const nd=byId.get(n.id); return nd?passesFacets(nd):true;};
  sources=sources.filter(keep); dests=dests.filter(keep);''',
r'''  let {sources,dests}=depNeighbors(depsRoot);
  // Sidebar facet filters shape the overview. A dependency view must show every
  // connection the resource actually has, or "0 sources" becomes a lie.
  const facetsActive=Object.values(facetFilters).some(s2=>s2.size>0);''')

patch("P17b note when sidebar filters are active",
r'''  g.append("text").attr("x",rx).attr("y",26).attr("text-anchor","middle")
    .attr("font-size",10).attr("font-weight",600).attr("letter-spacing","0.06em").attr("fill","#98A2B0")
    .text(dests.length+" DESTINATIONS");''',
r'''  g.append("text").attr("x",rx).attr("y",26).attr("text-anchor","middle")
    .attr("font-size",10).attr("font-weight",600).attr("letter-spacing","0.06em").attr("fill","#98A2B0")
    .text(dests.length+" DESTINATIONS");
  if(facetsActive)
    halo(g.append("text")).attr("x",cx).attr("y",26).attr("text-anchor","middle")
      .attr("font-size",9.5).attr("fill","#98A2B0")
      .text("sidebar filters do not apply here: every connection is shown");''')

# ---------------------------------------------------------------- P18
# The empty-state message sat on the new crumb line.
patch("P18 empty-state message below the crumb",
r'''    g.append("text").attr("x",cx).attr("y",cy+80).attr("text-anchor","middle")''',
r'''    g.append("text").attr("x",cx).attr("y",cy+104).attr("text-anchor","middle")''')

# ---------------------------------------------------------------- P19
# "Show only this cluster": isolate a subscription / RG / VNet cluster by
# setting the matching facet filter and expanding it, from the context menu
# and from the cluster panel.
patch("P19a ctx menu isolate item",
r'''  if(isGroup)html+='<button data-a="expand">Expand cluster</button>';''',
r'''  if(isGroup){
    html+='<button data-a="expand">Expand cluster</button>';
    const gk=(node.groupKey||"").split("|")[0];
    if(["sub","rg","vnet"].includes(gk))html+='<button data-a="isolate">Show only this cluster</button>';
  }''')

patch("P19b ctx menu isolate handler",
r'''    if(a==="expand"){expanded.add(node.groupKey);selected=null;renderAll();}''',
r'''    if(a==="expand"){expanded.add(node.groupKey);selected=null;renderAll();}
    if(a==="isolate"){isolateCluster(node);}''')

patch("P19c isolateCluster helper",
r'''function hideCtx(){const el=document.getElementById("ctx"); if(el)el.style.display="none";}''',
r'''function hideCtx(){const el=document.getElementById("ctx"); if(el)el.style.display="none";}
// Show only this cluster: filter the map down to the subscription / resource
// group / VNet behind the cluster, and open it so its members are visible.
function isolateCluster(grp){
  const bar=(grp.groupKey||"").indexOf("|");
  const kind=(grp.groupKey||"").slice(0,bar), rest=(grp.groupKey||"").slice(bar+1);
  if(kind==="sub")facetFilters.sub=new Set([rest]);
  else if(kind==="rg"){const cutAt=rest.indexOf("/");facetFilters.sub=new Set([rest.slice(0,cutAt)]);facetFilters.rg=new Set([rest.slice(cutAt+1)]);}
  else if(kind==="vnet")facetFilters.vnet=new Set([rest]);
  else return;
  expanded.add(grp.groupKey);selected=null;renderAll();
  const info=document.getElementById("focusInfo");
  if(info)info.textContent='Showing only "'+grp.name+'". Use the sidebar "all" links to bring everything back.';
}''')

patch("P19d panel isolate button",
r'''    gh+='<button class="btn gold" id="expandBtn" style="width:100%;margin-top:12px">Expand this cluster</button>';''',
r'''    gh+='<button class="btn gold" id="expandBtn" style="width:100%;margin-top:12px">Expand this cluster</button>';
    const gk0=(sel.groupKey||"").split("|")[0];
    if(["sub","rg","vnet"].includes(gk0))gh+='<button class="btn" id="isolateBtn" style="width:100%;margin-top:6px">Show only this cluster</button>';''')

patch("P19e panel isolate handler",
r'''    document.getElementById("expandBtn").onclick=()=>{expanded.add(sel.groupKey);selected=null;renderAll();};''',
r'''    document.getElementById("expandBtn").onclick=()=>{expanded.add(sel.groupKey);selected=null;renderAll();};
    const ib=document.getElementById("isolateBtn");
    if(ib)ib.onclick=()=>isolateCluster(sel);''')

# ---------------------------------------------------------------- P20
# Help text mentions the isolate action.
patch("P20 help text mentions isolate",
"""clusters at once.<br><br>Click any resource""",
"""clusters at once. Click a cluster and choose <b>Show only this cluster</b> to hide everything else.<br><br>Click any resource""")

# ---------------------------------------------------------------- P21
# State + zoom plumbing: one active isolation (so collapsing restores the
# previous filters) and a handle on the overview zoom so Inspect can close in.
patch("P21a isolation + zoom globals",
r'''let expanded=new Set();''',
r'''let expanded=new Set();
let isolated=null;            // the one active "hide everything else": {prev facet sets, groupKey}
let gZoom=null,gZoomSvg=null,gSimNodes=null,gGraphW=900,gGraphH=580;''')

patch("P21b renderGraph keeps a zoom handle",
r'''  svg.call(d3.zoom().scaleExtent([0.12,4]).on("zoom",ev=>root.attr("transform",ev.transform)));
  svg.on("dblclick.zoom",null);   // double-click expands / collapses a cluster instead of zooming''',
r'''  const zb=d3.zoom().scaleExtent([0.12,4]).on("zoom",ev=>root.attr("transform",ev.transform));
  svg.call(zb);
  svg.on("dblclick.zoom",null);   // double-click expands / collapses a cluster instead of zooming
  gZoom=zb; gZoomSvg=svg; gGraphW=W; gGraphH=H;''')

patch("P21c renderGraph exposes sim nodes for zoom lookups",
r'''  links.forEach((l,i)=>l._lt=(i%2)?0.40:0.60);   // alternate label anchors so converging edges do not stack labels''',
r'''  links.forEach((l,i)=>l._lt=(i%2)?0.40:0.60);   // alternate label anchors so converging edges do not stack labels
  gSimNodes=nodes;''')

patch("P21d deps view clears the overview zoom handle",
r'''function renderDeps(){
  stopParticles();''',
r'''function renderDeps(){
  stopParticles();
  gZoom=null; gZoomSvg=null; gSimNodes=null;   // the overview zoom handle must not act on this view''')

# ---------------------------------------------------------------- P22
# isolateCluster remembers what it replaced; deIsolateIf puts it back.
patch("P22 isolate snapshots filters; deIsolateIf restores them",
r'''function isolateCluster(grp){
  const bar=(grp.groupKey||"").indexOf("|");
  const kind=(grp.groupKey||"").slice(0,bar), rest=(grp.groupKey||"").slice(bar+1);
  if(kind==="sub")facetFilters.sub=new Set([rest]);
  else if(kind==="rg"){const cutAt=rest.indexOf("/");facetFilters.sub=new Set([rest.slice(0,cutAt)]);facetFilters.rg=new Set([rest.slice(cutAt+1)]);}
  else if(kind==="vnet")facetFilters.vnet=new Set([rest]);
  else return;
  expanded.add(grp.groupKey);selected=null;renderAll();
  const info=document.getElementById("focusInfo");
  if(info)info.textContent='Showing only "'+grp.name+'". Use the sidebar "all" links to bring everything back.';
}''',
r'''function isolateCluster(grp){
  const bar=(grp.groupKey||"").indexOf("|");
  const kind=(grp.groupKey||"").slice(0,bar), rest=(grp.groupKey||"").slice(bar+1);
  if(!["sub","rg","vnet"].includes(kind))return;
  // Remember what the sidebar looked like, so folding the cluster restores it.
  isolated={groupKey:grp.groupKey,prev:{sub:new Set(facetFilters.sub),rg:new Set(facetFilters.rg),
    vnet:new Set(facetFilters.vnet),type:new Set(facetFilters.type)}};
  if(kind==="sub")facetFilters.sub=new Set([rest]);
  else if(kind==="rg"){const cutAt=rest.indexOf("/");facetFilters.sub=new Set([rest.slice(0,cutAt)]);facetFilters.rg=new Set([rest.slice(cutAt+1)]);}
  else if(kind==="vnet")facetFilters.vnet=new Set([rest]);
  expanded.add(grp.groupKey);selected=null;renderAll();
  const info=document.getElementById("focusInfo");
  if(info)info.textContent='Showing only "'+grp.name+'". Double-click any of its resources to put everything back.';
}
// If this cluster was opened with "hide everything else", bring the rest back.
function deIsolateIf(groupKey){
  if(!isolated||isolated.groupKey!==groupKey)return false;
  facetFilters={sub:isolated.prev.sub,rg:isolated.prev.rg,vnet:isolated.prev.vnet,type:isolated.prev.type};
  isolated=null;
  return true;
}
// Glide the overview viewport onto one node.
function zoomToNodeById(id,scale){
  if(!gZoom||!gZoomSvg||!gSimNodes)return;
  const n=gSimNodes.find(x=>x.id===id); if(!n)return;
  const k=scale||1.7;
  gZoomSvg.transition().duration(450)
    .call(gZoom.transform,d3.zoomIdentity.translate(gGraphW/2-k*n.x,gGraphH/2-k*n.y).scale(k));
}''')

# ---------------------------------------------------------------- P23
# Cluster menu: Expand now hides everything else by default; keeping the
# rest of the map is the explicit secondary choice.
patch("P23 cluster menu: expand isolates by default",
r'''  if(isGroup){
    html+='<button data-a="expand">Expand cluster</button>';
    const gk=(node.groupKey||"").split("|")[0];
    if(["sub","rg","vnet"].includes(gk))html+='<button data-a="isolate">Show only this cluster</button>';
  }''',
r'''  if(isGroup){
    const gk=(node.groupKey||"").split("|")[0];
    if(["sub","rg","vnet"].includes(gk)){
      html+='<button data-a="isolate">Expand cluster (hide everything else)</button>';
      html+='<button data-a="expand">Expand without hiding the rest</button>';
    } else html+='<button data-a="expand">Expand cluster</button>';
  }''')

# ---------------------------------------------------------------- P24
# Double-click on a cluster isolates it; double-click on a member restores.
patch("P24 dblclick isolates and restores",
r'''    .on("dblclick",(ev,d)=>{ev.stopPropagation();hideCtx();
      if(d.type==="group"){expanded.add(d.groupKey);selected=null;renderAll();return;}
      const k=groupKeyOf(d); if(k&&expanded.has(k)){expanded.delete(k);selected=null;renderAll();}})''',
r'''    .on("dblclick",(ev,d)=>{ev.stopPropagation();hideCtx();
      if(d.type==="group"){
        const gk=(d.groupKey||"").split("|")[0];
        if(["sub","rg","vnet"].includes(gk))isolateCluster(d);
        else{expanded.add(d.groupKey);selected=null;renderAll();}
        return;
      }
      const k=groupKeyOf(d); if(k&&expanded.has(k)){deIsolateIf(k);expanded.delete(k);selected=null;renderAll();}})''')

# ---------------------------------------------------------------- P25
# Context-menu collapse also restores what isolate hid.
patch("P25 ctx collapse restores filters",
r'''    if(a==="collapse"){const k=groupKeyOf(node);if(k){expanded.delete(k);selected=null;renderAll();}}''',
r'''    if(a==="collapse"){const k=groupKeyOf(node);if(k){deIsolateIf(k);expanded.delete(k);selected=null;renderAll();}}''')

# ---------------------------------------------------------------- P26
# Panel buttons mirror the menu.
patch("P26a panel buttons: primary isolates",
r'''    gh+='<button class="btn gold" id="expandBtn" style="width:100%;margin-top:12px">Expand this cluster</button>';
    const gk0=(sel.groupKey||"").split("|")[0];
    if(["sub","rg","vnet"].includes(gk0))gh+='<button class="btn" id="isolateBtn" style="width:100%;margin-top:6px">Show only this cluster</button>';''',
r'''    const gk0=(sel.groupKey||"").split("|")[0];
    const canIso=["sub","rg","vnet"].includes(gk0);
    gh+='<button class="btn gold" id="expandBtn" style="width:100%;margin-top:12px">'+(canIso?"Expand this cluster (hide everything else)":"Expand this cluster")+'</button>';
    if(canIso)gh+='<button class="btn" id="expandKeepBtn" style="width:100%;margin-top:6px">Expand without hiding the rest</button>';''')

patch("P26b panel button handlers",
r'''    document.getElementById("expandBtn").onclick=()=>{expanded.add(sel.groupKey);selected=null;renderAll();};
    const ib=document.getElementById("isolateBtn");
    if(ib)ib.onclick=()=>isolateCluster(sel);''',
r'''    document.getElementById("expandBtn").onclick=()=>{
      if(canIso)isolateCluster(sel);
      else{expanded.add(sel.groupKey);selected=null;renderAll();}
    };
    const kb=document.getElementById("expandKeepBtn");
    if(kb)kb.onclick=()=>{expanded.add(sel.groupKey);selected=null;renderAll();};''')

# ---------------------------------------------------------------- P27
# Inspect closes in on the node it opened.
patch("P27 inspect zooms to the node",
r'''    if(a==="inspect"){selectNode(node.id);}''',
r'''    if(a==="inspect"){selectNode(node.id);setTimeout(()=>zoomToNodeById(node.id,node.type==="group"?1.5:1.8),650);}''')

# ---------------------------------------------------------------- P28
# Help text describes the new default.
patch("P28 help text: expand hides the rest by default",
"""Double-click a cluster to expand just that one. Double-click one of its resources to fold it back. The toolbar Expand/Collapse buttons work on many clusters at once. Click a cluster and choose <b>Show only this cluster</b> to hide everything else.<br><br>""",
"""Double-click a cluster to open it and hide everything else; Inspect zooms in on it. To open a cluster but keep the rest of the map, use <b>Expand without hiding the rest</b> in its click menu. Double-click one of its resources to put everything back. The toolbar Expand/Collapse buttons work on many clusters at once.<br><br>""")

# ---------------------------------------------------------------- P29
# Remediation engine. For a denied flow, work out what to change, where, and at
# what priority, honouring Azure's evaluation order. Produces a copyable az
# command plus, where possible, a proposal to narrow the offending rule instead.
patch("P29 remediation engine",
r'''/* Every denied path, grouped by the NSG / rule that Azure says blocked it. */''',
r'''/* ================= remediation: what to change, and where =================
   Evaluation order in Azure is fixed:
     1. AVNM security admin rules   (a Deny here cannot be overridden by an NSG)
     2. NSG rules                   (subnet, then NIC)
     3. Azure Firewall              (only for traffic routed through it)
   Route tables never "deny": a next hop of None discards the packet silently.
   So the fix must target the layer that actually decided, never a lower one.
   Everything below is a PROPOSAL for review. Nothing here runs against Azure. */

// Lower number = evaluated first. Find a free slot just ahead of the deny.
function freePriorityBelow(rules,denyPri,floor){
  const used=new Set((rules||[]).map(r=>+r.priority).filter(n=>!isNaN(n)));
  const start=Math.max(floor,denyPri-10);
  for(let x=start;x<denyPri;x++) if(!used.has(x))return x;
  for(let x=floor;x<denyPri;x++) if(!used.has(x))return x;
  return null;
}
// Pull the named segment out of an ARM resource id.
function armSeg(id,key){
  const parts=String(id||"").split("/");
  for(let i=0;i<parts.length-1;i++) if(low(parts[i])===low(key))return parts[i+1];
  return "";
}
// Prefer the source's own subnet over a bare /32 when we can see it.
function srcScopeOf(ip){
  const sn=subnetOfIp(ip);
  return (sn&&sn.meta&&sn.meta.prefix)?String(sn.meta.prefix).split(",")[0].trim():ip+"/32";
}
const protoFlag=p=>{const s=String(p||"").toUpperCase();return (s==="TCP"||s==="UDP"||s==="ICMP")?s:"*";};

// The whole recommendation for one denied flow row.
function remediationFor(r){
  if(!r)return null;
  const port=String(r.port||"*"), proto=protoFlag(r.proto);
  const srcScope=srcScopeOf(r.srcIp), dstScope=r.dstIp+"/32";
  const layer=denyLayerOf(r);
  const out={layer:DENY_LAYER[layer]||"Unknown layer",order:"",actions:[],refine:null};

  // ---- route drop: no rule denied it; the platform discarded it ----
  if(r.routeDrop||layer==="route"){
    const rt=fullGraph.nodes.find(n=>n.type==="rt"&&low(n.name)===low(r.rtName||""));
    const rg=(rt&&rt.rg)||"<resource-group>", name=(rt&&rt.name)||r.rtName||"<route-table>";
    const routeName=(rt&&rt.meta&&rt.meta.routeNames&&rt.meta.routeNames[r.rtPrefix])||"<route-name>";
    out.order="A next hop of None discards the packet on the platform. No rule denied it, "+
              "and nothing is logged as a deny. Either the prefix should be dropped, or the route is wrong.";
    out.actions.push({label:"If this traffic is legitimate: remove the blackhole route",
      note:"Deletes the route for "+r.rtPrefix+". Confirm nothing else relies on it being dropped.",
      cmd:"az network route-table route delete -g "+rg+" --route-table-name "+name+" -n "+routeName});
    out.actions.push({label:"Or send it to the firewall instead of dropping it",
      note:"Keeps the prefix steered, but through inspection rather than into a black hole.",
      cmd:"az network route-table route update -g "+rg+" --route-table-name "+name+" -n "+routeName+
          " --next-hop-type VirtualAppliance --next-hop-ip-address <firewall-private-ip>"});
    out.refine={what:"Route "+r.rtPrefix+" -> None on "+name,
      why:"This prefix covers "+r.dstIp+", which is receiving real traffic. Narrow the prefix so it "+
          "only covers what you actually intend to blackhole."};
    return out;
  }

  // ---- Azure Firewall ----
  if(layer==="fw"){
    const pol=r.fwPolicy||"<firewall-policy>";
    const polNode=fullGraph.nodes.find(n=>n.type==="fwpolicy"&&low(n.name)===low(pol));
    const rg=(polNode&&polNode.rg)||"<resource-group>";
    out.order="Azure Firewall decided this. NSG and AVNM already allowed it, so the change belongs in the firewall policy.";
    out.actions.push({label:"Add an allow rule to the firewall policy",
      note:"Put it in a rule collection whose priority is lower (earlier) than the collection holding \""+
           (r.fwRule||"the deny")+"\".",
      cmd:"az network firewall policy rule-collection-group collection rule add \\\n"+
          "  -g "+rg+" --policy-name "+pol+" --rule-collection-group-name <rcg-name> \\\n"+
          "  --collection-name <allow-collection> --name allow-"+port+"-"+proto.toLowerCase()+" \\\n"+
          "  --rule-type NetworkRule --protocols "+(proto==="*"?"Any":proto)+" \\\n"+
          "  --source-addresses "+srcScope+" --destination-addresses "+dstScope+" --destination-ports "+port});
    if(r.fwRule)out.refine={what:"Firewall rule "+r.fwRule+" in policy "+pol,
      why:"If this rule is a broad catch-all, narrowing its source or destination is safer than "+
          "stacking an allow in front of it."};
    return out;
  }

  const def=ruleDefinition(r.aclGroup,r.aclRule);   // {owner, rule} when we can see the rule
  const rule=def&&def.rule, owner=def&&def.owner;

  // ---- AVNM security admin rule ----
  if(layer==="avnm"){
    out.order="An AVNM security admin Deny is evaluated BEFORE every NSG. Adding an NSG allow will not help. "+
              "The change has to be made in AVNM itself.";
    if(owner){
      const nm=armSeg(owner.id,"networkManagers"),
            cfg=armSeg(owner.id,"securityAdminConfigurations"),
            rc=armSeg(owner.id,"ruleCollections"), rg=owner.rg||"<resource-group>";
      const pri=rule?freePriorityBelow(owner.meta.rules,+rule.priority,1):null;
      out.actions.push({label:"Add an Allow admin rule ahead of the deny"+(pri?" (priority "+pri+")":""),
        note:"Allow lets the traffic past AVNM and still evaluates your NSGs. Use AlwaysAllow only if you "+
             "also want NSGs bypassed, which is rarely what you want. Deploy the configuration afterwards.",
        cmd:"az network manager security-admin-config rule-collection rule create \\\n"+
            "  -g "+rg+" --network-manager-name "+nm+" --configuration-name "+cfg+" \\\n"+
            "  --rule-collection-name "+rc+" --rule-name allow-"+port+"-"+proto.toLowerCase()+" \\\n"+
            "  --kind Custom --protocol "+(proto==="*"?"Any":proto)+" --access Allow --priority "+(pri||"<free-priority>")+
            " --direction "+((rule&&rule.direction)||"Outbound")+" \\\n"+
            "  --dest-port-ranges "+port+" \\\n"+
            "  --sources '[{\"address-prefix-type\":\"IPPrefix\",\"address-prefix\":\""+srcScope+"\"}]' \\\n"+
            "  --destinations '[{\"address-prefix-type\":\"IPPrefix\",\"address-prefix\":\""+dstScope+"\"}]'\n"+
            "az network manager post-commit --network-manager-name "+nm+" -g "+rg+
            " --commit-type SecurityAdmin --target-locations <region> --configuration-ids "+
            owner.id.split(/\/rulecollections\//i)[0]});
      if(rule)out.refine={what:"Admin rule "+rule.name+" (#"+rule.priority+" "+rule.access+" "+
          (rule.direction||"")+" "+rule.protocol+" ports "+rule.ports+", "+rule.src+" -> "+rule.dst+")",
        why:"It matches "+r.srcIp+" -> "+r.dstIp+":"+port+" because "+
            (String(rule.dst).includes("/1")||rule.dst==="*"?"its destination range is very broad. ":"")+
            "Narrowing the destination so it no longer covers "+dstScope+
            " fixes this without adding a rule, but it also stops the deny protecting that range."};
    } else {
      out.actions.push({label:"Add an Allow admin rule ahead of \""+(r.aclRule||"the deny")+"\"",
        note:"The rule collection \""+(r.aclGroup||"?")+"\" is not in this scan, so the exact names could not be "+
             "resolved. Find it under your network manager's security admin configuration.",
        cmd:"az network manager security-admin-config rule-collection rule create \\\n"+
            "  -g <rg> --network-manager-name <nm> --configuration-name <config> \\\n"+
            "  --rule-collection-name "+(r.aclGroup||"<rule-collection>")+" --rule-name allow-"+port+"-"+proto.toLowerCase()+" \\\n"+
            "  --kind Custom --protocol "+(proto==="*"?"Any":proto)+" --access Allow --priority <free-priority> \\\n"+
            "  --sources '[{\"address-prefix-type\":\"IPPrefix\",\"address-prefix\":\""+srcScope+"\"}]' \\\n"+
            "  --destinations '[{\"address-prefix-type\":\"IPPrefix\",\"address-prefix\":\""+dstScope+"\"}]'"});
    }
    return out;
  }

  // ---- NSG, including Azure's built-in default rules ----
  const isDefault=(layer==="nsgdefault");
  out.order=isDefault
    ? "Nothing in your NSG allowed this, so Azure's built-in DenyAll rule applied. Add an explicit allow."
    : "An NSG rule decided this. Check that no AVNM deny also covers the path, or the allow will have no effect.";
  const nsgName=owner?owner.name:String(r.aclGroup||"").split("/").pop();
  const rg=owner?owner.rg:String(r.aclGroup||"").split("/")[1];
  const denyPri=rule?+rule.priority:4096;
  const pri=freePriorityBelow(owner?owner.meta.rules:[],denyPri,100);
  const dir=(rule&&rule.direction)||"Inbound";
  out.actions.push({label:"Add an allow rule ahead of the deny"+(pri?" (priority "+pri+")":""),
    note:"Scoped to the observed conversation. Widen the source only if you mean to.",
    cmd:"az network nsg rule create -g "+(rg||"<rg>")+" --nsg-name "+(nsgName||"<nsg>")+" \\\n"+
        "  -n allow-"+port+"-"+proto.toLowerCase()+" --priority "+(pri||"<free-priority>")+" \\\n"+
        "  --direction "+dir+" --access Allow --protocol "+(proto==="*"?"'*'":proto)+" \\\n"+
        "  --source-address-prefixes "+srcScope+" --destination-address-prefixes "+dstScope+" \\\n"+
        "  --destination-port-ranges "+port});
  if(rule&&!isDefault){
    out.actions.push({label:"Or narrow the deny rule so it stops matching",
      note:"Changes the existing rule instead of stacking another one in front of it.",
      cmd:"az network nsg rule update -g "+(rg||"<rg>")+" --nsg-name "+(nsgName||"<nsg>")+" -n "+rule.name+" \\\n"+
          "  --destination-address-prefixes <narrowed-list-excluding-"+dstScope+">"});
    out.refine={what:"Rule "+rule.name+" (#"+rule.priority+" "+rule.access+" "+(rule.direction||"")+" "+
        rule.protocol+" ports "+rule.ports+", "+rule.src+" -> "+rule.dst+")",
      why:"It matches this flow because source "+rule.src+" covers "+r.srcIp+
          " and destination "+rule.dst+" covers "+r.dstIp+
          (rule.ports==="*"?", and it applies to every port":", on port "+rule.ports)+"."};
  }
  return out;
}

/* Every denied path, grouped by the NSG / rule that Azure says blocked it. */''')

# ---------------------------------------------------------------- P30
# Styling for the fix block.
patch("P30 fixBox CSS",
r'''  .denyBox .dp{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:#B02A37}''',
r'''  .denyBox .dp{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:#B02A37}
  .fixBox{background:#F4F8F4;border:1px solid #CFE3D2;border-radius:8px;padding:9px 11px;margin:6px 0 9px}
  .fixBox .fh{font-size:9.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#1F6B3B;margin-bottom:4px}
  .fixBox .forder{font-size:11px;color:var(--dim);line-height:1.5;margin-bottom:6px}
  .fixBox .flabel{font-size:11.5px;font-weight:600;color:#1B2330;margin-top:6px}
  .fixBox .fnote{font-size:10.5px;color:var(--dim);line-height:1.45;margin:2px 0 4px}
  .fixBox pre{background:#FFFFFF;border:1px solid #DCE5DE;border-radius:6px;padding:7px 8px;margin:0;
    font-family:ui-monospace,Menlo,monospace;font-size:10px;line-height:1.5;color:#1B2330;
    white-space:pre-wrap;word-break:break-all;overflow-x:auto}
  .fixBox .copyFix{margin-top:4px;font-size:10.5px;color:#2F6FEB;background:none;border:none;padding:0;cursor:pointer}
  .fixBox .copyFix:hover{text-decoration:underline}
  .fixBox .refine{background:#FFFDF5;border:1px solid #EBDDB4;border-radius:6px;padding:7px 8px;margin-top:7px}
  .fixBox .refine .rt{font-size:10.5px;font-weight:600;color:#8A6100}
  .fixBox .refine .rw{font-size:10.5px;color:var(--dim);line-height:1.45;margin-top:2px}
  .fixBox .caveat{font-size:10px;color:var(--faint);margin-top:6px;line-height:1.4}''')

# ---------------------------------------------------------------- P31
# Render the recommendation inside each deny box in the panel.
patch("P31 panel renders the recommended fix",
r'''        +'<div class="dp">'+esc(r.srcIp)+' → '+esc(r.dstIp)+':'+esc(r.port)+'/'+esc(r.proto||"?")+' · '+Number(r.count).toLocaleString()+' blocked</div>'
        +'</div>';
    }
  })();''',
r'''        +'<div class="dp">'+esc(r.srcIp)+' → '+esc(r.dstIp)+':'+esc(r.port)+'/'+esc(r.proto||"?")+' · '+Number(r.count).toLocaleString()+' blocked</div>'
        +'</div>';
      html+=fixBoxHtml(r);
    }
  })();''')

patch("P31b fixBoxHtml builder",
r'''function renderPanel(){
  const panel=document.getElementById("panel");''',
r'''// Render one remediation as reviewable HTML. Proposals only: nothing is executed.
function fixBoxHtml(r){
  const fx=remediationFor(r);
  if(!fx||!fx.actions.length)return "";
  let h='<div class="fixBox"><div class="fh">Recommended fix \u00b7 '+esc(fx.layer)+'</div>';
  if(fx.order)h+='<div class="forder">'+esc(fx.order)+'</div>';
  fx.actions.forEach((a,i)=>{
    h+='<div class="flabel">'+esc(a.label)+'</div>';
    if(a.note)h+='<div class="fnote">'+esc(a.note)+'</div>';
    h+='<pre data-cmd="'+esc(a.cmd)+'">'+esc(a.cmd)+'</pre>';
    h+='<button class="copyFix" data-copy="'+esc(a.cmd)+'">Copy command</button>';
  });
  if(fx.refine)h+='<div class="refine"><div class="rt">Or refine what is already there: '+esc(fx.refine.what)+'</div>'
      +'<div class="rw">'+esc(fx.refine.why)+'</div></div>';
  h+='<div class="caveat">Proposal for review. Placeholders in &lt;angle brackets&gt; need your values. '
    +'Nothing in this tool writes to Azure. Verify with: az network watcher test-ip-flow</div>';
  return h+'</div>';
}
function renderPanel(){
  const panel=document.getElementById("panel");''')

# ---------------------------------------------------------------- P32
# Copy button wiring.
patch("P32 copy button wiring",
r'''  panel.querySelectorAll("[data-nav]").forEach(el=>el.onclick=()=>selectNode(el.getAttribute("data-nav")));''',
r'''  panel.querySelectorAll("[data-nav]").forEach(el=>el.onclick=()=>selectNode(el.getAttribute("data-nav")));
  panel.querySelectorAll(".copyFix").forEach(b=>b.onclick=(ev)=>{
    ev.stopPropagation();
    const txt=b.getAttribute("data-copy")||"";
    const done=()=>{const old=b.textContent;b.textContent="Copied";setTimeout(()=>b.textContent=old,1200);};
    if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(txt).then(done,()=>{});
    else{const ta=document.createElement("textarea");ta.value=txt;document.body.appendChild(ta);ta.select();
      try{document.execCommand("copy");done();}catch(e){}document.body.removeChild(ta);}
  });''')

# ---------------------------------------------------------------- P33
# Sidebar help mentions where the recommendations live.
patch("P33 help text mentions recommendations",
"""Red edges are denied flows. Red rings mark affected resources.<br><br>""",
"""Red edges are denied flows. Red rings mark affected resources. Click an affected resource to see, under <b>Why traffic is denied</b>, the rule that blocked it and a proposed az command to fix it.<br><br>""")

patch("P34 route table remembers route names",
r'''      const black=(p.routes||[]).filter(r=>{const rp=r.properties||r;return low(rp.nextHopType||"")==="none";})
        .map(r=>((r.properties||r).addressPrefix)||r.name);
      if(black.length)node.meta.blackhole=black.join(", ");''',
r'''      const black=(p.routes||[]).filter(r=>{const rp=r.properties||r;return low(rp.nextHopType||"")==="none";})
        .map(r=>((r.properties||r).addressPrefix)||r.name);
      if(black.length)node.meta.blackhole=black.join(", ");
      // prefix -> route name, so a remediation can name the route it wants changed
      node.meta.routeNames={};
      for(const r of (p.routes||[])){const rp=r.properties||r; if(rp.addressPrefix)node.meta.routeNames[rp.addressPrefix]=r.name||rp.name||"";}''')

# ---------------------------------------------------------------- P35
# The firewall log names the rule collection and the collection group that
# decided. Carry those onto the flow row so a remediation can address them.
patch("P35 firewall rows carry collection, group and reason",
r'''      r.denied=true; r.fwRule=d.rule; r.fwPolicy=d.policy; r.fwTable=d.table;''',
r'''      r.denied=true; r.fwRule=d.rule; r.fwPolicy=d.policy; r.fwTable=d.table;
      r.fwCollection=d.collection; r.fwGroup=d.group; r.fwReason=d.reason; r.fwDest=d.dst;''')

# ---------------------------------------------------------------- P36
# Firewall remediation, properly. Azure Firewall evaluates DNAT, then network
# rule collections, then application rule collections; inside a group, lower
# collection priority wins. A threat-intel or IDPS block has no rule to edit.
patch("P36 firewall remediation with real collections and priorities",
r'''  // ---- Azure Firewall ----
  if(layer==="fw"){
    const pol=r.fwPolicy||"<firewall-policy>";
    const polNode=fullGraph.nodes.find(n=>n.type==="fwpolicy"&&low(n.name)===low(pol));
    const rg=(polNode&&polNode.rg)||"<resource-group>";
    out.order="Azure Firewall decided this. NSG and AVNM already allowed it, so the change belongs in the firewall policy.";
    out.actions.push({label:"Add an allow rule to the firewall policy",
      note:"Put it in a rule collection whose priority is lower (earlier) than the collection holding \""+
           (r.fwRule||"the deny")+"\".",
      cmd:"az network firewall policy rule-collection-group collection rule add \\\n"+
          "  -g "+rg+" --policy-name "+pol+" --rule-collection-group-name <rcg-name> \\\n"+
          "  --collection-name <allow-collection> --name allow-"+port+"-"+proto.toLowerCase()+" \\\n"+
          "  --rule-type NetworkRule --protocols "+(proto==="*"?"Any":proto)+" \\\n"+
          "  --source-addresses "+srcScope+" --destination-addresses "+dstScope+" --destination-ports "+port});
    if(r.fwRule)out.refine={what:"Firewall rule "+r.fwRule+" in policy "+pol,
      why:"If this rule is a broad catch-all, narrowing its source or destination is safer than "+
          "stacking an allow in front of it."};
    return out;
  }''',
r'''  // ---- Azure Firewall ----
  if(layer==="fw"){
    const tbl=low(r.fwTable||"");
    const pol=r.fwPolicy||"<firewall-policy>";
    const polNode=fullGraph.nodes.find(n=>n.type==="fwpolicy"&&low(n.name)===low(pol));
    const rg=(polNode&&polNode.rg)||"<resource-group>";

    // Some firewall decisions are not rule decisions at all.
    if(tbl==="azfwthreatintel"){
      out.order="Threat intelligence stopped this, not a rule of yours. "+
                "Microsoft lists "+r.dstIp+" as malicious. Treat an allow here as a security decision, not a network fix.";
      out.actions.push({label:"If this destination is a confirmed false positive, allowlist it",
        note:"Adds one address to the threat-intel allowlist. The policy keeps blocking everything else.",
        cmd:"az network firewall policy update -g "+rg+" -n "+pol+" --ip-addresses "+r.dstIp});
      out.refine={what:"Threat intelligence on policy "+pol,
        why:"Do not fix this by setting --threat-intel-mode to Alert: that stops blocking for every "+
            "destination, not just this one. Allowlist the single address, or leave the block in place."};
      return out;
    }
    if(tbl==="azfwidpssignature"){
      out.order="An IDPS signature matched the packet. Rule processing is not what stopped it, "+
                "so no allow rule will help. Someone has to decide the signature is a false positive.";
      out.actions.push({label:"Review the signature, then bypass it only if it is a false positive",
        note:"Find the signature id in the AZFWIdpsSignature logs, then add a bypass in the policy's IDPS settings.",
        cmd:"az network firewall policy intrusion-detection add -g "+rg+" --policy-name "+pol+" \\\n"+
            "  --mode Deny --signature-mode-id <signature-id> --signature-mode-state Off"});
      return out;
    }

    // Locate the collection group and the collection holding the deny.
    let rcgName=r.fwGroup||"", collName=r.fwCollection||"";
    const rcgNode=fullGraph.nodes.find(n=>n.type==="fwrcg"&&
      (low(n.name)===low(rcgName)||(n.meta.rules||[]).some(x=>low(x.name)===low(r.fwRule||""))));
    if(rcgNode&&!rcgName)rcgName=rcgNode.name;
    const denyRule=rcgNode?(rcgNode.meta.rules||[]).find(x=>low(x.name)===low(r.fwRule||"")):null;
    const denyColPri=denyRule?+denyRule.priority:null;
    // Collection priorities inside the group; find a free slot ahead of the deny collection.
    const colPris=rcgNode?[...new Set((rcgNode.meta.rules||[]).map(x=>+x.priority).filter(n2=>!isNaN(n2)))]
      .map(p2=>({priority:p2})):[];
    const newColPri=denyColPri?freePriorityBelow(colPris,denyColPri,100):null;
    const isApp=(tbl==="azfwapplicationrule");
    const defaultDeny=!r.fwRule||/default action/i.test(r.fwReason||"");

    out.order="Azure Firewall decided this, which means the route already steers the traffic through it, "+
      "and both AVNM and the NSGs allowed it. "+
      (defaultDeny?"No rule matched, so the policy's default deny applied. ":"")+
      "Inside a collection group, the lowest collection priority is evaluated first, and network rule "+
      "collections are evaluated before application rule collections.";

    const target="  -g "+rg+" --policy-name "+pol+" --rule-collection-group-name "+(rcgName||"<rcg-name>");
    const rname="allow-"+port+"-"+proto.toLowerCase();
    // The firewall log carries the FQDN for application rules; the flow log only has an IP.
    const fqdn=r.fwDest&&!isIp(r.fwDest)?r.fwDest:"<fqdn>";
    const ruleCore=isApp
      ? "  --rule-type ApplicationRule \\\n"+
        "  --protocols "+(port==="443"?"Https=443":port==="80"?"Http=80":"Http=80 Https=443")+" \\\n"+
        "  --source-addresses "+srcScope+" --target-fqdns "+fqdn
      : "  --rule-type NetworkRule \\\n"+
        "  --ip-protocols "+(proto==="*"?"Any":proto)+" \\\n"+
        "  --source-addresses "+srcScope+" --destination-addresses "+dstScope+" --destination-ports "+port;

    out.actions.push({label:"Add an allow collection ahead of the deny"+(newColPri?" (collection priority "+newColPri+")":""),
      note:"Creates a new "+(isApp?"application":"network")+" rule collection that is evaluated before "+
           (collName?'"'+collName+'"':"the collection that denied this")+".",
      cmd:"az network firewall policy rule-collection-group collection add-filter-collection \\\n"+
          target+" \\\n"+
          "  --name "+rname+"-collection --collection-priority "+(newColPri||"<free-priority>")+
          " --action Allow \\\n"+
          "  --rule-name "+rname+" \\\n"+ruleCore});

    if(collName)out.actions.push({label:"Or add the rule to the existing allow collection",
      note:"Cleaner if you already keep a sanctioned-traffic collection ahead of the denies.",
      cmd:"az network firewall policy rule-collection-group collection rule add \\\n"+
          target+" --collection-name <existing-allow-collection> \\\n"+
          "  --name "+rname+" \\\n"+ruleCore});

    if(denyRule)out.refine={what:"Firewall rule "+denyRule.name+" in collection "+(collName||"?")+
        " (priority "+denyRule.priority+", "+denyRule.protocol+" ports "+denyRule.ports+", "+denyRule.src+" -> "+denyRule.dst+")",
      why:"It matches "+r.srcIp+" -> "+r.dstIp+":"+port+". Narrowing its source or destination is safer than "+
          "stacking an allow collection in front of it, because the allow then applies to everything that collection covers."};
    else if(defaultDeny)out.refine={what:"Policy "+pol+" default deny",
      why:"Nothing matched, so there is no rule to narrow. The only fix is an explicit allow, scoped tightly."};
    return out;
  }''')

# ---------------------------------------------------------------- P37
# Keep more sample flows per rule, so the Rules tab can show real traffic.
patch("P37 keep 12 sample flows per rule",
r'''      if(f.denied)r.deniedHits+=f.count; if(r.samples.length<5)r.samples.push(f); };''',
r'''      if(f.denied)r.deniedHits+=f.count; if(r.samples.length<12)r.samples.push(f); };''')

# ---------------------------------------------------------------- P38
# Rules tab: show the traffic that hit each rule, grouped, plus the same
# recommended fix the map panel gives, for rules that are actually denying.
patch("P38 rules tab shows traffic and the fix",
r'''        + (samples.length?'<div class="rd-h" style="margin-top:8px">Sample flows</div>'
            + samples.map(sf=>'<div class="rd-i mono'+(sf.denied?' bad':'')+'">'+esc(sf.srcIp)+' → '+esc(sf.dstIp)+':'+esc(sf.port)+'/'+esc(sf.proto||"?")
                +'  '+Number(sf.count).toLocaleString()+' flows'+(sf.denied?'  DENIED':'')
                +(sf.aclRule?'  · Azure: '+esc(sf.aclRule):'')+'</div>').join("") : "")
        +'</div></div></td></tr>';''',
r'''        + (samples.length?'<div class="rd-h" style="margin-top:8px">Traffic that hit this rule</div>'
            + samples.map(sf=>'<div class="rd-i mono'+(sf.denied?' bad':'')+'">'+esc(sf.srcIp)+' → '+esc(sf.dstIp)+':'+esc(sf.port)+'/'+esc(sf.proto||"?")
                +'  '+Number(sf.count).toLocaleString()+' flows'+(sf.bytes?'  '+fmtBytes(sf.bytes):'')+(sf.denied?'  DENIED':'')
                +(sf.aclRule?'  \u00b7 Azure: '+esc(sf.aclRule):'')+'</div>').join("")
            + ((r.samples||[]).length>samples.length?'<div class="rd-i" style="color:var(--faint)">+'
                +((r.samples||[]).length-samples.length)+' more</div>':'') : "")
        +'</div></div>'
        + (deniedSample?'<div style="padding:0 16px 12px">'+fixBoxHtml(deniedSample)+'</div>':'')
        +'</td></tr>';''')

patch("P38b compute the sample set and the denied sample",
r'''      const rnode=byId.get(r.resourceId);
      const scope=ruleScopeDescription(rnode);
      const samples=(r.samples||[]).slice(0,4);''',
r'''      const rnode=byId.get(r.resourceId);
      const scope=ruleScopeDescription(rnode);
      const samples=(r.samples||[]).slice(0,10);
      // A rule that is actually denying traffic gets the same remediation the map panel shows.
      const deniedSample=(r.samples||[]).find(sf=>sf.denied)||null;''')

patch("P38c rules tab tells you rows expand",
r'''  if(!rows.length)html+='<div class="statusline" style="padding:14px">No rules match these filters.</div>';''',
r'''  if(!rows.length)html+='<div class="statusline" style="padding:14px">No rules match these filters.</div>';
  else html='<div class="statusline" style="padding:6px 12px">Click any rule to see what it applies to, the traffic that hit it, and\u2014for rules that are denying\u2014how to fix it.</div>'+html;''')

# ---------------------------------------------------------------- P39
# Layout: a hairball forms because every node repels with the same force and
# every edge pulls with the same length, regardless of how busy the node is.
# Scale both with degree, cap the repulsion range so the graph stays bounded,
# and give the collision radius room for the label.
patch("P39a degree-aware forces",
r'''  sim=d3.forceSimulation(nodes)
    .force("link",d3.forceLink(links).id(d=>d.id)
      .distance(l=>(l.kind==="peer"?190:l.kind==="traffic"?135:l.kind==="contains"?62:78)*spread)
      .strength(l=>l.kind==="traffic"?0.05:0.45))
    .force("charge",d3.forceManyBody().strength(d=>(d.type==="group"?-900:-260)*spread))
    .force("center",d3.forceCenter(W/2,H/2))
    .force("collide",d3.forceCollide().radius(d=>rOf(d)+18*spread));''',
r'''  // How busy is each node? A hub with 30 edges needs far more room than a leaf.
  const degree=new Map();
  for(const l of links){const a=l.source.id||l.source,b=l.target.id||l.target;
    degree.set(a,(degree.get(a)||0)+1); degree.set(b,(degree.get(b)||0)+1);}
  const deg=d=>degree.get(d.id)||0;
  const labelRoom=d=>Math.min(26,(d.name||"").length*0.75);   // keep names off each other
  sim=d3.forceSimulation(nodes)
    .force("link",d3.forceLink(links).id(d=>d.id)
      // Longer edges where the endpoints are busy: this is what unpicks the yarn ball.
      .distance(l=>{
        const base=l.kind==="peer"?190:l.kind==="traffic"?135:l.kind==="contains"?62:78;
        const busy=Math.min(14,(degree.get(l.source.id||l.source)||0)+(degree.get(l.target.id||l.target)||0));
        return base*(1+0.07*busy)*spread;
      })
      .strength(l=>l.kind==="traffic"?0.05:0.45))
    // Busy nodes push harder, but repulsion is range-capped so the map cannot explode.
    .force("charge",d3.forceManyBody()
      .strength(d=>(d.type==="group"?-900-70*Math.min(12,deg(d)):-260-45*Math.min(12,deg(d)))*spread)
      .distanceMax(900*spread))
    .force("center",d3.forceCenter(W/2,H/2))
    // Weak pull to the middle: keeps stragglers on screen without crushing the layout.
    .force("xC",d3.forceX(W/2).strength(0.012))
    .force("yC",d3.forceY(H/2).strength(0.012))
    .force("collide",d3.forceCollide().radius(d=>rOf(d)+(16+labelRoom(d))*spread).strength(0.9));''')

patch("P39b tiers layout keeps the degree-aware centering off",
r'''    sim.force("center",null)
       .force("y",d3.forceY(d=>50+(TIER[d.type]??3)*((H-110)/6)).strength(d=>d.type==="group"?0.05:0.5))
       .force("x",d3.forceX(W/2).strength(0.05));''',
r'''    sim.force("center",null).force("xC",null).force("yC",null)
       .force("y",d3.forceY(d=>50+(TIER[d.type]??3)*((H-110)/6)).strength(d=>d.type==="group"?0.05:0.5))
       .force("x",d3.forceX(W/2).strength(0.05));''')

patch("P39c more room in the spread control",
r'''        <option value="0.7">Tight</option>
        <option value="1" selected>Normal</option>
        <option value="1.5">Roomy</option>
        <option value="2.2">Very roomy</option>''',
r'''        <option value="0.7">Tight</option>
        <option value="1" selected>Normal</option>
        <option value="1.5">Roomy</option>
        <option value="2.2">Very roomy</option>
        <option value="3.2">Untangle</option>
        <option value="4.5">Untangle more</option>''')

# ---------------------------------------------------------------- P40
# Honest boundary: this tool reads user-defined routes, not the effective route
# table (system + BGP + UDR merged). Say so where it matters most.
patch("P40 route remediation states the effective-route boundary",
r'''    out.refine={what:"Route "+r.rtPrefix+" -> None on "+name,
      why:"This prefix covers "+r.dstIp+", which is receiving real traffic. Narrow the prefix so it "+
          "only covers what you actually intend to blackhole."};
    return out;''',
r'''    out.refine={what:"Route "+r.rtPrefix+" -> None on "+name,
      why:"This prefix covers "+r.dstIp+", which is receiving real traffic. Narrow the prefix so it "+
          "only covers what you actually intend to blackhole. Note that this scan reads user-defined "+
          "routes only, not the effective route table, so a BGP or system route could also be steering "+
          "this traffic: confirm with az network nic show-effective-route-table --ids <nic-id>."};
    return out;''')

# ---------------------------------------------------------------- P41
# Rules scoped by Application Security Group carry no address prefixes, so they
# were parsed as "*" and the shadow test could never prove a deny covered them.
# That hid the most dangerous misconfiguration there is: a broad deny sitting at
# a lower priority number than every allow rule that is supposed to work.
#
# An ASG's members live on the NICs this NSG protects. So for an INBOUND rule the
# real destination is the prefix set the NSG is attached to, and for an OUTBOUND
# rule the real source is. Substitute that, and coverage becomes provable.
patch("P41a parseNsgRules records ASG scoping",
r'''function parseNsgRules(p){
  const many=(arr,single)=>(arr&&arr.length?arr.join(","):single||"*");
  return (p.securityRules||[]).map(r=>{const rp=r.properties||r;return{
    name:r.name,priority:rp.priority,direction:rp.direction,access:rp.access,protocol:rp.protocol,
    ports:many(rp.destinationPortRanges,rp.destinationPortRange),
    src:many(rp.sourceAddressPrefixes,rp.sourceAddressPrefix),
    dst:many(rp.destinationAddressPrefixes,rp.destinationAddressPrefix)};})
    .sort((a,b)=>a.priority-b.priority);
}''',
r'''function parseNsgRules(p){
  const many=(arr,single)=>(arr&&arr.length?arr.join(","):single||"*");
  const asgNames=a=>(a||[]).map(x=>String(x.id||"").split("/").pop()).filter(Boolean);
  return (p.securityRules||[]).map(r=>{const rp=r.properties||r;
    const sAsg=asgNames(rp.sourceApplicationSecurityGroups), dAsg=asgNames(rp.destinationApplicationSecurityGroups);
    return{
    name:r.name,priority:rp.priority,direction:rp.direction,access:rp.access,protocol:rp.protocol,
    ports:many(rp.destinationPortRanges,rp.destinationPortRange),
    src:many(rp.sourceAddressPrefixes,rp.sourceAddressPrefix),
    dst:many(rp.destinationAddressPrefixes,rp.destinationAddressPrefix),
    // An ASG-scoped side has no prefixes. Remember it, or the rule looks like "any".
    srcAsg:sAsg.length?sAsg.join(","):"", dstAsg:dAsg.length?dAsg.join(","):""};})
    .sort((a,b)=>a.priority-b.priority);
}''')

patch("P41b markRuleStates resolves ASG scope before testing coverage",
r'''function markRuleStates(){
  const adminRules=[];
  for(const n of fullGraph.nodes) if(n.type==="adminrules"&&n.meta.rules) adminRules.push(...n.meta.rules);
  for(const n of fullGraph.nodes){
    if(!n.meta.rules)continue;
    const rules=[...n.meta.rules].sort((a,b)=>a.priority-b.priority);
    for(let i=0;i<rules.length;i++){
      const b=rules[i]; b.shadowed=false; b.overridden=false;
      for(let j=0;j<i;j++) if(ruleCovers(rules[j],b)&&isAllow(rules[j])!==isAllow(b)){b.shadowed=true;break;}
      if(n.type==="nsg"&&isAllow(b)&&adminRules.some(a=>isDeny(a)&&ruleCovers(a,b))) b.overridden=true;
    }
  }
}''',
r'''// Which addresses does this NSG actually protect? An ASG referenced by one of its
// rules can only hold NICs behind it, so this is the real scope of an ASG side.
function nsgSelfPrefixes(nsgNode){
  const out=[];
  for(const e of fullGraph.edges){
    if(e.kind!=="nsg"||e.target!==nsgNode.id)continue;
    const s=byId.get(e.source); if(!s)continue;
    if(s.type==="subnet"&&s.meta.prefix)out.push(...String(s.meta.prefix).split(",").map(x=>x.trim()));
    if(s.type==="nic"&&s.meta.ips)out.push(...String(s.meta.ips).split(",").map(x=>x.trim()+"/32"));
  }
  return [...new Set(out.filter(Boolean))];
}
// Inbound: the protected NIC is the destination. Outbound: it is the source.
function effectiveRule(r,selfPfx){
  if(!selfPfx.length)return r;
  const self=selfPfx.join(",");
  const inbound=String(r.direction||"").toLowerCase()==="inbound";
  const o=Object.assign({},r);
  if(r.dstAsg&&(!r.dst||r.dst==="*")&&inbound)o.dst=self;
  if(r.srcAsg&&(!r.src||r.src==="*")&&!inbound)o.src=self;
  return o;
}
function markRuleStates(){
  const adminRules=[];
  for(const n of fullGraph.nodes) if(n.type==="adminrules"&&n.meta.rules) adminRules.push(...n.meta.rules);
  for(const n of fullGraph.nodes){
    if(!n.meta.rules)continue;
    const selfPfx=n.type==="nsg"?nsgSelfPrefixes(n):[];
    const rules=[...n.meta.rules].sort((a,b)=>a.priority-b.priority);
    const eff=rules.map(r=>effectiveRule(r,selfPfx));
    for(let i=0;i<rules.length;i++){
      const b=rules[i]; b.shadowed=false; b.overridden=false;
      for(let j=0;j<i;j++) if(ruleCovers(eff[j],eff[i])&&isAllow(rules[j])!==isAllow(b)){b.shadowed=true;b.shadowedBy=rules[j].name;break;}
      if(n.type==="nsg"&&isAllow(b)&&adminRules.some(a=>isDeny(a)&&ruleCovers(a,eff[i]))) b.overridden=true;
    }
  }
}''')

patch("P41c rules table shows ASG scope instead of a bare asterisk",
      "+'<td>'+esc(r.src||\"\")+'</td><td>'+esc(r.dst||\"\")+'</td><td>'+esc(r.name||\"\")+'</td>'",
      "+'<td>'+esc(r.srcAsg&&(!r.src||r.src===\"*\")?\"ASG: \"+r.srcAsg:(r.src||\"\"))+'</td>'"
      "+'<td>'+esc(r.dstAsg&&(!r.dst||r.dst===\"*\")?\"ASG: \"+r.dstAsg:(r.dst||\"\"))+'</td>'"
      "+'<td>'+esc(r.name||\"\")+'</td>'")

patch("P41d unreachable rules name what shadows them",
      "        +'<div><div class=\"rd-h\">Applies to</div>'",
      "        +'<div>'+(r.shadowed&&r.shadowedBy?'<div class=\"rd-h\" style=\"color:var(--danger)\">Never evaluated</div>'\n"
      "              +'<div class=\"rd-i\">Rule <b>'+esc(r.shadowedBy)+'</b> has a lower priority number, covers the same traffic, '\n"
      "              +'and does the opposite. This rule can never take effect. Renumber one of them.</div>':'')\n"
      "        +'<div class=\"rd-h\">Applies to</div>'")

# ---------------------------------------------------------------- P42
# AclGroup arrives as a full ARM resource id in real scans, not sub/rg/nsg.
# The fallback that guessed the resource group from a slash split was wrong.
patch("P42 remediation parses the resource group from the ARM id",
r'''  const nsgName=owner?owner.name:String(r.aclGroup||"").split("/").pop();
  const rg=owner?owner.rg:String(r.aclGroup||"").split("/")[1];''',
r'''  const nsgName=owner?owner.name:String(r.aclGroup||"").split("/").pop();
  // AclGroup can be a full ARM id, or "<subGuid>/<rg>/<nsg>". Handle both.
  const rg=owner?owner.rg:(armSeg(r.aclGroup,"resourcegroups")||armSeg(r.aclGroup,"resourceGroups")
                           ||String(r.aclGroup||"").split("/")[1]||"<rg>");''')

# ---------------------------------------------------------------- P43
# When the deny that blocked this flow also shadows allow rules on the same NSG,
# adding one more allow treats the symptom. The disease is the ordering: the deny
# was inserted at a lower priority number than the allows that are meant to work.
# Recommend renumbering first, and say exactly which rules are dead.
patch("P43 NSG remediation spots an ordering bug and recommends renumbering",
r"""  if(rule&&!isDefault){
    out.actions.push({label:"Or narrow the deny rule so it stops matching",""",
r"""  // Is this deny sitting in front of allow rules that can therefore never run?
  if(rule&&owner&&owner.meta.rules){
    const dead=owner.meta.rules.filter(x=>x.shadowed&&x.shadowedBy===rule.name);
    if(dead.length){
      const highest=Math.max(...dead.map(x=>+x.priority));
      const used=new Set(owner.meta.rules.map(x=>+x.priority));
      let newPri=null;
      for(let p2=highest+10;p2<=4096;p2++) if(!used.has(p2)){newPri=p2;break;}
      out.order="This is an ordering bug, not a missing allow. \"" + rule.name + "\" sits at priority "+
        rule.priority+", ahead of "+dead.length+" allow rule(s) that are meant to permit this traffic, so those "+
        "rules can never be evaluated. Adding one more allow in front of the deny only fixes this one flow.";
      out.actions.unshift({label:"Recommended: move the deny behind the allow rules it is shadowing"+
          (newPri?" (priority "+newPri+")":""),
        note:"Rules that can never take effect today: "+dead.map(x=>"#"+x.priority+" "+x.name).join(", ")+
             ". Renumbering the deny restores all of them at once. Review each one before you do it: they have "+
             "never actually been in force.",
        cmd:"az network nsg rule update -g "+(rg||"<rg>")+" --nsg-name "+(nsgName||"<nsg>")+
            " -n "+rule.name+" --priority "+(newPri||"<free-priority>")});
    }
  }
  if(rule&&!isDefault){
    out.actions.push({label:"Or narrow the deny rule so it stops matching",""")

# ---------------------------------------------------------------- P44
# The time-window control ran its init before rebuildData() populated allFlowRows,
# so it always concluded "No flow logs loaded" and disabled itself. The filter has
# never been usable. Make it a named function and call it after the data exists.
patch("P44a initWindow becomes a named function",
r'''(function initWindow(){
  const sel=document.getElementById("timeWin"); if(!sel)return;
  if(!allFlowRows.length){ sel.disabled=true; sel.title="No flow logs loaded."; return; }
  if(!allFlowRows.some(f=>f.ts)){
    sel.disabled=true;
    sel.title="This scan predates time bucketing. Re-run generate-netmap.sh to enable it.";
    return;
  }
  for(const o of [...sel.options]) if(+o.value && +o.value > flowSpanMin+30) o.disabled=true;
})();''',
r'''function initWindow(){
  const sel=document.getElementById("timeWin"); if(!sel)return;
  sel.disabled=false;
  for(const o of [...sel.options]){ o.disabled=false; o.title=""; }
  if(!allFlowRows.length){ sel.disabled=true; sel.title="No flow logs loaded."; return; }
  if(!allFlowRows.some(f=>f.ts)){
    sel.disabled=true;
    sel.title="This scan predates time bucketing. Re-run generate-netmap.sh to enable it.";
    return;
  }
  sel.title="Filters the traffic already captured in this scan ("+humanMins(flowSpanMin)+
    " of history), measured back from its newest data. It does not re-query Azure.";
  // A window longer than the scan captured cannot be honoured. Say why, do not just grey it out.
  for(const o of [...sel.options]) if(+o.value && +o.value > flowSpanMin+30){
    o.disabled=true;
    o.title="This scan only captured "+humanMins(flowSpanMin)+" of flow logs. "+
      "Set FLOW_WINDOW=7d in docker-compose.yml and rescan to unlock longer windows.";
  }
}''')

patch("P44b initWindow runs after the data is built",
r'''rebuildData();
function scannedLabel(){''',
r'''rebuildData();
initWindow();          // must run after rebuildData(), or allFlowRows is still empty
function scannedLabel(){''')

# ---------------------------------------------------------------- P45
# Searching set one facet without clearing the others, so a VNet search followed
# by a subscription search left BOTH filters on and the map went empty. And a
# scope search never left the dependency view, so pressing Enter looked dead.
patch("P45 a scope search resets the previous search",
r'''function jumpToScope(q,mode){
  const ls=low(q.trim());
  if(!ls)return false;
  const tryFacet=(kind,label)=>{
    // facetValues is keyed by id (subscription id, resource-group name, vnet id) and
    // carries the human label. Match the label; filter on the key.
    const vals=facetValues(kind);
    const keys=Object.keys(vals);
    const nameOf=k=>low(vals[k].label||k);
    const key = mode==="partial"
      ? keys.find(k=>nameOf(k).includes(ls))
      : keys.find(k=>nameOf(k)===ls);
    if(!key)return false;
    facetFilters[kind]=new Set([key]);
    facetOpen[kind]=true;
    expanded=new Set();
    renderSidebar(); renderGraph(); renderPanel();
    // renderGraph rewrites the status line, so set ours after it, not before.
    const info=document.getElementById("focusInfo");
    if(info)info.textContent=label+' filtered to "'+(vals[key].label||key)+'" \u00b7 '+vals[key].n+
      ' resources \u00b7 clear it in the sidebar';
    return true;
  };
  return tryFacet("sub","Subscription") || tryFacet("rg","Resource group") || tryFacet("vnet","VNet");
}''',
r'''// Every search starts from a clean slate. Otherwise a VNet search followed by a
// subscription search leaves both filters on, and their intersection is empty.
function clearSearchState(){
  facetFilters={sub:new Set(),rg:new Set(),vnet:new Set(),type:new Set()};
  isolated=null;
  expanded=new Set();
}
function jumpToScope(q,mode){
  const ls=low(q.trim());
  if(!ls)return false;
  const tryFacet=(kind,label)=>{
    // facetValues is keyed by id (subscription id, resource-group name, vnet id,
    // or type key) and carries the human label. Match the label; filter on the key.
    const vals=facetValues(kind);
    const keys=Object.keys(vals);
    const nameOf=k=>low(vals[k].label||k);
    const key = mode==="partial"
      ? keys.find(k=>nameOf(k).includes(ls))
      : keys.find(k=>nameOf(k)===ls);
    if(!key)return false;
    clearSearchState();
    facetFilters[kind]=new Set([key]);
    facetOpen[kind]=true;
    // A filter is a map view. Leave the dependency view, or nothing appears to happen.
    viewMode="overview"; selected=null; syncViewBtns();
    renderSidebar(); renderGraph(); renderPanel();
    // renderGraph rewrites the status line, so set ours after it, not before.
    const info=document.getElementById("focusInfo");
    if(info)info.textContent=label+' filtered to "'+(vals[key].label||key)+'" \u00b7 '+vals[key].n+
      ' resources · press Enter on an empty box, or use the sidebar, to clear it';
    return true;
  };
  // Exact matches first, in the order a person would expect.
  return tryFacet("sub","Subscription") || tryFacet("rg","Resource group")
      || tryFacet("vnet","VNet")        || tryFacet("type","Resource type");
}''')

# ---------------------------------------------------------------- P46
# jumpTo: search resource types too, clear stale filters when jumping to a
# resource, and make an empty Enter reset everything.
patch("P46 jumpTo handles types, empty input, and stale filters",
r'''function jumpTo(q){
  const hit=lookup(q);
  const info=document.getElementById("focusInfo");
  // An exact resource name (or an IP) wins outright. Otherwise a subscription,
  // resource group or VNet name filters the map before partial resource names
  // get a say, so "iam101" shows the subscription, not a lookalike resource.
  const exactHit = hit && (isIp(q.trim()) || low(hit.node.name)===low(q.trim()));
  if(!exactHit){
    if(jumpToScope(q,"exact"))return;
    if(jumpToScope(q,"partial"))return;
  }
  if(!hit){
    info.textContent='Nothing matches "'+q+'". Try a VM name, an IP, or a subscription, resource group or VNet name.';
    return;
  }
  const node=preferOwner(hit.node);
  selected=node.id; depsRoot=node.id; viewMode="deps";
  showTab("map"); syncViewBtns(); renderAll();
  info.textContent=hit.how+(node.id!==hit.node.id?" → showing its owner "+node.name:"")+" · sources and destinations below, with ports";
}''',
r'''function jumpTo(q){
  const info=document.getElementById("focusInfo");
  // Enter on an empty box means "show me everything again".
  if(!String(q||"").trim()){
    clearSearchState(); focusOn=false; syncFocusBtn();
    viewMode="overview"; selected=null; depsRoot=null; syncViewBtns();
    showTab("map"); renderAll();
    if(info)info.textContent="Filters cleared.";
    return;
  }
  const hit=lookup(q);
  // An exact resource name (or an IP) wins outright. Otherwise a subscription,
  // resource group, VNet or resource-type name filters the map before partial
  // resource names get a say, so "iam101" shows the subscription, not a lookalike.
  const exactHit = hit && (isIp(q.trim()) || low(hit.node.name)===low(q.trim()));
  if(!exactHit){
    if(jumpToScope(q,"exact"))return;
    if(jumpToScope(q,"partial"))return;
  }
  if(!hit){
    info.textContent='Nothing matches "'+q+'". Try a VM name, an IP, a subscription, a resource group, '+
      'a VNet, or a resource type such as "Load balancer".';
    return;
  }
  // A new resource search is a new question. Do not answer it through the last search's filters.
  clearSearchState();
  const node=preferOwner(hit.node);
  selected=node.id; depsRoot=node.id; viewMode="deps";
  showTab("map"); syncViewBtns(); renderAll();
  info.textContent=hit.how+(node.id!==hit.node.id?" → showing its owner "+node.name:"")+" · sources and destinations below, with ports";
}''')

# ---------------------------------------------------------------- P47
# Autocomplete: offer the subscriptions, resource groups, VNets and resource
# types that can be searched, so they do not have to be guessed.
patch("P47a search box gets a suggestion list",
'''      <input type="text" id="q" placeholder="VM, IP, subscription, resource group or VNet — press Enter" />''',
'''      <input type="text" id="q" list="qSuggest" autocomplete="off"
             placeholder="VM, IP, subscription, resource group, VNet or resource type — press Enter" />
      <datalist id="qSuggest"></datalist>''')

patch("P47b sidebar refresh keeps the suggestion list current",
r'''function renderSidebar(){
  const el=document.getElementById("side"); if(!el)return;''',
r'''// The things a search can actually match, offered as you type.
function fillSearchSuggestions(){
  const dl=document.getElementById("qSuggest"); if(!dl)return;
  // Subscriptions and types are few and always useful, so they go first and are
  // never truncated away by hundreds of resource groups.
  const out=[];
  for(const kind of ["sub","type","vnet","rg"]){
    const vals=facetValues(kind);
    for(const k of Object.keys(vals)) if(vals[k].label) out.push(vals[k].label);
  }
  const seen=new Set(); const uniq=out.filter(x=>{const l=low(x); if(seen.has(l))return false; seen.add(l); return true;});
  dl.innerHTML=uniq.slice(0,800).map(x=>'<option value="'+esc(x)+'"></option>').join("");
}
function renderSidebar(){
  fillSearchSuggestions();
  const el=document.getElementById("side"); if(!el)return;''')

# ---------------------------------------------------------------- P48
# Typing then pressing Enter fired the debounced re-render as well as the jump,
# which fought each other. Cancel the pending render, and do not re-render on
# every keystroke unless focus mode is actually on.
patch("P48 typing no longer fights the Enter key",
r'''let qTimer;
const qEl=document.getElementById("q");
qEl.oninput=()=>{clearTimeout(qTimer);qTimer=setTimeout(renderAll,250);};
qEl.onkeydown=(e)=>{if(e.key==="Enter"){e.preventDefault();clearTimeout(qTimer);jumpTo(qEl.value);}};''',
r'''let qTimer;
const qEl=document.getElementById("q");
// Live filtering only matters while Focus is on. Otherwise typing should be free,
// and Enter decides what happens.
qEl.oninput=()=>{clearTimeout(qTimer); if(focusOn)qTimer=setTimeout(renderAll,250);};
qEl.onkeydown=(e)=>{if(e.key==="Enter"){e.preventDefault();clearTimeout(qTimer);jumpTo(qEl.value);}};''')

# ---------------------------------------------------------------- P49
# "vnet", "nic", "nsg", "lb" are what an engineer actually types. Without an alias
# table they fell through to a partial name match and opened whichever resource
# happened to contain those letters. Resolve the shorthand to a resource type,
# ahead of any partial matching.
patch("P49a type alias table",
r"""function jumpToScope(q,mode){""",
r"""// What people type, mapped to the type keys the map uses.
const TYPE_ALIASES={
  vnet:"vnet", vnets:"vnet", "virtual network":"vnet", "virtual networks":"vnet",
  subnet:"subnet", subnets:"subnet",
  nsg:"nsg", nsgs:"nsg", "security group":"nsg", "security groups":"nsg",
  nic:"nic", nics:"nic", "network interface":"nic", "network interfaces":"nic",
  lb:"lb", lbs:"lb", "load balancer":"lb", "load balancers":"lb",
  appgw:"appgw", "application gateway":"appgw", "app gateway":"appgw",
  fw:"fw", firewall:"fw", firewalls:"fw", "azure firewall":"fw",
  vm:"vm", vms:"vm", "virtual machine":"vm", "virtual machines":"vm",
  vmss:"vmss", "scale set":"vmss", "scale sets":"vmss",
  pe:"pe", "private endpoint":"pe", "private endpoints":"pe",
  rt:"rt", "route table":"rt", "route tables":"rt", udr:"rt",
  pip:"pip", "public ip":"pip", "public ips":"pip",
  aks:"aks", kubernetes:"aks",
  storage:"storage", "storage account":"storage", "storage accounts":"storage",
  kv:"kv", keyvault:"kv", "key vault":"kv", "key vaults":"kv",
  sql:"sql", bastion:"bastion", natgw:"natgw", "nat gateway":"natgw",
  vgw:"vgw", "vpn gateway":"vgw", erc:"erc", expressroute:"erc",
  avnm:"avnm", "network manager":"avnm", asg:"asg", "application security group":"asg",
  zone:"zone", "private dns zone":"zone", dnszone:"dnszone", "dns zone":"dnszone",
  fwpolicy:"fwpolicy", "firewall policy":"fwpolicy",
  adminrules:"adminrules", "security admin rules":"adminrules",
};
// Resolve shorthand to a type that actually exists in this scan.
function typeKeyFor(q){
  const k=TYPE_ALIASES[low(String(q||"").trim())];
  if(!k)return null;
  return fullGraph.nodes.some(n=>n.type===k)?k:null;
}
function jumpToScope(q,mode){""")

patch("P49b jumpTo resolves shorthand before partial matching",
r"""  const exactHit = hit && (isIp(q.trim()) || low(hit.node.name)===low(q.trim()));
  if(!exactHit){
    if(jumpToScope(q,"exact"))return;
    if(jumpToScope(q,"partial"))return;
  }""",
r"""  const exactHit = hit && (isIp(q.trim()) || low(hit.node.name)===low(q.trim()));
  if(!exactHit){
    if(jumpToScope(q,"exact"))return;
    // "nic" means the resource type, not whichever resource has those three letters.
    const tk=typeKeyFor(q);
    if(tk){
      clearSearchState();
      facetFilters.type=new Set([tk]); facetOpen.type=true;
      viewMode="overview"; selected=null; depsRoot=null; syncViewBtns();
      showTab("map"); renderSidebar(); renderGraph(); renderPanel();
      const n2=fullGraph.nodes.filter(n=>n.type===tk).length;
      if(info)info.textContent='Resource type filtered to "'+TYPES[tk].label+'" \u00b7 '+n2+
        ' resources \u00b7 press Enter on an empty box to clear it';
      return;
    }
    if(jumpToScope(q,"partial"))return;
  }""")

patch("P49c suggestion list offers the shorthand too",
r"""  const seen=new Set(); const uniq=out.filter(x=>{const l=low(x); if(seen.has(l))return false; seen.add(l); return true;});""",
r"""  // The short forms an engineer types, offered alongside the full labels.
  for(const a of Object.keys(TYPE_ALIASES)) if(typeKeyFor(a)&&a.length<=6) out.push(a);
  const seen=new Set(); const uniq=out.filter(x=>{const l=low(x); if(seen.has(l))return false; seen.add(l); return true;});""")

# ---------------------------------------------------------------- P50
# Traffic rows are aggregated across 30-minute buckets, which threw the times
# away. Keep the first and last bucket so a rule can say WHEN it saw traffic.
patch("P50a aggregated flow rows remember first and last seen",
r'''    if(!e.rows.has(rk))e.rows.set(rk,{srcIp:f.src,dstIp:f.dst,port:f.port,proto:f.proto||"",
        count:0,bytesOut:0,bytesIn:0,bytes:0,denied:false,aclRule:"",aclGroup:"",flowType:"",peId:""});
    const r=e.rows.get(rk);
    r.count+=f.count;''',
r'''    if(!e.rows.has(rk))e.rows.set(rk,{srcIp:f.src,dstIp:f.dst,port:f.port,proto:f.proto||"",
        count:0,bytesOut:0,bytesIn:0,bytes:0,denied:false,aclRule:"",aclGroup:"",flowType:"",peId:"",
        firstTs:null,lastTs:null});
    const r=e.rows.get(rk);
    if(f.ts){ if(!r.firstTs||f.ts<r.firstTs)r.firstTs=f.ts; if(!r.lastTs||f.ts>r.lastTs)r.lastTs=f.ts; }
    r.count+=f.count;''')

# ---------------------------------------------------------------- P51
# Azure Firewall never writes to the flow logs, so its policy rules always showed
# "No traffic seen" even while denying millions of packets. Credit them from the
# firewall's own logs. Route tables drop silently, so credit those too.
patch("P51 firewall and route-table rules get their traffic",
r'''  const flowRows=[];
  for(const e of fullGraph.edges){
    if(e.kind!=="traffic"||!e.rows)continue;
    for(const r of e.rows) flowRows.push(r);
  }
  if(!flowRows.length){ruleHitsComputed=true;return;}''',
r'''  // ---- Azure Firewall: its verdicts live in AZFWNetworkRule / AZFWApplicationRule,
  // keyed by rule name, not in NTANetAnalytics. Without this the Rules tab calls a
  // rule that denied 50 million packets "unused".
  const fwByName=new Map();
  for(const n of fullGraph.nodes){
    if(n.type!=="fwrcg"||!n.meta.rules)continue;
    for(const r of n.meta.rules) if(r.name) fwByName.set(low(r.name),r);
  }
  if(fwByName.size) for(const f of fwInWindow()){
    const r=fwByName.get(low(f.rule||"")); if(!r)continue;
    const hits=+f.hits||1;
    r.hits+=hits; r.hitBytes=r.hitBytes||0;
    if(fwIsDeny(f))r.deniedHits+=hits;
    if(!r.firstTs||(f.ts&&f.ts<r.firstTs))r.firstTs=f.ts||r.firstTs;
    if(!r.lastTs ||(f.ts&&f.ts>r.lastTs)) r.lastTs =f.ts||r.lastTs;
    if(r.samples.length<12)r.samples.push({srcIp:f.src,dstIp:f.dst,port:f.port,proto:f.proto,
      count:hits,bytes:0,denied:fwIsDeny(f),aclRule:f.rule,firstTs:f.ts,lastTs:f.ts,
      fwCollection:f.collection,fwGroup:f.group,fwPolicy:f.policy,fwTable:f.table,fwReason:f.reason});
  }

  const flowRows=[];
  for(const e of fullGraph.edges){
    if(e.kind!=="traffic"||!e.rows)continue;
    for(const r of e.rows) flowRows.push(r);
  }

  // ---- Route tables: a next hop of None drops the packet with no rule and no log.
  // Attribute those drops to the route that did it, so the Rules tab can show them.
  for(const n of fullGraph.nodes) if(n.type==="rt") n.meta.routeHits={};
  for(const f of flowRows){
    if(!f.routeDrop||!f.rtName)continue;
    const rt=fullGraph.nodes.find(n=>n.type==="rt"&&low(n.name)===low(f.rtName)); if(!rt)continue;
    const h=rt.meta.routeHits[f.rtPrefix]||(rt.meta.routeHits[f.rtPrefix]={hits:0,deniedHits:0,samples:[]});
    h.hits+=f.count||0; h.deniedHits+=f.count||0;
    if(h.samples.length<12)h.samples.push(f);
  }

  if(!flowRows.length){ruleHitsComputed=true;return;}''')

# ---------------------------------------------------------------- P52
# The expanded rule now shows when the traffic happened, not just that it did.
patch("P52a rule detail carries route-table traffic and timestamps",
r'''      const rnode=byId.get(r.resourceId);
      const scope=ruleScopeDescription(rnode);
      const samples=(r.samples||[]).slice(0,10);
      // A rule that is actually denying traffic gets the same remediation the map panel shows.
      const deniedSample=(r.samples||[]).find(sf=>sf.denied)||null;''',
r'''      const rnode=byId.get(r.resourceId);
      const scope=ruleScopeDescription(rnode);
      // A route entry keeps its traffic on the route table, not on the rule object.
      const rh=(r.layer==="rt"&&rnode&&rnode.meta.routeHits)?rnode.meta.routeHits[r.name]:null;
      if(rh){ r.hits=rh.hits; r.deniedHits=rh.deniedHits; r.samples=rh.samples; }
      const samples=(r.samples||[]).slice(0,10);
      // A rule that is actually denying traffic gets the same remediation the map panel shows.
      const deniedSample=(r.samples||[]).find(sf=>sf.denied)||null;
      const seenFrom=Math.min(...(r.samples||[]).map(s=>s.firstTs||Infinity));
      const seenTo  =Math.max(...(r.samples||[]).map(s=>s.lastTs ||-Infinity));
      const seenLine=(isFinite(seenFrom)&&isFinite(seenTo))
        ? '<div class="rd-i" style="color:var(--faint)">first seen '+esc(fmtClock(seenFrom))
          +' \u00b7 last seen '+esc(fmtClock(seenTo,true))+'</div>' : "";''')

patch('P52b every sample line is stamped with its time',
'        + (samples.length?\'<div class="rd-h" style="margin-top:8px">Traffic that hit this rule</div>\'\n            + samples.map(sf=>\'<div class="rd-i mono\'+(sf.denied?\' bad\':\'\')+\'">\'+esc(sf.srcIp)+\' → \'+esc(sf.dstIp)+\':\'+esc(sf.port)+\'/\'+esc(sf.proto||"?")\n                +\'  \'+Number(sf.count).toLocaleString()+\' flows\'+(sf.bytes?\'  \'+fmtBytes(sf.bytes):\'\')+(sf.denied?\'  DENIED\':\'\')\n                +(sf.aclRule?\'  \\u00b7 Azure: \'+esc(sf.aclRule):\'\')+\'</div>\').join("")',
'        + (samples.length?\'<div class="rd-h" style="margin-top:8px">Traffic that hit this rule \\u00b7 \'+esc(windowLabel())+\'</div>\'\n            + seenLine\n            + samples.map(sf=>\'<div class="rd-i mono\'+(sf.denied?\' bad\':\'\')+\'">\'\n                +(sf.lastTs?\'<span style="color:var(--faint)">\'+esc(fmtClock(sf.lastTs))+\'</span>  \':\'\')\n                +esc(sf.srcIp)+\' → \'+esc(sf.dstIp)+\':\'+esc(sf.port)+\'/\'+esc(sf.proto||"?")\n                +\'  \'+Number(sf.count).toLocaleString()+(sf.fwPolicy?\' hits\':\' flows\')+(sf.bytes?\'  \'+fmtBytes(sf.bytes):\'\')+(sf.denied?\'  DENIED\':\'\')\n                +(sf.fwCollection?\'  \\u00b7 collection \'+esc(sf.fwCollection):\'\')\n                +(sf.aclRule&&!sf.fwPolicy?\'  \\u00b7 Azure: \'+esc(sf.aclRule):\'\')+\'</div>\').join("")')

patch("P52c route entries expand like any other rule",
r'''    if(r.layer!=="rt"){
      const rnode=byId.get(r.resourceId);''',
r'''    {
      const rnode=byId.get(r.resourceId);''')

patch("P52d route entries show a status too",
r'''    const s=r.layer==="rt"?{k:"",label:""}:ruleStatus(r);''',
r'''    const rtn=r.layer==="rt"?byId.get(r.resourceId):null;
    const rtHit=(rtn&&rtn.meta.routeHits)?rtn.meta.routeHits[r.name]:null;
    const s=r.layer==="rt"
      ? (rtHit&&rtHit.hits?{k:"deny",label:"Dropping traffic"}:{k:"",label:""})
      : ruleStatus(r);''')

patch("P52e route entries show their traffic count in the table",
"    const traffic=r.layer===\"rt\"?\"\":(r.hits?Number(r.hits).toLocaleString()+(r.deniedHits?\" <span style='color:var(--danger)'>(\"+Number(r.deniedHits).toLocaleString()+\" denied)</span>\":\"\"):\"\u2014\");",
"    const traffic=(r.layer===\"rt\")\n"
      "      ? (rtHit&&rtHit.hits?\"<span style='color:var(--danger)'>\"+Number(rtHit.hits).toLocaleString()+\" dropped</span>\":\"\u2014\")\n"
      "      : (r.hits?Number(r.hits).toLocaleString()+(r.deniedHits?\" <span style='color:var(--danger)'>(\"+Number(r.deniedHits).toLocaleString()+\" denied)</span>\":\"\"):\"\u2014\");")

# ---------------------------------------------------------------- P53
# The Rules tab needs its own window control: reading "this rule denied 2,684
# flows" is meaningless without knowing over what period.
patch("P53a rules toolbar gets a time window",
r'''      <select id="ruleLayer">
        <option value="all">All layers</option>
        <option value="adminrules">AVNM security admin</option>
        <option value="nsg">NSG</option>
        <option value="fwrcg">Firewall policy</option>
        <option value="rt">Route tables</option>
      </select>''',
r'''      <select id="ruleLayer">
        <option value="all">All layers</option>
        <option value="adminrules">AVNM security admin</option>
        <option value="nsg">NSG</option>
        <option value="fwrcg">Firewall policy</option>
        <option value="rt">Route tables</option>
      </select>
      <select id="ruleWin" title="Same traffic window as the map. Filters what this scan already captured; it does not re-query Azure.">
        <option value="0">All flows in this scan</option>
        <option value="30">Last 30 minutes</option>
        <option value="60">Last hour</option>
        <option value="360">Last 6 hours</option>
        <option value="1440">Last 24 hours</option>
        <option value="4320">Last 3 days</option>
        <option value="10080">Last 7 days</option>
      </select>''')

patch("P53b the two window controls stay in step",
r'''bind("timeWin","onchange",function(){applyWindow(+this.value);});''',
r'''bind("timeWin","onchange",function(){applyWindow(+this.value);syncWindowControls();});
bind("ruleWin","onchange",function(){applyWindow(+this.value);syncWindowControls();});
// One window, two places to set it. Keep them showing the same thing, and give the
// Rules tab the same "this scan only holds N hours" honesty as the map.
function syncWindowControls(){
  const a=document.getElementById("timeWin"), b=document.getElementById("ruleWin");
  if(!a||!b)return;
  b.value=String(windowMin||0); a.value=String(windowMin||0);
  b.disabled=a.disabled;
  for(const o of [...b.options]){
    const m=[...a.options].find(x=>x.value===o.value);
    if(m){ o.disabled=m.disabled; o.title=m.title; }
  }
}''')

patch("P53c initWindow syncs both controls",
r'''rebuildData();
initWindow();          // must run after rebuildData(), or allFlowRows is still empty''',
r'''rebuildData();
initWindow();          // must run after rebuildData(), or allFlowRows is still empty
syncWindowControls();''')

patch("P53d rules header states the window it is counting over",
r'''  else html='<div class="statusline" style="padding:6px 12px">Click any rule to see what it applies to, the traffic that hit it, and\u2014for rules that are denying\u2014how to fix it.</div>'+html;''',
r'''  else html='<div class="statusline" style="padding:6px 12px">Traffic counts cover <b>'+esc(windowLabel())+'</b>. '
      +'Click any rule to see what it applies to, when it saw traffic, and\u2014for rules that are denying\u2014how to fix it. '
      +'Firewall rules are counted from the firewall\u2019s own logs; route entries show what they silently dropped.</div>'+html;''')

# ---------------------------------------------------------------- P54
# Resource Graph does not always return firewallPolicies/ruleCollectionGroups, so a
# policy can appear in the scan with no rules at all and the Rules tab shows nothing
# for Azure Firewall. The firewall's own logs name the policy, collection group,
# collection and rule for every decision. Reconstruct the rules it actually enforced.
patch("P54a observed firewall rules, rebuilt from the firewall logs",
r"""  // ---- Azure Firewall: its verdicts live in AZFWNetworkRule / AZFWApplicationRule,""",
r"""  // If the policy's rule collections are not in this scan, rebuild what the firewall
  // enforced from its logs. These are observed rules: real hits, real times, but no
  // priority and no authored scope, so they are never used for shadow analysis.
  const haveFwRules=fullGraph.nodes.some(n=>n.type==="fwrcg"&&n.meta.rules&&n.meta.rules.length);
  if(!haveFwRules&&fwRows.length){
    const pols=fullGraph.nodes.filter(n=>n.type==="fwpolicy");
    for(const p of pols) p.meta.rules=[];
    const byPol=new Map(pols.map(p=>[low(p.name),p]));
    const agg=new Map();
    for(const f of fwInWindow()){
      const p=byPol.get(low(f.policy||""))||pols[0]; if(!p)continue;
      const rn=f.rule||"(policy default deny)";
      const k=p.id+"|"+low(f.group||"")+"|"+low(f.collection||"")+"|"+low(rn)+"|"+low(f.table||"");
      let r=agg.get(k);
      if(!r){
        r={name:rn,priority:"",direction:"Outbound",access:fwIsDeny(f)?"Deny":"Allow",
           protocol:f.proto||"*",ports:new Set(),src:new Set(),dst:new Set(),
           observed:true,collection:f.collection||"",group:f.group||"",table:f.table||"",
           hits:0,deniedHits:0,hitBytes:0,samples:[],firstTs:null,lastTs:null,_pol:p};
        agg.set(k,r); p.meta.rules.push(r);
      }
      const hits=+f.hits||1;
      r.hits+=hits; if(fwIsDeny(f))r.deniedHits+=hits;
      if(f.port)r.ports.add(String(f.port));
      if(f.src)r.src.add(f.src);
      if(f.dst)r.dst.add(f.dst);
      if(f.ts){ if(!r.firstTs||f.ts<r.firstTs)r.firstTs=f.ts; if(!r.lastTs||f.ts>r.lastTs)r.lastTs=f.ts; }
      if(r.samples.length<12)r.samples.push({srcIp:f.src,dstIp:f.dst,port:f.port,proto:f.proto,
        count:hits,bytes:0,denied:fwIsDeny(f),firstTs:f.ts,lastTs:f.ts,
        fwRule:f.rule,fwPolicy:f.policy,fwTable:f.table,fwCollection:f.collection,fwGroup:f.group,
        fwReason:f.reason,fwDest:f.dst,aclRule:f.rule,aclGroup:f.policy});
    }
    // Collapse the sets into the short strings the table renders.
    const brief=(s2,n2)=>{const a=[...s2]; return a.slice(0,n2).join(",")+(a.length>n2?" +"+(a.length-n2)+" more":"");};
    for(const r of agg.values()){
      r.ports=brief(r.ports,6)||"*"; r.src=brief(r.src,3)||"*"; r.dst=brief(r.dst,3)||"*";
      delete r._pol;
    }
    for(const p of pols) p.meta.rules.sort((a,b)=>b.hits-a.hits);
  }

  // ---- Azure Firewall: its verdicts live in AZFWNetworkRule / AZFWApplicationRule,""")

patch("P54b observed rules are never judged as shadowed",
r"""    for(let i=0;i<rules.length;i++){
      const b=rules[i]; b.shadowed=false; b.overridden=false;
      for(let j=0;j<i;j++) if(ruleCovers(eff[j],eff[i])&&isAllow(rules[j])!==isAllow(b)){b.shadowed=true;b.shadowedBy=rules[j].name;break;}""",
r"""    for(let i=0;i<rules.length;i++){
      const b=rules[i]; b.shadowed=false; b.overridden=false;
      // Rules rebuilt from logs have no authored priority or scope. Coverage cannot be proven.
      if(b.observed)continue;
      for(let j=0;j<i;j++) if(ruleCovers(eff[j],eff[i])&&isAllow(rules[j])!==isAllow(b)){b.shadowed=true;b.shadowedBy=rules[j].name;break;}""")

patch("P54c the Rules tab knows about firewall policies",
r"""const LAYER_LABEL={adminrules:"AVNM admin",nsg:"NSG",fwrcg:"Firewall policy",rt:"Route table"};""",
r"""const LAYER_LABEL={adminrules:"AVNM admin",nsg:"NSG",fwrcg:"Firewall policy",
                   fwpolicy:"Azure Firewall (from logs)",rt:"Route table"};""")

patch("P54d firewall filter option",
r"""        <option value="fwrcg">Firewall policy</option>""",
r"""        <option value="fwrcg">Firewall policy</option>
        <option value="fwpolicy">Azure Firewall (from logs)</option>""")

patch("P54e observed rules say where they came from",
r"""      const rh=(r.layer==="rt"&&rnode&&rnode.meta.routeHits)?rnode.meta.routeHits[r.name]:null;""",
r"""      const rh=(r.layer==="rt"&&rnode&&rnode.meta.routeHits)?rnode.meta.routeHits[r.name]:null;
      const obs=r.observed
        ? '<div class="rd-i" style="color:var(--faint)">Rebuilt from the firewall\u2019s own logs: this policy\u2019s rule '
          +'collections are not in this scan, so priority and authored scope are unknown. Source, destination and '
          +'ports below are what was actually seen'+(r.collection?', in collection <b>'+esc(r.collection)+'</b>':'')
          +(r.group?' of group <b>'+esc(r.group)+'</b>':'')+'.</div>'
        : "";""")

patch("P54f render the provenance note",
r"""        +'<div class="rd-h">Applies to</div>'""",
r"""        +obs+'<div class="rd-h">Applies to</div>'""")

# ---------------------------------------------------------------- P55
# Three wording bugs the real data exposed: the traffic heading was hard-coded to
# "last 24h" regardless of window; observed firewall hits were called "flows" and
# shown with an empty byte column; and Azure writes the policy name into
# RuleCollectionGroup, so we printed "group <policy>" as if it were a group.
patch("P55a traffic heading follows the window",
r"""        +'<div><div class="rd-h">Traffic in the last 24h</div>'""",
r"""        +'<div><div class="rd-h">Traffic \u00b7 '+esc(windowLabel())+'</div>'""")

patch('P55b observed firewall rules count hits, not flows or bytes',
'        + (r.hits?(\'<div class="rd-i">\'+Number(r.hits).toLocaleString()+\' flows · \'+fmtBytes(r.hitBytes||0)',
'        + (r.hits?(\'<div class="rd-i">\'+Number(r.hits).toLocaleString()+(r.observed?\' hits\':\' flows · \'+fmtBytes(r.hitBytes||0))')

patch("P55c do not print the policy name as a collection group",
r"""          +(r.group?' of group <b>'+esc(r.group)+'</b>':'')+'.</div>'""",
r"""          +(r.group&&low(r.group)!==low(rnode?rnode.name:"")?' of group <b>'+esc(r.group)+'</b>':'')+'.</div>'""")

patch("P55d an observed firewall rule says which firewall enforces it",
r"""      const scope=ruleScopeDescription(rnode);""",
r"""      let scope=ruleScopeDescription(rnode);
      if(r.observed&&rnode){
        // The policy is not "attached" to a subnet; it is enforced by the firewalls using it.
        const fws=fullGraph.edges.filter(e=>e.kind==="policy"&&e.target===rnode.id)
          .map(e=>(byId.get(e.source)||{}).name).filter(Boolean);
        scope=[fws.length?"Enforced by "+fws.join(", "):"Enforced by Azure Firewall",
               "Policy "+rnode.name];
      }""")

# ---------------------------------------------------------------- P56
# A scan can hold firewall logs and no flow logs. The window control looked only at
# flow rows and disabled itself, even though the firewall's rows are timestamped and
# fwInWindow() honours the window. Consider both sources.
patch('P56a history span covers firewall logs too',
'  const stamped=allFlowRows.filter(f=>f.ts);\n  if(stamped.length){\n    const lo=Math.min(...stamped.map(f=>f.ts)), hi=Math.max(...stamped.map(f=>f.ts));\n    flowSpanMin=Math.round((hi-lo)/60000)+30;   // buckets are 30 minutes wide\n  } else flowSpanMin=0;',
'  const stamped=allFlowRows.filter(f=>f.ts).concat(fwRows.filter(f=>f.ts));\n  if(stamped.length){\n    const lo=Math.min(...stamped.map(f=>f.ts)), hi=Math.max(...stamped.map(f=>f.ts));\n    flowSpanMin=Math.round((hi-lo)/60000)+30;   // buckets are 30 minutes wide\n  } else flowSpanMin=0;')

patch('P56b the window stays usable when only firewall logs are timestamped',
'  if(!allFlowRows.length){ sel.disabled=true; sel.title="No flow logs loaded."; return; }\n  if(!allFlowRows.some(f=>f.ts)){\n    sel.disabled=true;\n    sel.title="This scan predates time bucketing. Re-run generate-netmap.sh to enable it.";\n    return;\n  }',
'  if(!allFlowRows.length&&!fwRows.length){ sel.disabled=true; sel.title="No flow logs loaded."; return; }\n  if(!allFlowRows.some(f=>f.ts)&&!fwRows.some(f=>f.ts)){\n    sel.disabled=true;\n    sel.title="This scan predates time bucketing. Re-run generate-netmap.sh to enable it.";\n    return;\n  }')

# ---------------------------------------------------------------- P57
# Two questions an engineer asks of any rule: is it doing anything, and is the
# traffic it touches legitimate? The panel answered neither. Add a port-intent
# classifier and make every effective rule show its real traffic.
patch('P57 effective rules show status and open their traffic',
'      html+=\'<div class="secTitle">Effective rules (evaluation order)</div>\';\n      layers.forEach((L,i)=>{\n        html+=\'<div class="effLayer"><div class="lh">\'+(i+1)+\'. \'+esc(L.layer)+\' — \'+esc(L.from)+\'</div>\';\n        for(const r of [...L.rules].sort((a,b)=>a.priority-b.priority).slice(0,12)){\n          const deny=/deny/i.test(r.access);\n          html+=\'<div class="rule"><span style="color:\'+(deny?"var(--danger)":"var(--ok)")+\'">\'+(deny?"✕":"✓")+\'</span> #\'+r.priority\n             +\' \'+(r.direction==="Inbound"?"IN ":"OUT")+\' <b>:\'+esc(r.ports)+\'</b> \'+esc(r.protocol)\n             +\' <span style="color:var(--faint)">\'+esc(r.src)+\' → \'+esc(r.dst)+\'</span> \'+esc(r.name)+\'</div>\';\n        }\n        if(L.rules.length>12)html+=\'<div style="font-size:10.5px;color:var(--faint);padding-top:3px">+\'+(L.rules.length-12)+\' more</div>\';\n        html+=\'</div>\';\n      });',
'      if(!ruleHitsComputed)computeRuleHits();\n      html+=\'<div class="secTitle">Effective rules (evaluation order)</div>\';\n      html+=\'<div style="font-size:10.5px;color:var(--faint);line-height:1.45;margin-bottom:5px">\'\n          +\'Click a rule to see the traffic it actually matched in \'+esc(windowLabel())+\'.</div>\';\n      let effIdx=0;\n      layers.forEach((L,i)=>{\n        html+=\'<div class="effLayer"><div class="lh">\'+(i+1)+\'. \'+esc(L.layer)+\' — \'+esc(L.from)+\'</div>\';\n        for(const r of [...L.rules].sort((a,b)=>a.priority-b.priority).slice(0,12)){\n          const deny=/deny/i.test(r.access);\n          const st=r.shadowed?{t:"Never evaluated",c:"var(--danger)"}\n                 :r.overridden?{t:"Overridden by AVNM",c:"var(--danger)"}\n                 :(r.hits||0)>0?{t:Number(r.hits).toLocaleString()+" flows"+((r.deniedHits||0)?" · "+Number(r.deniedHits).toLocaleString()+" denied":""),c:deny?"var(--danger)":"var(--ok)"}\n                 :{t:"No traffic seen",c:"var(--faint)"};\n          const eid="eff-"+(effIdx++);\n          html+=\'<div class="rule" data-eff="\'+eid+\'" style="cursor:pointer"><span style="color:\'+(deny?"var(--danger)":"var(--ok)")+\'">\'+(deny?"✕":"✓")+\'</span> #\'+r.priority\n             +\' \'+(r.direction==="Inbound"?"IN ":"OUT")+\' <b>:\'+esc(r.ports)+\'</b> \'+esc(r.protocol)\n             +\' <span style="color:var(--faint)">\'+esc(r.srcAsg&&(!r.src||r.src==="*")?"ASG:"+r.srcAsg:r.src)+\' → \'+esc(r.dstAsg&&(!r.dst||r.dst==="*")?"ASG:"+r.dstAsg:r.dst)+\'</span> \'+esc(r.name)\n             +\' <span style="color:\'+st.c+\';font-size:10px">\'+esc(st.t)+\'</span></div>\';\n          html+=\'<div id="\'+eid+\'" style="display:none;padding:4px 0 6px 16px">\'+effDetailHtml(r)+\'</div>\';\n        }\n        if(L.rules.length>12)html+=\'<div style="font-size:10.5px;color:var(--faint);padding-top:3px">+\'+(L.rules.length-12)+\' more</div>\';\n        html+=\'</div>\';\n      });')

# ---------------------------------------------------------------- P58
# What IS this traffic? A port is a strong hint about intent. This is guidance,
# never a verdict: it tells you which way to lean and what to check.
patch("P58a port intent classifier",
r'''function effectiveRules(nodeId){''',
r'''/* ================= what is this traffic, and is it plausible? =================
   A destination port says a great deal about intent. This never decides for you:
   it says which way to lean, and what to verify before you allow or keep blocking. */
const PORT_INTENT={
  "53":["DNS","infra"], "88":["Kerberos","infra"], "123":["NTP time sync","infra"],
  "135":["RPC endpoint mapper","infra"], "389":["LDAP / CLDAP (DC locator)","infra"],
  "464":["Kerberos password change","infra"], "636":["LDAPS","infra"],
  "3268":["Global catalog","infra"], "3269":["Global catalog over TLS","infra"],
  "5722":["DFS replication","infra"], "9389":["AD web services","infra"],
  "22":["SSH","mgmt"], "3389":["RDP","mgmt"], "3390":["RDP (alt port)","mgmt"],
  "5985":["WinRM (HTTP)","mgmt"], "5986":["WinRM (HTTPS)","mgmt"],
  "161":["SNMP poll","mgmt"], "162":["SNMP trap","mgmt"], "1688":["KMS activation","mgmt"],
  "137":["NetBIOS name service","noise"], "138":["NetBIOS datagram","noise"],
  "139":["NetBIOS session","noise"], "5353":["mDNS","noise"], "1900":["SSDP","noise"],
  "7680":["Windows Delivery Optimization (peer cache)","noise"],
  "445":["SMB","lateral"], "1433":["SQL Server","app"], "3306":["MySQL","app"],
  "5432":["PostgreSQL","app"], "6379":["Redis","app"], "9092":["Kafka (plaintext)","app"],
  "9093":["Kafka (TLS)","app"], "5671":["AMQP over TLS","app"], "5672":["AMQP (plaintext)","app"],
  "9200":["Elasticsearch","app"], "2049":["NFS","app"], "80":["HTTP","app"],
  "443":["HTTPS","app"], "8080":["HTTP (alt)","app"], "8443":["HTTPS (alt)","app"],
};
const INTENT_ADVICE={
  infra:"Domain and platform traffic. If this is denied, expect authentication, name resolution or time sync to degrade. Usually legitimate: confirm the source is a domain member before allowing.",
  mgmt:"Management access. Often legitimate, but only from a sanctioned jump host or privileged-access range. Check the source before allowing.",
  noise:"Legacy broadcast or peer-to-peer chatter. Almost never needed. Keeping it blocked is normally right; better still, disable it at the source.",
  lateral:"A common lateral-movement port. Allow only between explicitly sanctioned hosts, never broadly.",
  app:"Application traffic. Only the application owner can say whether this endpoint is required.",
  unknown:"No well-known meaning for this port. Ask the workload owner what it is before allowing.",
};
function trafficIntent(port,proto){
  const p=String(port||"");
  let hit=PORT_INTENT[p];
  // NetBIOS name service is UDP; the same number over TCP is a session, still noise.
  if(!hit&&+p>=49152)hit=["Ephemeral / RPC dynamic port","infra"];
  const kind=hit?hit[1]:"unknown";
  return {what:hit?hit[0]:"Port "+p+(proto?"/"+proto:""), kind, advice:INTENT_ADVICE[kind]};
}
const INTENT_COLOR={infra:"#1F6B3B",mgmt:"#8A6100",noise:"#8A94A6",lateral:"#B02A37",app:"#2F6FEB",unknown:"#5A6678"};
const INTENT_LABEL={infra:"infrastructure",mgmt:"management",noise:"noise",lateral:"lateral movement",app:"application",unknown:"unclassified"};

// The traffic a single rule matched, with a plain-language read on what it is.
function effDetailHtml(r){
  const samples=(r.samples||[]).slice(0,8);
  let h="";
  if(r.shadowed&&r.shadowedBy)
    h+='<div style="font-size:10.5px;color:var(--danger);line-height:1.45">Never evaluated: <b>'+esc(r.shadowedBy)
      +'</b> has a lower priority number, covers the same traffic and does the opposite.</div>';
  if(!samples.length)
    return h+'<div style="font-size:10.5px;color:var(--faint)">'
      +(flows.length?"No flow in this window matched this rule.":"No flow logs loaded, so rule traffic cannot be shown.")+'</div>';
  const seen=new Set();
  for(const sf of samples){
    const it=trafficIntent(sf.port,sf.proto);
    h+='<div style="font-family:ui-monospace,Menlo,monospace;font-size:10px;color:'+(sf.denied?"#B02A37":"var(--dim)")+'">'
      +(sf.lastTs?'<span style="color:var(--faint)">'+esc(fmtClock(sf.lastTs))+'</span>  ':'')
      +esc(sf.srcIp)+' \u2192 '+esc(sf.dstIp)+':'+esc(sf.port)+'/'+esc(sf.proto||"?")
      +'  '+Number(sf.count).toLocaleString()+(sf.denied?' DENIED':'')+'</div>';
    if(!seen.has(it.kind)){
      seen.add(it.kind);
      h+='<div style="font-size:10.5px;line-height:1.45;margin:1px 0 5px"><b style="color:'+INTENT_COLOR[it.kind]+'">'
        +esc(it.what)+'</b> <span style="color:var(--faint)">('+esc(INTENT_LABEL[it.kind])+')</span> '
        +'<span style="color:var(--dim)">'+esc(it.advice)+'</span></div>';
    }
  }
  if((r.samples||[]).length>samples.length)
    h+='<div style="font-size:10px;color:var(--faint)">+'+((r.samples||[]).length-samples.length)+' more</div>';
  return h;
}
function effectiveRules(nodeId){''')

patch("P58b clicking an effective rule opens its traffic",
r'''  panel.querySelectorAll("[data-nav]").forEach(el=>el.onclick=()=>selectNode(el.getAttribute("data-nav")));''',
r'''  panel.querySelectorAll("[data-nav]").forEach(el=>el.onclick=()=>selectNode(el.getAttribute("data-nav")));
  panel.querySelectorAll("[data-eff]").forEach(el=>el.onclick=(ev)=>{
    ev.stopPropagation();
    const d=document.getElementById(el.getAttribute("data-eff"));
    if(d)d.style.display=(d.style.display==="none")?"block":"none";
  });''')

# ---------------------------------------------------------------- P59
# Every denied flow gets the same plain-language read, in the fix box.
patch("P59 the recommended fix says what the traffic is",
r'''  let h='<div class="fixBox"><div class="fh">Recommended fix \u00b7 '+esc(fx.layer)+'</div>';
  if(fx.order)h+='<div class="forder">'+esc(fx.order)+'</div>';''',
r'''  let h='<div class="fixBox"><div class="fh">Recommended fix \u00b7 '+esc(fx.layer)+'</div>';
  const it=trafficIntent(r.port,r.proto);
  h+='<div class="forder"><b style="color:'+INTENT_COLOR[it.kind]+'">'+esc(it.what)+'</b> '
    +'<span style="color:var(--faint)">('+esc(INTENT_LABEL[it.kind])+')</span> \u2014 '+esc(it.advice)+'</div>';
  if(fx.order)h+='<div class="forder">'+esc(fx.order)+'</div>';''')

# ---------------------------------------------------------------- P60
# Load balancer troubleshooting: what is in the pool, is there a probe, and is
# any backend actually carrying traffic. All of this is readable with Reader.
patch("P60 load balancer and gateway health section",
r'''  const nbs=neighborsOf(sel.id);
  const traf=nbs.filter(n=>n.kind==="traffic");''',
r'''  // ---- Load balancer / application gateway: pool, probes, and who is really serving
  if(["lb","appgw"].includes(sel.type)){
    const backends=fullGraph.edges.filter(e=>e.kind==="backend"&&e.source===sel.id)
      .map(e=>byId.get(e.target)).filter(Boolean);
    const pools=sel.meta.poolCount||0, members=sel.meta.backendCount||0, probes=sel.meta.probeCount||0;
    html+='<div class="secTitle">'+(sel.type==="lb"?"Load balancer":"Application gateway")+' health</div>';
    html+='<div class="mcards" style="grid-template-columns:1fr 1fr 1fr">'
        + mcard("Backend pools",String(pools),pools?"":"none defined")
        + mcard("Members",String(members),members?"":"pool is empty")
        + mcard("Health probes",String(probes),probes?"":"no probe attached")
        + '</div>';
    if(!members)html+='<div class="impairBox"><div class="ih">Backend pool is empty</div>'
      +'<div class="iw">Nothing is behind this. Every connection will fail or time out.</div>'
      +'<div class="iw"><b>Check:</b> '+esc(IMPAIR_FIX.emptypool)+'</div></div>';
    if(members&&!probes)html+='<div class="impairBox"><div class="ih">No health probe</div>'
      +'<div class="iw">Without a probe the load balancer cannot tell a dead backend from a live one, so it keeps sending traffic to both.</div>'
      +'<div class="iw"><b>Check:</b> '+esc(IMPAIR_FIX.noprobe)+'</div></div>';
    if(backends.length){
      html+='<div class="secTitle" style="margin-top:8px">Backends</div>';
      for(const bnode of backends.slice(0,12)){
        const t=nodeTraffic(bnode.id);
        const dead=!t.flows;
        html+='<div class="row" data-nav="'+esc(bnode.id)+'">'
          +'<span style="color:'+(dead?"var(--faint)":TYPES[bnode.type].color)+';font-size:11px">\u25cf</span>'
          +'<span style="word-break:break-all">'+esc(bnode.name)+(bnode.meta.ips?' <span style="color:var(--faint)">'+esc(bnode.meta.ips)+'</span>':'')+'</span>'
          +'<span class="edgeKind" style="color:'+(dead?"var(--faint)":(t.denied?"var(--danger)":"var(--ok)"))+'">'
          +(dead?"no traffic":Number(t.flows).toLocaleString()+" flows"+(t.denied?" \u00b7 "+t.denied+" denied":""))+'</span></div>';
      }
      const silent=backends.filter(x=>!nodeTraffic(x.id).flows).length;
      if(silent&&silent===backends.length)
        html+='<div class="impairBox"><div class="ih">No backend is serving traffic</div>'
          +'<div class="iw">The pool has '+backends.length+' member(s), and none of them recorded a single flow in '+esc(windowLabel())+'. '
          +'Either nothing is reaching the front end, or every member is failing its probe.</div>'
          +'<div class="iw"><b>Check:</b> '+esc(IMPAIR_FIX.unhealthy)+'</div></div>';
      else if(silent)
        html+='<div style="font-size:10.5px;color:var(--faint);padding:2px 0">'+silent+' of '+backends.length
          +' member(s) recorded no traffic in this window.</div>';
    }
    if(!metricsRaw.length)
      html+='<div style="font-size:10.5px;color:var(--faint);line-height:1.45;margin-top:6px">'
        +'Probe availability, SNAT port usage and unhealthy-host counts need metrics. '
        +'Set <b>METRICS: "1"</b> in docker-compose.yml (needs Monitoring Reader) and rescan.</div>';
  }

  const nbs=neighborsOf(sel.id);
  const traf=nbs.filter(n=>n.kind==="traffic");''')

# ---------------------------------------------------------------- P61
# The Rules tab sample lines get the same read.
patch("P61 rules tab explains what the traffic is",
r'''        + (deniedSample?'<div style="padding:0 16px 12px">'+fixBoxHtml(deniedSample)+'</div>':'')''',
r'''        + (samples.length?(function(){
              const kinds=[...new Set(samples.map(sf=>trafficIntent(sf.port,sf.proto).kind))];
              return '<div class="rd-i" style="margin-top:6px;line-height:1.5">'+kinds.map(k=>{
                const one=samples.map(sf=>trafficIntent(sf.port,sf.proto)).find(x=>x.kind===k);
                return '<b style="color:'+INTENT_COLOR[k]+'">'+esc(one.what)+'</b> <span style="color:var(--faint)">('
                  +esc(INTENT_LABEL[k])+')</span> <span style="color:var(--dim)">'+esc(one.advice)+'</span>';
              }).join("<br>")+'</div>';})():"")
        + (deniedSample?'<div style="padding:0 16px 12px">'+fixBoxHtml(deniedSample)+'</div>':'')''')

# ---------------------------------------------------------------- P62
# Flow logs name the rule that DENIED a flow, never the rule that allowed it. So an
# AVNM allow rule can never be credited with traffic. Reporting it as "no traffic
# seen" invites someone to delete a rule that is doing its job. Say the truth instead.
patch('P62a an unattributable allow is not an unused allow',
'function ruleStatus(r){\n  if(r.shadowed)return {k:"unreachable",label:"Unreachable"};\n  if(r.overridden)return {k:"overridden",label:"Overridden by AVNM"};\n  if(r.hits>0)return {k:"active",label:"Active"};\n  if(!flows.length)return {k:"unknown",label:"—"};\n  return {k:"unused",label:"No traffic seen"};\n}',
'function ruleStatus(r){\n  if(r.shadowed)return {k:"unreachable",label:"Unreachable"};\n  if(r.overridden)return {k:"overridden",label:"Overridden by AVNM"};\n  if(r.hits>0)return {k:"active",label:"Active"};\n  if(!flows.length)return {k:"unknown",label:"—"};\n  // Azure names the rule that DENIED a flow. It never names the rule that allowed it,\n  // so an AVNM allow rule can never be credited. Silence is not evidence of disuse.\n  if(r.admin&&isAllow(r))return {k:"unknown",label:"Not attributable"};\n  return {k:"unused",label:"No traffic seen"};\n}')

patch('P62b analysis stops calling AVNM allows unused',
'        else if(isAllow(r)&&(r.hits||0)===0&&!r.shadowed&&r.priority<4000)\n          add("info","unused","Allow rule sees no traffic: "+r.name,',
'        else if(isAllow(r)&&(r.hits||0)===0&&!r.shadowed&&!r.admin&&!r.observed&&r.priority<4000)\n          add("info","unused","Allow rule sees no traffic: "+r.name,')

patch('P62c effective-rule status says not attributable',
'                 :(r.hits||0)>0?{t:Number(r.hits).toLocaleString()+" flows"+((r.deniedHits||0)?" · "+Number(r.deniedHits).toLocaleString()+" denied":""),c:deny?"var(--danger)":"var(--ok)"}\n                 :{t:"No traffic seen",c:"var(--faint)"};',
'                 :(r.hits||0)>0?{t:Number(r.hits).toLocaleString()+" flows"+((r.deniedHits||0)?" · "+Number(r.deniedHits).toLocaleString()+" denied":""),c:deny?"var(--danger)":"var(--ok)"}\n                 :(r.admin&&!deny)?{t:"not attributable",c:"var(--faint)"}\n                 :{t:"No traffic seen",c:"var(--faint)"};')

patch('P62d the expanded rule explains why it has no traffic',
'  if(!samples.length)\n    return h+\'<div style="font-size:10.5px;color:var(--faint)">\'\n      +(flows.length?"No flow in this window matched this rule.":"No flow logs loaded, so rule traffic cannot be shown.")+\'</div>\';',
'  if(!samples.length){\n    const why = (r.admin&&isAllow(r))\n      ? "Azure names the rule that denied a flow, never the one that allowed it, so traffic cannot be attributed to an AVNM allow rule. This does not mean it is unused."\n      : (flows.length?"No flow in this window matched this rule.":"No flow logs loaded, so rule traffic cannot be shown.");\n    return h+\'<div style="font-size:10.5px;color:var(--faint);line-height:1.45">\'+esc(why)+\'</div>\';\n  }')

# ========================================================= DATADOG HEALTH RINGS
# Datadog CNM colours a node's ring by HEALTH (green healthy / red alerting /
# grey unknown), with the resource type shown by the centre icon. This tool
# coloured the ring by resource TYPE. Move health onto the ring and keep type on
# the centre dot + legend + tables, so nothing is lost. Honest about unknowns:
# a node with no observed traffic gets a neutral grey ring, not a green one.
patch("P70a overview health rings (type stays on the centre dot)",
"""  node.append("circle").attr("r",rOf)
    .attr("stroke-dasharray",d=>(d.type==="ext"||d.groupKey==="internet|all")?"5 3":"none")
    .attr("fill",d=>(!badNodes.has(d.id)&&impairedNodes.has(d.id))?"#FFFBF2":"#FFFFFF")
    .attr("stroke",d=>badNodes.has(d.id)||(d.type==="group"&&d.bad)?"#DC3545":TYPES[d.type].color)""",
"""  // Datadog-style health ring: red = denied traffic seen, amber = impaired path,
  // green = observed (allowed) traffic, grey = no signal. Resource TYPE stays on
  // the centre dot and the legend/tables, so type colouring is preserved.
  const trafficNodes=new Set();
  for(const l of links){ if(l.kind==="traffic"&&!l.denied){ trafficNodes.add(l.source.id||l.source); trafficNodes.add(l.target.id||l.target); } }
  const healthColor=d=>badNodes.has(d.id)?"#DC3545":impairedNodes.has(d.id)?"#E0A02B":trafficNodes.has(d.id)?"#2FA36A":"#C4CCD6";
  node.append("circle").attr("r",rOf)
    .attr("stroke-dasharray",d=>(d.type==="ext"||d.groupKey==="internet|all")?"5 3":"none")
    .attr("fill",d=>(!badNodes.has(d.id)&&impairedNodes.has(d.id))?"#FFFBF2":"#FFFFFF")
    .attr("stroke",d=>d.type==="group"?(d.bad?"#DC3545":TYPES[d.type].color):healthColor(d))""")

# Dependencies view (Datadog's single-service map): same health colouring on the
# side nodes and the root, type still carried by each node's centre dot.
patch("P70b deps side-node health rings",
'.attr("stroke",badNodes.has(d.id)?"#DC3545":TYPES[nd.type].color).attr("stroke-width",2);',
'.attr("stroke",(badNodes.has(d.id)||d.denied)?"#DC3545":impairedNodes.has(d.id)?"#E0A02B":(d.total>0)?"#2FA36A":"#C4CCD6").attr("stroke-width",2);')

patch("P70c deps root health ring",
'.attr("stroke",badNodes.has(root.id)?"#DC3545":TYPES[root.type].color).attr("stroke-width",3);',
'.attr("stroke",badNodes.has(root.id)?"#DC3545":impairedNodes.has(root.id)?"#E0A02B":"#2FA36A").attr("stroke-width",3);')

# Legend: spell out that the node ring encodes health, so green/red/grey read.
patch("P70d node-ring health legend",
'''          <span class="chip"><i style="height:0;border-top:2px dashed var(--danger);width:16px;background:none"></i> denied</span>
        </div>''',
'''          <span class="chip"><i style="height:0;border-top:2px dashed var(--danger);width:16px;background:none"></i> denied</span>
          <span class="chip" style="margin-left:8px"><b style="color:var(--dim);font-weight:600">Node ring = health</b></span>
          <span class="chip"><i style="width:11px;height:11px;border-radius:50%;border:2px solid #2FA36A;background:none"></i> healthy</span>
          <span class="chip"><i style="width:11px;height:11px;border-radius:50%;border:2px solid #DC3545;background:none"></i> denied</span>
          <span class="chip"><i style="width:11px;height:11px;border-radius:50%;border:2px solid #E0A02B;background:none"></i> impaired</span>
          <span class="chip"><i style="width:11px;height:11px;border-radius:50%;border:2px solid #C4CCD6;background:none"></i> no signal</span>
        </div>''')

# ==================================================== MAP CLARITY & DECLUTTER
# P71a: the overview link aggregation copied blockRule/blockGroup but not
# blockLayer (same bug class P1 fixed for the deps view), so the on-map deny
# label rendered "blocked at ?" instead of "blocked at Route table / ...".
patch("P71a carry blockLayer through overview aggregation (fixes 'blocked at ?')",
'''    if(e.kind==="traffic"){a.total+=e.total||1;if(e.denied)a.denied=true;
      if(e.blockRule&&!a.blockRule){a.blockRule=e.blockRule;a.blockGroup=e.blockGroup;}
      for(const r of (e.rows||[]))a.ports.add(":"+r.port);}''',
'''    if(e.kind==="traffic"){a.total+=e.total||1;if(e.denied)a.denied=true;
      if(e.blockRule&&!a.blockRule){a.blockRule=e.blockRule;a.blockGroup=e.blockGroup;}
      if(e.blockLayer&&!a.blockLayer)a.blockLayer=e.blockLayer;
      for(const r of (e.rows||[]))a.ports.add(":"+r.port);}''')

patch("P71a2 expose blockLayer on the built link",
'    blockRule:a.blockRule||"", blockGroup:a.blockGroup||"",',
'    blockRule:a.blockRule||"", blockGroup:a.blockGroup||"", blockLayer:a.blockLayer||"",')

# P71b: the overview drew every port label AND every long "blocked at ..." string
# on top of the graph at all times, so a busy map turned into a wall of text.
# Datadog keeps the map clean and reveals detail on hover. Hide both label layers
# by default and light up only the hovered node's edges. Nothing is lost — the
# panel and the dependencies view still carry the full text.
patch("P71b1 port labels hidden until hover",
'    .attr("text-anchor","middle").attr("opacity",.9);',
'    .attr("text-anchor","middle").attr("opacity",0);')

patch("P71b2 blocked-at labels hidden until hover",
'    .attr("text-anchor","middle").attr("opacity",.95);',
'    .attr("text-anchor","middle").attr("opacity",0);')

patch("P71b3 hover reset also clears both label layers",
'link.attr("opacity",d=>d.denied?.95:d.kind==="traffic"?.7:.5);lbl.attr("opacity",.9);return;}',
'link.attr("opacity",d=>d.denied?.95:d.kind==="traffic"?.7:.5);lbl.attr("opacity",0);lbl2.attr("opacity",0);return;}')

patch("P71b4 hover reveals both label layers for the focused node",
'    lbl.attr("opacity",d=>{const s2=d.source.id||d.source,t2=d.target.id||d.target;return (s2===id||t2===id)?1:.05;});',
'''    lbl.attr("opacity",d=>{const s2=d.source.id||d.source,t2=d.target.id||d.target;return (s2===id||t2===id)?1:.05;});
    lbl2.attr("opacity",d=>{const s2=d.source.id||d.source,t2=d.target.id||d.target;return (s2===id||t2===id)?1:0;});''')

# P71c: the three stacked prose paragraphs under the map read as a wall of text.
# Fold the explanation into one collapsible "How to read this map" disclosure
# (native <details>, no JS), so the default view stays clean and professional.
patch("P71c fold map prose into a collapsible",
'''        <div class="canvasHint" style="border-top:0;padding-top:0;color:var(--faint)">
          <span><b>Moving dots = flows Azure actually recorded</b>, travelling source → destination. Dot count and line width scale with volume. A plain line means connected in configuration, with nothing recorded flowing.</span>
          <span><b>Red = denied.</b> A rule said no. Dots stop halfway and the line reads <i>blocked at &lt;policy or NSG&gt; / &lt;rule&gt;</i>.</span>
          <span><b>Amber = impaired.</b> Nothing denied it, but the path cannot complete: an empty backend pool, a failing health probe, SNAT exhaustion, a peering that never connected, a blackhole route, or a destination that never answered.</span>
        </div>
        <div class="canvasHint" style="border-top:0;padding-top:0;color:var(--faint)">
          <span><b>Numbers:</b> inside a circle = resources in that cluster.</span>
          <span><b>×N</b> on a line = N separate links collapsed into one.</span>
          <span>Ports (<b>:53</b>) and flow counts label traffic lines only.</span>
        </div>''',
'''        <details class="canvasHint" style="border-top:0;padding-top:0;color:var(--faint);display:block">
          <summary style="cursor:pointer;color:var(--dim);font-weight:600">How to read this map</summary>
          <div style="display:flex;flex-direction:column;gap:5px;margin-top:6px;line-height:1.5;max-width:1100px">
            <span><b>Line width</b> = traffic volume · <b>moving dots</b> show direction, source → destination. A plain line is a configuration link with nothing flowing.</span>
            <span><b style="color:var(--danger)">Red</b> = a rule denied the flow — hover the edge to see the layer and rule. <b style="color:var(--warn)">Amber</b> = impaired: nothing denied it, but the path can\\'t complete (empty backend pool, failing health probe, SNAT exhaustion, an unconnected peering, a blackhole route, or an endpoint that never answered).</span>
            <span><b>Number in a circle</b> = resources in that cluster · <b>×N</b> = N links collapsed into one · ports (<b>:443</b>) and flow counts label traffic edges on hover.</span>
          </div>
        </details>''')

# P71d: point people at the hover interaction, and drop the now-redundant inline
# "width = volume · dots = direction" from the traffic chip.
patch("P71d intro line names the hover interaction",
'          <span>Scroll to zoom · drag to move · click a node for actions</span>',
'          <span>Scroll to zoom · drag to pan · click a node for actions · <b style="color:var(--dim)">hover a node to reveal its ports and the rule that blocked it</b></span>')

patch("P71d2 shorten the traffic chip",
'          <span class="chip"><i style="background:var(--edgeTraffic);height:3px"></i> observed traffic · width = volume · dots = direction</span>',
'          <span class="chip"><i style="background:var(--edgeTraffic);height:3px"></i> observed traffic</span>')

# ============================================= EXTERNAL / PUBLIC CONNECTIONS
# Task 1 companion (HTML side). The fixed KQL now delivers public/external flows
# with a real address plus Azure's own enrichment (service tag, country). Parse
# those, and NAME the far end — Cloudflare (published CIDRs), the Azure service
# tag Azure attached, or at least the country — instead of collapsing every
# public IP into one anonymous "Internet" node. This is what lets the map answer
# "is this resource talking to Cloudflare?".

# P72a1: recover the public address when SrcIp/DestIp is blank, and add the parse
# helpers. (Belt-and-braces with the KQL, and it makes public flows renderable
# straight from raw NTANetAnalytics rows too.)
patch("P72a1 public-IP fallback in the flow normalizer",
'''    if(r&&isIp(r.src)&&isIp(r.dst)&&typeof r.port==="number")return r; // already normalized
    return {
      src:pick(r,["SrcIp","SrcIP","SourceIP","srcip_s","src"]),
      dst:pick(r,["DestIp","DstIp","DestIP","destip_s","dst"]),''',
'''    if(r&&isIp(r.src)&&isIp(r.dst)&&typeof r.port==="number")return r; // already normalized
    // AzurePublic / ExternalPublic flows report the far end in Src/DestPublicIps, not
    // Src/DestIp (bar-delimited, first token = IP). Azure also tags the owner and country.
    const firstIp=s=>{const m=String(s||"").match(/([0-9A-Fa-f:.]+)/);return m&&isIp(m[1])?m[1]:"";};
    const lastSeg=s=>{const p=String(s||"").split("|");return p.length>1?p[p.length-1].trim():"";};
    return {
      src:pick(r,["SrcIp","SrcIP","SourceIP","srcip_s","src"])||firstIp(pick(r,["SrcPublicIps"])),
      dst:pick(r,["DestIp","DstIp","DestIP","destip_s","dst"])||firstIp(pick(r,["DestPublicIps"])),''')

# P72a2: carry the service tag and country onto each flow for labelling.
patch("P72a2 carry service tag / country on flows",
'''      flowType:pick(r,["FlowType"])||"",
      peId:pick(r,["PrivateEndpointResourceId"])||"",''',
'''      flowType:pick(r,["FlowType"])||"",
      srcTag:lastSeg(pick(r,["SrcServiceTags"])),
      dstTag:lastSeg(pick(r,["DestServiceTags"])),
      country:pick(r,["Country"])||"",
      peId:pick(r,["PrivateEndpointResourceId"])||"",''')

# P72b: the classifier + Cloudflare's published ranges.
patch("P72b external-endpoint classifier",
'function attachTraffic(graph,flows){',
'''// Well-known external providers we can name from a public IP. Cloudflare publishes its
// ranges (cloudflare.com/ips, IPv4 set). Azure service tags and per-flow Country come
// straight from NTANetAnalytics, so they need no static list.
const CLOUDFLARE_CIDRS=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"];
const COUNTRY_NAMES={US:"United States",GB:"United Kingdom",CA:"Canada",DE:"Germany",FR:"France",NL:"Netherlands",IE:"Ireland",AU:"Australia",IN:"India",SG:"Singapore",JP:"Japan",BR:"Brazil"};
// Give an external public IP the most specific identity we can prove: a named provider
// (Cloudflare), the Azure service tag Azure itself attached, or its country.
function classifyExt(ip,tag,country){
  if(CLOUDFLARE_CIDRS.some(c=>inCidr(ip,c)))
    return {id:"extsvc|cloudflare",name:"Cloudflare",prov:"cloudflare",meta:{ip,provider:"Cloudflare (WAF / reverse proxy)"}};
  const t=String(tag||"").trim();
  if(t&&!/^internet$/i.test(t)){const base=t.split(".")[0];
    return {id:"extsvc|tag:"+base,name:base,prov:"tag:"+base,meta:{ip,serviceTag:t}};}
  const c=String(country||"").trim().toUpperCase();
  if(c) return {id:"ext:"+ip,name:ip,prov:"",meta:{ip,country:c,countryName:COUNTRY_NAMES[c]||c}};
  return {id:"ext:"+ip,name:ip,prov:"",meta:{ip}};
}
function attachTraffic(graph,flows){''')

# P72c: resolve() consults the classifier for external IPs (dedupes Cloudflare's many
# IPs to one node, service-tagged IPs to one node per service).
patch("P72c resolve signature takes external meta",
'''  const resolve=ip=>{
    if(ipMap.has(ip))return ipMap.get(ip);''',
'''  const resolve=(ip,extMeta)=>{
    if(ipMap.has(ip))return ipMap.get(ip);''')

patch("P72c2 resolve names external endpoints",
'''    if(!extNodes.has(ip))extNodes.set(ip,{id:"ext:"+ip,type:"ext",name:ip,sub:"",meta:{ip}});
    return "ext:"+ip;''',
'''    const ex=classifyExt(ip,extMeta&&extMeta.tag,extMeta&&extMeta.country);
    if(!extNodes.has(ex.id))extNodes.set(ex.id,{id:ex.id,type:"ext",name:ex.name,sub:"",prov:ex.prov,meta:ex.meta});
    return ex.id;''')

# P72d: pass each side's tag + the flow's country into resolve.
patch("P72d flow loop passes tag/country to resolve",
'    const a=resolve(f.src),b=resolve(f.dst); if(a===b)continue;',
'    const a=resolve(f.src,{tag:f.srcTag,country:f.country}),b=resolve(f.dst,{tag:f.dstTag,country:f.country}); if(a===b)continue;')

# P72e: named external providers stand alone as their own node; only anonymous bare
# IPs still collapse into the single Internet bucket.
patch("P72e named external providers are not collapsed into Internet",
'  if(n.type==="ext")return "internet|all";           // public IPs collapse into one Internet node',
'  if(n.type==="ext")return n.prov?null:"internet|all"; // Cloudflare / service-tagged endpoints stand alone; bare IPs collapse')

# ================================================== RESOURCE-TYPE ICONS ON MAP
# The Architecture view already draws per-resource icons via iconSvg() (which uses
# the official Azure icon pack when icons/manifest.json is present, else the built-in
# glyph). Bring the same icon into the CENTRE of every map node, Datadog-style, so a
# resource's type reads at a glance on the graph too — not just its ring colour.
patch("P73 resource-type icon in the centre of map nodes",
'''  node.append("circle").attr("r",d=>Math.max(3,rOf(d)*0.30))
    .attr("fill",d=>badNodes.has(d.id)||(d.type==="group"&&d.bad)?"#DC3545":TYPES[d.type].color)
    .attr("opacity",d=>d.type==="group"?0:0.85);''',
'''  node.append("circle").attr("r",d=>Math.max(3,rOf(d)*0.30))
    .attr("fill",d=>badNodes.has(d.id)||(d.type==="group"&&d.bad)?"#DC3545":TYPES[d.type].color)
    .attr("opacity",d=>(d.type==="group"||GLYPH[d.type])?0:0.85);
  // Azure resource-type icon in the node centre. Uses the official icon pack when
  // icons/manifest.json is loaded (make-icon-pack.sh), otherwise the built-in glyph.
  node.filter(d=>d.type!=="group"&&GLYPH[d.type]).each(function(d){
    const sz=Math.min(16,Math.max(11,rOf(d)*1.3));
    const gg=document.createElementNS("http://www.w3.org/2000/svg","g");
    gg.setAttribute("transform","translate("+(-sz/2)+","+(-sz/2)+")");
    gg.innerHTML=iconSvg(d.type,badNodes.has(d.id)?"#B91C1C":TYPES[d.type].color,sz);
    this.appendChild(gg);
  });''')

# ============================================ AZURE RULE RECOMMENDATIONS (NTA)
# Azure Traffic Analytics publishes NTARuleRecommendation: a per-traffic-pattern
# verdict of Allow / Block / Advisory. That is Microsoft's own answer to "is this
# rule legitimate?". generate-netmap.sh now collects it into EMBEDDED.recos;
# surface it in the Analysis tab next to the tool's own heuristic.
patch("P74a load rule recommendations",
'let metricsRaw=EMBEDDED&&EMBEDDED.metrics?EMBEDDED.metrics:[];',
'''let metricsRaw=EMBEDDED&&EMBEDDED.metrics?EMBEDDED.metrics:[];
let recos=EMBEDDED&&EMBEDDED.recos?EMBEDDED.recos:[];''')

patch("P74b Azure rule recommendations section in Analysis",
'  const groups=deniedByRule();',
'''  // Azure's own verdict (NTARuleRecommendation): Allow / Block / Advisory per pattern.
  if(recos&&recos.length){
    const AC={Allow:"#1F9D62",Block:"#B02A37",Advisory:"#9A6700"};
    html+='<div class="secTitle" style="margin-top:14px">Azure rule recommendations'
       +'<span style="color:var(--faint);font-weight:400;text-transform:none;letter-spacing:0"> '
       +recos.length+" from Traffic Analytics — Microsoft's own Allow / Block / Advisory verdict on observed traffic</span></div>";
    html+='<table class="rules"><thead><tr><th>VERDICT</th><th>PROTO</th><th>PORTS</th><th>SOURCE</th><th>DESTINATION</th><th>SCOPE</th><th>RULE</th></tr></thead><tbody>';
    for(const r of recos.slice(0,200)){
      const act=r.RecommendedAction||r.recommendedAction||"";
      const col=AC[act]||"var(--dim)";
      const src=r.SrcPublicIpCidrs||r.SrcServiceTagsList||"*";
      const dst=r.DestPublicIpCidrs||r.DestServiceTagsList||"*";
      const ports=String(r.DestPortsRanges||"")+(r.PortCategory?" ("+r.PortCategory+")":"");
      html+='<tr><td><span style="display:inline-block;font-size:9.5px;font-weight:700;letter-spacing:.04em;'
        +'text-transform:uppercase;padding:2px 7px;border-radius:9px;color:#fff;background:'+col+'">'+esc(act||"—")+'</span></td>'
        +'<td>'+esc(r.L4Protocol||"")+'</td><td>'+esc(ports||"—")+'</td>'
        +'<td class="mono">'+esc(String(src).slice(0,40))+'</td>'
        +'<td class="mono">'+esc(String(dst).slice(0,40))+'</td>'
        +'<td>'+esc(r.RuleScope||"")+'</td><td>'+esc(r.RecommendedRuleName||"")+'</td></tr>';
    }
    html+='</tbody></table>';
    html+='<div style="font-size:11px;color:var(--faint);margin:4px 0 6px"><b style="color:#B02A37">Block</b> = traffic Azure judges you should not be allowing · <b style="color:#1F9D62">Allow</b> = legitimate traffic worth an explicit rule · <b style="color:#9A6700">Advisory</b> = review. Azure derives these from observed flows; cross-check against the Rules tab.</div>';
  }
  const groups=deniedByRule();''')

# ================================================ EFFECTIVE ROUTES (per NIC)
# The tool reads authored UDRs. generate-netmap.sh can now also collect each NIC's
# EFFECTIVE route table (UDR + BGP + system, as Azure applies it) via Network Watcher
# into EMBEDDED.effectiveRoutes. Show it on the resource's panel — the real answer to
# "where does this traffic actually go?".
patch("P75a load and index effective routes",
'let recos=EMBEDDED&&EMBEDDED.recos?EMBEDDED.recos:[];',
'''let recos=EMBEDDED&&EMBEDDED.recos?EMBEDDED.recos:[];
let effRoutes=EMBEDDED&&EMBEDDED.effectiveRoutes?EMBEDDED.effectiveRoutes:[];
const effRoutesBy=new Map(); for(const e of effRoutes){ if(e&&e.nicId)effRoutesBy.set(low(e.nicId),e.routes||[]); }''')

patch("P75b effective-routes section on the panel",
'''  if(sel.meta.routes&&sel.meta.routes.length){
    html+='<div class="secTitle" style="color:var(--hi)">ROUTES</div>';
    for(const r of sel.meta.routes)html+='<div class="traf" style="cursor:default;color:var(--text)">'+esc(r)+'</div>';
  }''',
'''  if(sel.meta.routes&&sel.meta.routes.length){
    html+='<div class="secTitle" style="color:var(--hi)">ROUTES</div>';
    for(const r of sel.meta.routes)html+='<div class="traf" style="cursor:default;color:var(--text)">'+esc(r)+'</div>';
  }
  {
    const er=effRoutesBy.get(low(sel.id));
    if(er&&er.length){
      html+='<div class="secTitle" style="color:var(--hi)">EFFECTIVE ROUTES <span style="color:var(--faint);font-weight:400;text-transform:none;letter-spacing:0">UDR + BGP + system, as Azure applies them</span></div>';
      for(const r of er.slice(0,24)){
        const drop=/^none$/i.test(r.nextHopType||"");
        const hop=(r.nextHopType||"")+(r.nextHopIp?" "+r.nextHopIp:"");
        html+='<div class="traf" style="cursor:default;color:'+(drop?"var(--danger)":"var(--text)")+'">'+esc(r.prefix||"")+' → '+esc(hop)+(r.source?' <span style="color:var(--faint)">'+esc(r.source)+'</span>':'')+(drop?' <span style="color:var(--danger)">blackhole</span>':'')+'</div>';
      }
    }
  }''')

# ================================ NODE SIZE BY VOLUME + DENY DETAIL IN TOOLTIP
# P76a: memoise nodeTraffic (it is about to be called once per node for sizing) and
# collect, per node, the layer/group/rule of every denied path touching it.
patch("P76a memoise nodeTraffic and collect deny reasons",
'''function nodeTraffic(id){
  let out=0,inn=0,flows=0,denied=0;
  for(const e of fullGraph.edges){
    if(e.kind!=="traffic")continue;
    if(e.source===id){ out+=e.bytesOut||0; inn+=e.bytesIn||0; flows+=e.total||0; if(e.denied)denied++; }
    else if(e.target===id){ out+=e.bytesIn||0; inn+=e.bytesOut||0; flows+=e.total||0; if(e.denied)denied++; }
  }
  return {out,inn,flows,denied};
}''',
'''let _ntCache=new Map(), _ntVer=null;
function nodeTraffic(id){
  if(_ntVer!==fullGraph){ _ntCache=new Map(); _ntVer=fullGraph; }
  if(_ntCache.has(id))return _ntCache.get(id);
  let out=0,inn=0,flows=0,denied=0; const deny=[];
  for(const e of fullGraph.edges){
    if(e.kind!=="traffic")continue;
    const isSrc=e.source===id, isTgt=e.target===id;
    if(!isSrc&&!isTgt)continue;
    if(isSrc){ out+=e.bytesOut||0; inn+=e.bytesIn||0; } else { out+=e.bytesIn||0; inn+=e.bytesOut||0; }
    flows+=e.total||0;
    if(e.denied){ denied++;
      const oid=isSrc?(e.target.id||e.target):(e.source.id||e.source), o=byId&&byId.get(oid);
      deny.push({peer:o?o.name:"?", layer:DENY_LAYER[e.blockLayer]||"unknown", group:e.blockGroup||"", rule:e.blockRule||""}); }
  }
  const res={out,inn,flows,denied,deny};
  _ntCache.set(id,res); return res;
}''')

# P76b: node radius grows with observed traffic volume (Datadog-style), so a busy
# resource reads as a bigger circle. No traffic keeps the type's base size.
patch("P76b node size scales with traffic volume",
'const rOf=d=>d.type==="group"?Math.max(19,Math.min(50,12+Math.sqrt(d.count)*3.1)):TYPES[d.type].r+2;',
'''const rOf=d=>{
  if(d.type==="group")return Math.max(19,Math.min(50,12+Math.sqrt(d.count)*3.1));
  const base=TYPES[d.type].r+2, t=nodeTraffic(d.id), bytes=(t.out||0)+(t.inn||0);
  return bytes>0?Math.max(base,Math.min(30,base+Math.log10(bytes)*1.9)):base;
};''')

# P76c: put the deny detail (which layer/rule blocked it) in the node hover box,
# not only the count — so hovering a red node explains WHY it is red.
patch("P76c deny detail in the node hover box",
'''      if(t.denied)html+='<div class="tr bad"><span>Denied paths</span><b>'+t.denied+'</b></div>';''',
'''      if(t.denied){
        html+='<div class="tr bad"><span>Denied paths</span><b>'+t.denied+'</b></div>';
        const seen=new Set();
        for(const dn of (t.deny||[])){
          const k=dn.layer+"|"+dn.group+"|"+dn.rule; if(seen.has(k))continue; seen.add(k);
          html+='<div class="tr bad" style="align-items:flex-start"><span>blocked at</span>'
              + '<b style="text-align:right;max-width:210px">'+esc(dn.layer)+(dn.group?" "+esc(dn.group):"")
              + (dn.rule?'<br><span style="color:#FCA5A5;font-weight:400">'+esc(dn.rule)+'</span>':'')+'</b></div>';
          if(seen.size>=3)break;
        }
      }''')

# ============================================== MAP DECLUTTER: DROP EDGE PROSE
# The long "blocked at ..." / "impaired: ..." strings that were drawn on the edges
# are now fully carried by the node hover box (deny layer + rule) and the amber
# ring, so remove them from the map entirely — no more words sprawled across it.
patch("P77 remove blocked-at / impaired edge labels from the map",
'''  const lbl2=halo(root.append("g").selectAll("text")
    .data(links.filter(d=>(d.denied&&(d.blockRule||d.blockGroup))||d.impaired)).join("text"))''',
'''  const lbl2=halo(root.append("g").selectAll("text")
    .data([]).join("text"))''')

# ============================================= ANALYSIS TAB: COMPACT THE INTRO
# The five-line severity explainer was a wall of text at the top of Analysis.
# Replace it with a one-line severity strip and fold the full explanation into a
# collapsible, the same pattern used under the map.
patch("P78 compact the Analysis severity legend",
'''  html+='<div class="sevKey">'
    +'<div><span class="fb high">High</span> Broken or exposed right now: traffic is being blocked, a management port is open to the internet, SNAT ports are exhausted, a backend is unhealthy.</div>'
    +'<div><span class="fb warn">Warning</span> Configuration that is wrong or ineffective: a rule that can never match, an NSG allow that AVNM overrides, a VNet outside AVNM, a subnet with no NSG.</div>'
    +'<div><span class="fb info">Info</span> Hygiene: unattached NSGs, rules that saw no traffic, subnets with no route table. Worth cleaning up, not urgent.</div>'
    +'<div style="color:var(--faint);margin-top:2px"><b>Severity is not traffic volume.</b> For top talkers use the Metrics tab; for the busiest rules, sort the Rules tab by Traffic.</div>'
    +'<div style="color:var(--faint)"><b style="color:#B02A37">Denied</b> = a rule said no, and Azure names it. <b style="color:#9A6700">Impaired</b> = nothing denied it, the path cannot complete. Different colours on the map, different fixes.</div>'
    +'</div>';''',
'''  html+='<div class="sevKey" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">'
    +'<span class="fb high">High</span><span style="color:var(--faint)">broken or exposed now</span>'
    +'<span class="fb warn">Warning</span><span style="color:var(--faint)">wrong or ineffective config</span>'
    +'<span class="fb info">Info</span><span style="color:var(--faint)">hygiene</span>'
    +'<details style="margin-left:auto"><summary style="cursor:pointer;color:var(--dim);font-weight:600;font-size:11px;list-style:none">What these mean</summary>'
    +'<div style="margin-top:7px;line-height:1.55;max-width:900px;font-weight:400">'
    +'<div><b>High</b> — traffic blocked now, a management port open to the internet, SNAT exhausted, a backend unhealthy.</div>'
    +'<div><b>Warning</b> — a rule that can never match, an NSG allow that AVNM overrides, a VNet outside AVNM, a subnet with no NSG.</div>'
    +'<div><b>Info</b> — unattached NSGs, rules that saw no traffic, subnets with no route table.</div>'
    +"<div style=\\"color:var(--faint);margin-top:3px\\"><b>Severity is not volume</b> — for top talkers use Metrics; for the busiest rules sort Rules by Traffic. <b style=\\"color:#B02A37\\">Denied</b> = a rule said no. <b style=\\"color:#9A6700\\">Impaired</b> = nothing denied it, the path cannot complete.</div>"
    +'</div></details>'
    +'</div>';''')

# =============================================== METRICS TAB: REAL SORT KEYS
# The sort dropdown offered CPU / network / disk, which don't match the network
# metrics actually collected (SNAT, availability, health, unhealthy hosts), so the
# sort did nothing. Replace with keys that match the real metric names.
patch("P79 metrics sort by real network metrics",
'<select id="mSort"><option value="cpu">Sort by CPU</option><option value="network">Sort by network</option><option value="disk">Sort by disk</option></select>',
'<select id="mSort"><option value="snatport">Sort by SNAT utilization</option><option value="availability">Sort by availability</option><option value="firewallhealth">Sort by firewall health</option><option value="unhealthy">Sort by unhealthy hosts</option><option value="latency">Sort by latency</option></select>')

# =================================================== CUSTOM DATE/TIME RANGE
# The window control offers presets (30 min … 7 days). Add an absolute from → to
# range, wired on the Map, Rules and Analysis tabs. The window is global, so a
# custom range set on any tab applies everywhere. Filters captured flow data only;
# it never re-queries Azure (same contract as the presets).

# --- state + filtering ---
patch("P80a custom-range state",
'let windowMin=0;              // 0 = the whole scan window',
'''let windowMin=0;              // 0 = the whole scan window
let winFrom=null, winTo=null; // absolute custom range (ms); overrides windowMin when set''')

patch("P80b flows honour the custom range",
'''function flowsInWindow(){
  if(!windowMin||!allFlowRows.length)return allFlowRows;''',
'''function flowsInWindow(){
  if(winFrom&&winTo)return allFlowRows.filter(f=>!f.ts||(f.ts>=winFrom&&f.ts<=winTo));
  if(!windowMin||!allFlowRows.length)return allFlowRows;''')

patch("P80c firewall logs honour the custom range",
'''function fwInWindow(){
  if(!windowMin||!fwRows.length)return fwRows;''',
'''function fwInWindow(){
  if(winFrom&&winTo)return fwRows.filter(r=>!r.ts||(r.ts>=winFrom&&r.ts<=winTo));
  if(!windowMin||!fwRows.length)return fwRows;''')

patch("P80d applyCustomWindow + rebuildForWindow",
'''function applyWindow(min){
  windowMin=min;
  const base0=buildGraph(items);''',
'''function applyWindow(min){ windowMin=min; winFrom=winTo=null; rebuildForWindow(); }
function applyCustomWindow(from,to){ windowMin=0; winFrom=from; winTo=to; rebuildForWindow(); }
function rebuildForWindow(){
  const base0=buildGraph(items);''')

patch("P80e windowRange reflects the custom range",
'''function windowRange(){
  const to=newestFlowTs();
  if(!to)return null;''',
'''function windowRange(){
  if(winFrom&&winTo)return {from:winFrom,to:winTo};
  const to=newestFlowTs();
  if(!to)return null;''')

patch("P80f windowLabel reflects the custom range",
'  const base=windowMin?"last "+humanMins(windowMin):(flowSpanMin?"all "+humanMins(flowSpanMin):"all flows");',
'  const base=(winFrom&&winTo)?"custom range":(windowMin?"last "+humanMins(windowMin):(flowSpanMin?"all "+humanMins(flowSpanMin):"all flows"));')

# --- markup: Map toolbar ---
patch("P80g custom-range control on the Map toolbar",
'''      <option value="10080">Last 7 days</option>
    </select>
  </div>''',
'''      <option value="10080">Last 7 days</option>
      <option value="custom">Custom range…</option>
    </select>
    <span id="timeWinCustom" style="display:none;gap:5px;align-items:center">
      <input type="datetime-local" id="timeWinFrom" style="font-size:11px;padding:3px 5px" />
      <span style="color:var(--faint)">→</span>
      <input type="datetime-local" id="timeWinTo" style="font-size:11px;padding:3px 5px" />
      <button class="btn" id="timeWinApply">Apply</button>
    </span>
  </div>''')

# --- markup: Rules toolbar ---
patch("P80h custom-range control on the Rules toolbar",
'''        <option value="10080">Last 7 days</option>
      </select>
      <select id="ruleAccess">''',
'''        <option value="10080">Last 7 days</option>
        <option value="custom">Custom range…</option>
      </select>
      <span id="ruleWinCustom" style="display:none;gap:5px;align-items:center">
        <input type="datetime-local" id="ruleWinFrom" style="font-size:11px;padding:3px 5px" />
        <span style="color:var(--faint)">→</span>
        <input type="datetime-local" id="ruleWinTo" style="font-size:11px;padding:3px 5px" />
        <button class="btn" id="ruleWinApply">Apply</button>
      </span>
      <select id="ruleAccess">''')

# --- markup: Analysis window control (it had none) ---
patch("P80i window control on the Analysis tab",
'''  <div id="analysisView" style="display:none">
    <div class="statusline" id="anaSummary"></div>''',
'''  <div id="analysisView" style="display:none">
    <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
      <span style="font-size:11px;color:var(--faint)">Traffic window</span>
      <select id="anaWin" title="Filters the traffic already captured in this scan; it does not re-query Azure.">
        <option value="0">All flows in this scan</option>
        <option value="30">Last 30 minutes</option>
        <option value="60">Last hour</option>
        <option value="360">Last 6 hours</option>
        <option value="1440">Last 24 hours</option>
        <option value="4320">Last 3 days</option>
        <option value="10080">Last 7 days</option>
        <option value="custom">Custom range…</option>
      </select>
      <span id="anaWinCustom" style="display:none;gap:5px;align-items:center">
        <input type="datetime-local" id="anaWinFrom" style="font-size:11px;padding:3px 5px" />
        <span style="color:var(--faint)">→</span>
        <input type="datetime-local" id="anaWinTo" style="font-size:11px;padding:3px 5px" />
        <button class="btn" id="anaWinApply">Apply</button>
      </span>
    </div>
    <div class="statusline" id="anaSummary"></div>''')

# --- handlers: wire preset + custom on all three tabs ---
patch("P80j wire custom-range handlers",
'''bind("timeWin","onchange",function(){applyWindow(+this.value);syncWindowControls();});
bind("ruleWin","onchange",function(){applyWindow(+this.value);syncWindowControls();});''',
'''function _winToMs(v){const t=v?Date.parse(v):NaN;return isNaN(t)?null:t;}
function _winToLocal(ms){const d=new Date(ms-new Date(ms).getTimezoneOffset()*60000);return d.toISOString().slice(0,16);}
function wireWin(sel,customId,fromId,toId,applyId){
  const s=document.getElementById(sel); if(!s)return;
  s.onchange=function(){
    const cc=document.getElementById(customId);
    if(this.value==="custom"){
      if(cc)cc.style.display="inline-flex";
      const r=windowRange();
      if(r){const f=document.getElementById(fromId),t=document.getElementById(toId);if(f)f.value=_winToLocal(r.from);if(t)t.value=_winToLocal(r.to);}
    }else{ if(cc)cc.style.display="none"; applyWindow(+this.value); syncWindowControls(); }
  };
  const ab=document.getElementById(applyId);
  if(ab)ab.onclick=function(){
    const f=_winToMs((document.getElementById(fromId)||{}).value), t=_winToMs((document.getElementById(toId)||{}).value);
    const info=document.getElementById("focusInfo");
    if(f==null||t==null||f>=t){ if(info)info.textContent="Pick a valid from → to range."; return; }
    applyCustomWindow(f,t); syncWindowControls();
  };
}
wireWin("timeWin","timeWinCustom","timeWinFrom","timeWinTo","timeWinApply");
wireWin("ruleWin","ruleWinCustom","ruleWinFrom","ruleWinTo","ruleWinApply");
wireWin("anaWin","anaWinCustom","anaWinFrom","anaWinTo","anaWinApply");''')

patch("P80k syncWindowControls keeps all three selects in step",
'''  const a=document.getElementById("timeWin"), b=document.getElementById("ruleWin");
  if(!a||!b)return;
  b.value=String(windowMin||0); a.value=String(windowMin||0);''',
'''  const a=document.getElementById("timeWin"), b=document.getElementById("ruleWin"), an=document.getElementById("anaWin");
  if(!a||!b)return;
  const v=(winFrom&&winTo)?"custom":String(windowMin||0);
  a.value=v; b.value=v; if(an)an.value=v;
  for(const cid of ["timeWinCustom","ruleWinCustom","anaWinCustom"]){
    const cc=document.getElementById(cid); if(cc)cc.style.display=(v==="custom")?"inline-flex":"none";
  }''')

# ==================================== EFFECTIVE RULES: INCLUDE FIREWALL LAYER
# The effective-rules panel already pulls the AVNM security admin rules and the
# NSG rules that apply to a resource, in evaluation order. Add the Azure Firewall
# policy rules too, when the resource's routes (authored UDR or the effective
# table) steer egress to a firewall — so for a denied flow you can see all three
# rule layers together and where an allow would need to go to unblock it.
patch("P81 firewall policy rules in the effective-rules panel",
'''  for(const id of nicIds)
    for(const e of fullGraph.edges) if(e.kind==="nsg"&&e.source===id){
      const g=byId.get(e.target); if(g&&g.meta.rules)layers.push({layer:"NIC NSG",from:g.name,rules:g.meta.rules});
    }
  return layers;''',
'''  for(const id of nicIds)
    for(const e of fullGraph.edges) if(e.kind==="nsg"&&e.source===id){
      const g=byId.get(e.target); if(g&&g.meta.rules)layers.push({layer:"NIC NSG",from:g.name,rules:g.meta.rules});
    }
  // Azure Firewall policy rules, when egress from this resource is steered to a firewall
  // (a next hop of VirtualAppliance in an authored UDR or the effective route table).
  let viaFw=false;
  const rtIds=new Set();
  for(const id of (nicIds.length?nicIds:[nodeId]))
    for(const e of fullGraph.edges) if(e.kind==="inSubnet"&&e.source===id)
      for(const e2 of fullGraph.edges) if(e2.kind==="rt"&&e2.source===e.target) rtIds.add(e2.target);
  for(const rid of rtIds){ const rt=byId.get(rid); if(rt&&rt.meta.routes&&rt.meta.routes.some(x=>/virtualappliance/i.test(x))) viaFw=true; }
  for(const id of (nicIds.length?nicIds:[nodeId])){ const er=effRoutesBy.get(low(id)); if(er&&er.some(r=>/virtualappliance/i.test(r.nextHopType||""))) viaFw=true; }
  if(viaFw)
    for(const fp of fullGraph.nodes.filter(x=>x.type==="fwrcg"&&x.meta.rules&&x.meta.rules.length))
      layers.push({layer:"Azure Firewall policy",from:fp.name,rules:fp.meta.rules});
  return layers;''')

open(SRC, "w", encoding="utf-8").write(html)
print(f"OK — {len(applied)} patch(es) applied:")
for a in applied:
    print("  ", a)
