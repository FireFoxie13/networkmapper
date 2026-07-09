#!/usr/bin/env bash
# make-icon-pack.sh — turn Microsoft's official Azure icon set into an icon pack
# the mapper can use.
#
# Microsoft's Azure architecture icons are licensed for use in YOUR diagrams,
# documentation and training material, but they may not be redistributed. So they
# are not bundled with this tool. Download them yourself, then run this script.
#
#   1. Get the icon pack:  https://learn.microsoft.com/azure/architecture/icons/
#      (a .zip of SVGs). Accept the terms on that page.
#   2. ./make-icon-pack.sh ~/Downloads/Azure_Public_Service_Icons.zip
#      or, if you already unzipped it:
#      ./make-icon-pack.sh ~/Downloads/Azure_Public_Service_Icons/
#
# Writes ./maps/icons/manifest.json. The mapper picks it up automatically and
# swaps its built-in glyphs for the real Azure icons.
set -uo pipefail

SRC="${1:-}"
OUT_DIR="${2:-./maps/icons}"

if [ -z "$SRC" ]; then
  echo "usage: $0 <path-to-azure-icons.zip | path-to-unzipped-folder> [output-dir]" >&2
  exit 1
fi
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

WORK=""
cleanup(){ [ -n "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT

if [ -f "$SRC" ]; then
  command -v unzip >/dev/null || { echo "unzip required to read a .zip" >&2; exit 1; }
  WORK=$(mktemp -d)
  echo ">> unzipping $SRC"
  unzip -qo "$SRC" -d "$WORK" || { echo "unzip failed" >&2; exit 1; }
  ROOT="$WORK"
elif [ -d "$SRC" ]; then
  ROOT="$SRC"
else
  echo "not a file or directory: $SRC" >&2; exit 1
fi

mkdir -p "$OUT_DIR"

python3 - "$ROOT" "$OUT_DIR/manifest.json" <<'PY'
import sys, os, re, json

root, out = sys.argv[1], sys.argv[2]

# node type -> keywords that should appear in the icon's filename.
# First match wins, so put the specific ones first.
WANT = [
    ("avnm",      ["virtual-network-manager", "network-manager"]),
    ("fwpolicy",  ["firewall-policy", "firewall-policies"]),
    ("fw",        ["firewall"]),
    ("appgw",     ["application-gateway"]),
    ("wafpolicy", ["web-application-firewall", "waf"]),
    ("lb",        ["load-balancer"]),
    ("natgw",     ["nat", "nat-gateway"]),
    ("bastion",   ["bastion"]),
    ("vgw",       ["virtual-network-gateway", "vpn-gateway"]),
    ("erc",       ["expressroute", "express-route"]),
    ("vwan",      ["virtual-wan"]),
    ("vhub",      ["virtual-wan-hub", "virtual-hub"]),
    ("pe",        ["private-endpoint"]),
    ("plsvc",     ["private-link-service", "private-link"]),
    ("dnsres",    ["dns-private-resolver", "dns-resolver"]),
    ("zone",      ["private-dns", "dns-private-zone"]),
    ("dnszone",   ["dns-zone", "dns-zones"]),
    ("fwdrules",  ["dns-forwarding", "forwarding-ruleset"]),
    ("subnet",    ["subnet"]),
    ("vnet",      ["virtual-network"]),
    ("nsg",       ["network-security-group"]),
    ("asg",       ["application-security-group"]),
    ("ipgroup",   ["ip-group"]),
    ("rt",        ["route-table", "route-tables"]),
    ("nic",       ["network-interface"]),
    ("pip",       ["public-ip", "ip-address"]),
    ("vmss",      ["vm-scale-set", "virtual-machine-scale"]),
    ("vm",        ["virtual-machine"]),
    ("aks",       ["kubernetes-service", "kubernetes-services"]),
    ("func",      ["function-app", "function-apps"]),
    ("webapp",    ["app-service", "app-services"]),
    ("plan",      ["app-service-plan"]),
    ("sql",       ["sql-server", "sql-database"]),
    ("storage",   ["storage-account"]),
    ("kv",        ["key-vault"]),
    ("cosmos",    ["cosmos-db", "azure-cosmos"]),
    ("redis",     ["cache-for-redis", "redis"]),
    ("sbus",      ["service-bus"]),
    ("ehub",      ["event-hub"]),
    ("acr",       ["container-registr"]),
    ("tm",        ["traffic-manager"]),
    ("fd",        ["front-door", "cdn-profile"]),
    ("site",      ["on-premises", "server"]),
]

svgs = []
for dirpath, _, files in os.walk(root):
    for f in files:
        if f.lower().endswith(".svg"):
            svgs.append(os.path.join(dirpath, f))
if not svgs:
    sys.exit("no .svg files found under " + root)

def norm(p):
    return re.sub(r"[^a-z0-9]+", "-", os.path.basename(p).lower())

def inner_and_viewbox(path):
    try:
        s = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return None
    m = re.search(r"<svg\b([^>]*)>(.*)</svg>", s, re.S | re.I)
    if not m:
        return None
    attrs, inner = m.group(1), m.group(2)
    vb = re.search(r'viewBox\s*=\s*"([^"]+)"', attrs, re.I)
    vb = vb.group(1) if vb else "0 0 18 18"
    inner = re.sub(r"<\?xml.*?\?>", "", inner, flags=re.S)
    inner = re.sub(r"<!--.*?-->", "", inner, flags=re.S)
    inner = re.sub(r"<title>.*?</title>", "", inner, flags=re.S | re.I)
    inner = re.sub(r"\s+", " ", inner).strip()
    if not inner or len(inner) > 60000:
        return None
    return {"vb": vb, "svg": inner}

manifest, used = {}, {}
for typ, keys in WANT:
    best = None
    for p in svgs:
        n = norm(p)
        for k in keys:
            if k in n:
                score = (len(n), n)          # prefer the shorter, simpler filename
                if best is None or score < best[0]:
                    best = (score, p)
                break
    if best:
        got = inner_and_viewbox(best[1])
        if got:
            manifest[typ] = got
            used[typ] = os.path.basename(best[1])

if not manifest:
    sys.exit("no icons matched. Is this the Azure icon pack?")

os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, separators=(",", ":"))

print(f">> matched {len(manifest)} of {len(WANT)} node types from {len(svgs)} svg files")
for t in sorted(used):
    print(f"     {t:10} <- {used[t]}")
missing = [t for t, _ in WANT if t not in manifest]
if missing:
    print(">> no icon found for: " + ", ".join(missing))
    print("   (the built-in glyph is used for those)")
print(f">> wrote {out} ({os.path.getsize(out)} bytes)")
PY

echo ""
echo "Done. Restart or refresh the map — the Architecture tab will say"
echo "\"official Azure icons loaded\" when it picks them up."
echo ""
echo "Note: manifest.json contains Microsoft's icon artwork. Keep it local;"
echo "do not commit it to a shared repo."
