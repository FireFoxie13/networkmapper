# Azure Network Mapper — handoff

Single-file D3 app (`azure-net-map.html`) that renders an Azure network topology plus
flow logs, firewall logs, NSG / AVNM / firewall rules, and route tables. It is a
**template**: `generate-netmap.sh` scans Azure with the `az` CLI + Resource Graph,
then substitutes the scan payload into the template at the marker

```
const EMBEDDED=null;//__NETMAP_EMBED__
```

producing a dated, self-contained map under `./maps/`. A Docker container serves it.
Nothing in the tool ever writes to Azure. Everything is read-only, Reader-level.

Owner: Alexa Skaggs, Cloud Network Engineering Manager, Dayforce (GUSA FedRAMP).
Environment: 22 subscriptions under management group `4cc0f888-f4fe-43e6-bb80-fa8df5fba315`.

---

## Repo layout (what she runs)

| File | Purpose |
|---|---|
| `azure-net-map.html` | the template. **The only file changed in this work.** |
| `generate-netmap.sh` | Azure scan (Resource Graph + Log Analytics KQL) → embeds payload |
| `Dockerfile`, `entrypoint.sh` | container: login, scan, serve on :8080, optional rescan loop |
| `docker-compose.yml` | **do not overwrite.** Holds two `WORKSPACE_ID` GUIDs |
| `verify.sh` | read-only permissions / coverage / ground-truth checks |
| `make-icon-pack.sh` | optional: real Azure icons |

Deploy = replace `azure-net-map.html`, then `docker compose up -d --build`.

---

## How this work is structured (important)

**Do not hand-edit `azure-net-map.html`.** All changes live in `apply_patches.py`
as 114 assertion-guarded patches against the pristine original.

```bash
cp azure-net-map.PRISTINE.html azure-net-map.html
python3 apply_patches.py          # 114 patches; any miss aborts loudly
```

Each patch asserts its target string occurs an exact number of times before
replacing. A miss prints the patch name and the expected string, then exits 1.
This is deliberate: it makes the change set reviewable and replayable, and it
makes silent no-ops impossible.

Provenance (verify before trusting anything):

```
azure-net-map.PRISTINE.html   md5 1e8b808e621403fdb105281f19c46aea   235,005 bytes
azure-net-map.html (rebuilt)  md5 e20acc1551a523c4c77d58a566cdd85c   291,814 bytes
```

The rebuild is deterministic. No original function was removed.

---

## Test harness

Playwright + Chromium, headless, against synthetic scans built through the real
embed marker. Requires `pip install playwright && python3 -m playwright install chromium`.
Note: the browser context needs `ignore_https_errors=True` if your egress proxy
re-signs TLS (D3 loads from cdnjs).

```bash
python3 build_scan.py        # GUSA-shaped scan: AVNM deny, 2 subs, 2 VNets
python3 build_fix_scan.py    # + real NSG rules, AVNM rule collection, route table,
                             #   firewall policy w/ rule collection group, subnet NSG, LB
python3 build_fwlog_scan.py  # firewall policy with NO rule collections (as Resource
                             #   Graph actually returns it) + firewall logs only
python3 run_tests.py         # 47 assertions: layout, deps, clusters, search, window
python3 run_fix_tests.py     # 57 assertions: remediation engine, rules tab, effective
                             #   rules, intent classifier, load balancer, layout metric
python3 run_stress.py        #  5 assertions: 12x14 deps rows, no label overlap/clip
```

All 109 pass on the current build. Console errors are treated as failures, with
`icons/manifest.json` and `favicon.ico` 404s whitelisted (optional resources).

`hairball-old.html` / `hairball-new.html` are a 63-node dense mesh used to measure
label collisions before/after the layout change (225 → 108 at default, → 25 on
"Untangle").

---

## What changed, grouped

**Dependencies view.** Labels were anchored 68% toward the centre on the right
side (bug), so destination labels piled up. Now pinned per-row beside their own
node, with white halos. The "blocked at" string moved to a reserved bottom band.
`depNeighbors` never copied `blockLayer` off the edge, so every deny printed
"blocked at ?" — fixed.

**Clusters.** Double-click a cluster isolates it (hides everything else) and
double-click a member restores the previous filter state. Inspect zooms. Toolbar
Expand/Collapse unchanged.

**Layout.** Repulsion and edge length now scale with node degree; repulsion is
range-capped; collision radius accounts for label width. Two new spread levels.

**Search.** Filters used to stack across searches, and a scope search never left
the deps view — both broke back-and-forth searching. Now each search resets state.
Resource types are searchable, including shorthand (`nic`, `vnet`, `nsg`, `lb`).
`initWindow()` ran before `rebuildData()`, so the time-window control always
concluded "no flow logs" and disabled itself permanently — fixed.

**Remediation engine** (`remediationFor(row)`). For each denied flow, produces a
copyable `az` command targeting the layer that actually decided, honouring Azure's
evaluation order:

- AVNM Deny is evaluated before every NSG → refuses to suggest an NSG fix, emits
  `security-admin-config rule-collection rule create` + `post-commit`, computes a
  free priority ahead of the deny, explains Allow vs AlwaysAllow.
- NSG → `nsg rule create` at a free priority below the deny, scoped to the observed
  port/proto/source-subnet. **If the deny shadows allow rules on the same NSG, it
  recommends renumbering instead** — the ordering bug is the disease.
- Azure Firewall → three distinct paths: network rule (`add-filter-collection` at a
  computed collection priority), application rule (targets the FQDN from the
  firewall log, not the flow-log IP), threat intel / IDPS (no allow rule exists;
  allowlist one address, never downgrade the mode).
- Route drop → names the actual route, offers delete or reroute-to-firewall, and
  states that this tool reads UDRs, not the *effective* route table.

Every box is marked a proposal, escaped at render, and points at
`az network watcher test-ip-flow` for verification. Nothing executes.

**Rule analysis.**
- ASG-scoped rules had no address prefixes, so they parsed as `*` and the shadow
  test could never fire. An ASG's members live behind the NSG, so for an inbound
  rule the effective destination is the NSG's attached subnet prefixes. With that
  substitution the tool found **50 rules across her estate that can never take
  effect**, including 20 on the two domain-controller NSGs.
- Azure Firewall policy rules get zero hits from flow logs (firewall decisions live
  in `AZFWNetworkRule` / `AZFWApplicationRule`). Resource Graph also returned **zero
  rule collection groups** for her policies. So firewall rules are now rebuilt from
  the firewall's own logs, marked `observed`, and excluded from shadow analysis
  (no authored priority ⇒ coverage cannot be proven).
- Flow logs name the rule that **denied** a flow, never the one that allowed it. So
  an AVNM allow rule can never be credited. It now reads "Not attributable" rather
  than "No traffic seen", and is excluded from the unused-rule findings. Previously
  the Analysis tab was advising deletion of `IN-ALLOW-ADDS-DC-TO-DC-SYNC-TCP`.
- Route entries with next hop `None` are credited with the traffic they silently
  dropped.
- Rules tab and effective-rules panel both expand to show timestamped traffic, and
  a port-intent classifier labels it infrastructure / management / noise / lateral /
  application with guidance, never a verdict.

**Load balancer / app gateway.** Panel section: pools, members, probes, each backend
named with flow counts, warnings for empty pool, missing probe, and a pool where no
member carried a single flow.

---

## Findings in her live environment (not code bugs — real config)

1. **Both DC NSGs have a deny at priority 980/981 that shadows ~20 allow rules**
   (member prefixes, Bastion RDP, AVD, Delinea RDP, DNS clients, DC-to-DC sync).
   Flow logs confirm: to `azh1dfgus1dc07/08`, **0 allowed / 219 denied on 389,
   0 / 107 on 123, 0 / 14 on 88**. Those DCs serve nothing to domain members.
   AVNM has `OUT-ALLOW-DOMAINJOINED-SPOKES-TO-ADDS-*` (#120/#125, AlwaysAllow) but
   **no inbound counterpart**, so the DC's NSG still decides — and denies.
   Fix is a renumber, but it turns on twenty dormant rules at once. Change-controlled.
2. **Firewall `Deny-Outbound` logged 50,852,583 hits in 24 h**, 49.9 M of them
   port 9092/TCP (plaintext Kafka) from four hosts: `azg5padbje001/002`,
   `azg5admbje003/004`. ~578 attempts/second. Something behind the firewall is
   misconfigured for 9092 instead of TLS 9093.
3. **PRTG SNMP is denied** — rules #215/#218 allow port 161 over **TCP**; SNMP is UDP.
4. **89% of traffic bytes never reach the map.** 14,583 of 40,000 flow rows have an
   empty `DestIp` (every `AzurePublic` / `ExternalPublic` row, 1.56 TB of 1.75 TB).
   The mapper drops rows without a valid IP pair. Denies are unaffected (19 of 3,373).
   **This is a KQL fix in `generate-netmap.sh`, not the HTML — outstanding.**
5. `METRICS: "1"` is commented out in docker-compose.yml, so probe availability,
   SNAT exhaustion, unhealthy-host counts and firewall health never run. Needs
   Monitoring Reader. This is the largest remaining gap in troubleshooting coverage
   and no HTML change fixes it.

---

## Outstanding work

- [ ] **KQL fix** so public/external flows keep their destination (finding 4 above).
      Highest value: it recovers the top-talkers view.
- [ ] Enable `METRICS: "1"` and verify the metric-driven checks light up.
- [ ] Search suggestion dropdown is a native `<datalist>`. A custom menu grouped by
      kind (resource / subscription / RG / VNet / type) with keyboard navigation
      would be better.
- [ ] Effective-rules panel caps at 12 rules per layer. Fine for NSGs, thin for AVNM.
- [ ] Load time is ~36 s on her 51 MB scan (3,467 nodes, 40 k flows). Parsing and
      layout are client-side. Worth profiling before adding features.
- [ ] Rules rebuilt from firewall logs cannot be shadow-analysed. If Resource Graph
      can be made to return `firewallPolicies/ruleCollectionGroups`, that gap closes.

---

## Ground rules that were followed

- Never overwrite `docker-compose.yml`; the two `WORKSPACE_ID` GUIDs are load-bearing.
- Never delete a feature to fix another.
- Assertion-guarded patches, exact occurrence counts, fail loudly.
- Test against real-shape scan data, not toy fixtures.
- The tool proposes; it never writes to Azure.
- Where the tool cannot know something (effective routes, BGP, whether an AVNM allow
  saw traffic), say so rather than guess.

## A note on workspace hygiene

Twice during this work, patches appeared in `apply_patches.py` that were not authored
in-session, and files appeared in an unrelated working directory. They were reviewed
line-by-line, scanned for network calls / eval / storage access (none found), tested,
and kept because they were correct. If more than one agent session is ever pointed at
these files simultaneously, expect collisions. The checksum chain above is the way to
verify what you actually have.
