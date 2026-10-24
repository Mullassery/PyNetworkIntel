# Competitive intelligence in roadmap and upgrade work

**Policy date:** 2026-10-19

Competitive findings are an input to product decisions, not a one-off report.
Every pending roadmap item, new feature, and routine dependency upgrade should
check the repository's [`AUDIT_FINDINGS.md`](AUDIT_FINDINGS.md) before work
starts, and record the decision in the PR or changelog.

## Required check before building

1. **Read `AUDIT_FINDINGS.md`.** Find the relevant competitor row and the
   ranked next actions. If the finding is stale, update it with a dated source.
2. **Name the competitor and the user problem.** A feature is not justified by
   "competitor has it". State the workflow it unlocks, who needs it, and how
   often. Mark unverified demand as a hypothesis.
3. **Prefer reuse over new code.** Check whether an existing Mullassery repo
   already provides the capability (see `BUNDLES.md` in the profile repo and
   the bundle role file in this repo, when present). Typical reuse:
   - crawling/fetching/robots/SSRF → **MudFish**
   - architecture maps / PR diffs → **CodeAtlas**
   - data-quality contracts / validation → **StatGuardian**
   - token counting / cost tables → **PyTokenCalc**
   - dependency graph / advisories / SBOM → **PyDeepMesh**
   - segmentation / CLV / churn → **ClusterAudienceKit**
   - activation / lineage / PII → **PyReverseETL**
   - fleet state sync → **SyncFleet** (only after conflict resolution)
4. **Choose one disposition:** build, integrate, defer, or reject. Write it
   down. A rejection with a reason is a successful outcome.
5. **For routine upgrades**, check whether the upgrade closes a known
   competitor gap or breaks a differentiated capability. Run the tests that
   cover the affected path; do not merge a green build that silently changes a
   user-visible contract.

## PR / changelog checklist

- [ ] Competitor and source URL/date recorded (or "no direct competitor").
- [ ] User impact and frequency stated; unverified demand labelled.
- [ ] Reuse check done against sibling repos/bundles.
- [ ] Failure mode and rollback considered (especially auth, PII, cost).
- [ ] Docs/roadmap status updated honestly.
- [ ] Tests or a manual verification command included.

## Review cadence

- Refresh the competitor row when a release changes the capability.
- Re-check the full `AUDIT_FINDINGS.md` at least quarterly and before a major
  release.
- If a finding is wrong or stale, correct it in the same PR that relies on it.

## Non-goals

- Copying features for parity.
- Adding a dependency just because a competitor uses it.
- Treating star counts or download counts as proof of user need.

## OSS gap analysis — 2026-10-24

**What matters most here:** fast discovery and evidence-backed vulnerabilities. One nmap subprocess per scan does not scale to large ranges, and keyword CVE matches produce false positives; integrate RustScan/Naabu and Nuclei evidence.

Scope: PyNetworkIntel assessed against four maintained network-scanning tools on discovery speed, service/version detection, script/template coverage, CVE triage, topology fidelity, change tracking, inventory export, and scan safety. It is a wrapper around Nmap, so Nmap is both dependency and comparator.

### Comparable OSS projects

| Project | GitHub | License | Last activity | Why it is the comparison |
| --- | --- | --- | --- | --- |
| Nmap | https://github.com/nmap/nmap | NPSL (GPLv2-based) | active mirror, pushed 2026-10-24; no GitHub releases | The engine PyNetworkIntel calls; NSE, OS detection, and service/version scanning set the discovery baseline. |
| RustScan | https://github.com/bee-san/RustScan | GPL-3.0 | v2.4.1, 2025-02-23; pushed 2026-10-20 | Fast port discovery with adaptive batching and Nmap handoff; the speed alternative for large ranges. |
| Naabu | https://github.com/projectdiscovery/naabu | MIT | v2.6.1, 2026-05-05 | Fast Go port scanner with passive Shodan ports and now native service-version probes; closest modern scanner. |
| Nuclei | https://github.com/projectdiscovery/nuclei | MIT | v3.11.1, 2026-08-08 | Template-based vulnerability verification with SARIF/JSONL and network/HTTP/DNS/cloud protocols; the proof layer we lack. |

### Capability comparison

| Capability | Ours | Nmap | RustScan | Naabu | Nuclei | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| Host/port discovery | Yes | Yes | Yes | Yes | No | None |
| Service/version detection | Yes | Yes | Partial | Yes | No | None |
| Large-range scan speed | Partial | Partial | Yes | Yes | Partial | Large |
| Script/template vulnerability checks | Partial | Yes | No | No | Yes | Large |
| CVE-by-version triage | Yes | No | No | No | Partial | Ahead |
| CPE-accurate version matching | Partial | No | No | No | No | Medium |
| Topology graph | Partial | No | No | No | No | Ahead |
| Change tracking/history | Yes | No | No | No | No | Ahead |
| Asset inventory export | Yes | Partial | No | Partial | Partial | Ahead |
| SARIF/CI output | Yes | No | No | No | Yes | None |
| Offline operation | Partial | Yes | Yes | Partial | Partial | Medium |
| Authorization/scope guard | Partial | No | No | No | No | Ahead |
| Reports and alerts | Yes | Partial | No | No | Partial | Ahead |
| Non-HTTP/OT protocol coverage | Partial | Yes | No | Partial | Partial | Medium |

Nuance: our discovery is `nmap -sV --script=smb-os-discovery` via subprocess; we add no native packet engine and do not expose Nmap timing/rate controls. Naabu now performs native service-version probes, narrowing our `-sV` advantage. Our topology groups hosts into inferred subnets from IP addressing and draws gateway-style edges heuristically; there is no traceroute, LLDP, SNMP, or ARP-based L2 discovery. Our CVE matching is service-name/version keyword search against the live NVD API with a 24-hour disk cache, not CPE-based matching, and has no EPSS/KEV prioritization. The Nuclei adapter covers HTTP(S) services only. Nmap's license is the Nmap Public Source License, which is GPLv2-based but not OSI-approved; RustScan is GPL-3.0, so neither can be vendored into this Apache-2.0 package.

### Gaps that matter (ranked)

1. **No fast-scan path for large ranges** — every scan is a single `nmap -sV` subprocess. RustScan and Naabu offer asynchronous/adaptive discovery, rate controls, CDN exclusion, and passive Shodan ports, so a /16 or internet-facing estate is minutes versus hours. Building it is L; integrating Naabu or RustScan output is S/M and preserves the existing pipeline.
2. **Vulnerability claims are weakly verified** — config rules are fixed patterns and CVE hits come from service-name/version keyword matching, which is prone to false positives. Nuclei proves template-detectable issues with request/response evidence, and Nmap NSE covers protocol checks; our Nuclei adapter is optional and HTTP(S)-only. M effort to add full-protocol templates and evidence capture.
3. **Topology is heuristic, not observed** — inferred subnets and gateway edges cannot answer "what path connects A to B" or "which switch port". SNMP/LLDP/ARP/traceroute enrichment would make the graph defensible; arp-scan covers L2, Nmap covers route tracing. M effort.
4. **CVE prioritization and accuracy are missing** — no CPE matching, no EPSS, no CISA KEV, no vendor advisory mapping. A list of NVD matches without exploitability context is noisy for triage; competitors are also weak here, so this is an opportunity rather than catch-up. M effort.
5. **Non-HTTP/IoT/OT coverage is thin** — the IoT module is lighter-tested, and Nuclei verification stops at HTTP(S). Nmap NSE and Nuclei network templates reach further. M/L effort if OT/ICS is a target segment; otherwise document the boundary.

### Where we are differentiated

- Asset lifecycle in one tool: discovery plus topology, CVE triage, scan-to-scan change history, reports, and alerts, where Nmap/RustScan/Naabu/Nuclei return raw results.
- A persistent CVE cache with explicit offline mode and no hidden calls beyond Nmap, SSH, NVD, and opt-in Anthropic.
- SARIF output plus NetBox CSV, GraphML, and d3-json exports, making results consumable by code scanning, source-of-truth, and visualization tools.
- Safety defaults competitors do not have: mandatory authorization acknowledgement, no default SSH user, no password CLI flag, validated scan targets before argv construction.

### Disposition

- **Build:** CPE-aware NVD matching with EPSS/KEV, topology enrichment (SNMP/LLDP/ARP/traceroute), scope allowlists and rate/timing profiles, and full-protocol Nuclei verification.
- **Integrate/reuse:** use Nmap for service/version/NSE, Naabu or RustScan for fast discovery, Nuclei for proof, arp-scan for L2, and NetBox as the inventory source of truth. Keep the current pipeline as the normalization layer.
- **Defer/reject:** a native scanner, enterprise auth/HA/multitenancy, DAST, and a native template engine. Document OT/ICS as out of scope until a validated user need exists.

### Sources

- https://github.com/nmap/nmap and https://nmap.org/book/man-legal.html (accessed 2026-10-24)
- https://github.com/bee-san/RustScan (formerly RustScan/RustScan; accessed 2026-10-24)
- https://github.com/projectdiscovery/naabu (accessed 2026-10-24)
- https://github.com/projectdiscovery/nuclei (accessed 2026-10-24)
- Repo files inspected: `README.md`, `COMPETITIVE_INTELLIGENCE.md`, `AUDIT_FINDINGS.md`, `CHANGELOG.md`, `ROADMAP_HONEST.md`, `CLAUDE.md`, `pyproject.toml`, `pynetworkintel/discovery/scanner.py`, `pynetworkintel/topology.py`, `pynetworkintel/analysis/cve.py`, `pynetworkintel/discovery/nuclei.py`
