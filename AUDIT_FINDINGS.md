# Audit findings — 2026-10-19

This file records the repository-specific findings from the portfolio audit
conducted on 2026-10-19. It is documentation only; no code or release artifacts
were changed in this pass unless explicitly noted under "Implementation status".

Sources: the repository's own README/source/workflows, GitHub metadata and
Actions runs, PyPI metadata, and official competitor documentation. Claims are
marked as verified, inferred, or open questions. "Absent" means not found in the
inspected repository/docs, not proof that it cannot exist.

## What it is

LAN discovery, topology mapping, CVE triage, change tracking, and reporting around `nmap`.

## Verified strengths

- Real `nmap -sV`; topology graph/GraphML/d3; live NVD; SSH config grabs; change tracking; reports/alerts; cloud/K8s/IoT/ML/DevOps extensions; 17 test files; authorization warning.
- Topology + change tracking + alerts add real value over raw nmap.

## Verified gaps and user-facing risks

- It is an nmap wrapper; live NVD dependency; thin coverage in reporting/dashboard; no auth/HA/enterprise; no benchmark.
- No SARIF; active scanning safety depends entirely on the user.

## Direct competitors

- nmap, RustScan, OpenVAS/Nessus, NetBox.

## Ranked next actions

- P1: authorization guard/safe defaults + SARIF (S).
- P2: offline NVD cache (S).

## Do not build

- A native scanner; nmap is better and free.

## Evidence gaps / validation needed

- No real network validation; no false-positive analysis.

## Recommended disposition

Maintain as a convenience layer; do not compete with nmap.

## Implementation status

Added a persistent NVD cache and explicit offline mode in this pass:

- Cache file `~/.pynetworkintel/cve_cache.json` (override
  `PYNETWORKINTEL_CVE_CACHE`), TTL `PYNETWORKINTEL_CVE_CACHE_TTL` (default 24h).
- `PYNETWORKINTEL_OFFLINE=1` / `CVEChecker(offline=True)` forbids network calls;
  uncached services are skipped with a warning.
- `tests/test_cve.py`: 17 passed (including disk-cache round trip and offline
  no-network cases). Version `1.6.0`.

Also added SARIF 2.1.0 output (`-o sarif`) for findings, with tests. Still
open: cache warming/pre-seeding, and the live Anthropic summary remains
network-only.
