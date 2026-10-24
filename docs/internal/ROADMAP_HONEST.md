# ROADMAP_HONEST.md

Honest, current status of PyNetworkIntel: what's real, what's broken, what's
fake, and what's genuinely pending. Written during a 2026-09
OSS-standardization pass. No hedge language - if something doesn't work or
doesn't exist, it says so plainly. Every claim below was checked against
the actual code/tests/tooling during this pass, not assumed.

Items are grouped into four buckets: **Fixed in this pass**, **Critical -
needs a dedicated session**, **Real tech debt (documented, not fixed)**,
and **Accepted gaps (not bugs)**.

---

## 1. Fixed in this pass (small, safe, verified)

All of the following were verified by re-running the full test suite
(`pytest tests/ -v`, 168 tests, later 171 after a 2026-09-21 quick-fix pass
added 3 tests) after the change, unless noted otherwise.

- **Version drift bug**: `pynetworkintel/__init__.py`'s `__version__` was
  `"1.3.1"` while `pyproject.toml` said `"1.4.0"` - anyone doing
  `import pynetworkintel; pynetworkintel.__version__` got a wrong answer.
  Root cause: `scripts/update-version.sh` never touched `__init__.py` and
  `scripts/check-version-sync.sh` never checked it either, so nothing
  would have caught this. Fixed both the value and both scripts.
- **Broken `Dockerfile`**: `COPY setup.py requirements.txt /app/` failed
  the build immediately (`setup.py` doesn't exist in this repo anymore).
  Confirmed by actually running `docker build .` and reproducing the
  failure, then fixing it and confirming the build gets past that step
  (the build then hits `apt-get install nmap` failing in this sandbox due
  to no network access to `deb.debian.org` - an environment limitation of
  this pass, not a Dockerfile bug; the Dockerfile itself is now correct).
- **Broken `docker-compose.yml` networking**: defined a custom Docker
  network literally named `host` with `driver: host`, which does **not**
  give the container the real host network namespace (needed for `nmap`
  to see the LAN). Replaced with the standard `network_mode: host`.
  Verified with `docker compose config` (no warnings, correct resolved
  config).
- **`pynetworkintel/db.py`**: deprecated `sqlalchemy.ext.declarative.declarative_base`
  import (SQLAlchemy 2.0 deprecation warning on every import). Switched to
  `sqlalchemy.orm.declarative_base`; warning is gone, tests pass.
- **`pip-audit` findings on dev dependencies**: `black` 24.10.0 and
  `pytest` 8.4.2 (the newest versions the old bounds allowed) had known
  CVEs (PYSEC-2026-2120, PYSEC-2026-2121, PYSEC-2026-1845). Bumped
  `dev` extra lower bounds to `pytest>=9.0.3` / `black>=26.3.1`. Verified
  both install and the full test suite still passes under pytest 9.1.1.
- **67 unused imports + 6 f-strings-without-placeholders** removed via
  `ruff check --fix --select F401,F541` across `pynetworkintel/`. Pure
  mechanical, no behavior change possible; verified with full test suite
  before/after.
- **`examples/dashboard_demo.py`** hardcoded the original author's local
  absolute path (`sys.path.insert(0, '/Users/georgimullassery/...')`),
  which breaks the example on every other machine. Removed; verified the
  script runs without error after the fix.
- **`examples/mcp_pynetworkintel.py`** deleted: it imported
  `PerceptionEngine` from `pynetworkintel`, a class that has never existed
  in this package (confirmed `ImportError`) - unmodified boilerplate from
  an unrelated project. See section 2 below for why it wasn't just fixed.
- **Stray tracked backup file** `tests/__init__.py.bak` removed (`git rm`).
- **`tests/__init__.py`** had a dead, unused, misleading
  `__version__ = "2.0.0"` line before its own docstring (not referenced
  anywhere, docstring wasn't even functioning as a module docstring due to
  the ordering). Cleaned up to just the docstring.
- **`actions/setup-python@v4`** in `.github/workflows/tests.yml` flagged
  by `actionlint` as too old to run on GitHub Actions; bumped to `@v5`.
  Re-ran `actionlint` - clean.
- **CLAUDE.md** had a stale `License: Proprietary` / `v1.3.1` header,
  contradicting the actual Apache-2.0 relicense and 1.4.0 version. Fixed.
- **Discoverability**: `docs/ARCHITECTURE.md`, `docs/PRODUCT_VISION.md`,
  and `docs/ROADMAP.md` were flagged as stale only in README.md - anyone
  browsing `docs/` directly on GitHub would see zero indication they're
  fictional/outdated. Added an in-file banner to each pointing at the real
  docs. `docs/VERSION_MANAGEMENT.md` was rewritten to be accurate (it
  referenced the removed `setup.py` and a README "Status line" that no
  longer exists) rather than just banner-flagged, since it's now tied to
  the corrected version-sync tooling.
- Added `.gitignore` entries for `.ruff_cache/` and `.deepeval/` (found as
  untracked local clutter; removed the empty directories too).
- Added `.github/dependabot.yml` (pip + github-actions, weekly).
- Added a `pip-audit` job to CI (see section 3 for why it's non-blocking).
- Added `.github/ISSUE_TEMPLATE/bug_report.yml`,
  `.github/ISSUE_TEMPLATE/feature_request.yml`,
  `.github/pull_request_template.md`.
- Added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, this file.
- Added authorized-use/legal-scanning guidance to `SECURITY.md` (it
  previously had zero mention of this, despite README already covering it
  extensively for a tool whose entire purpose is scanning other people's
  networks).
- Added a CI badge to README.md linking to the real `.github/workflows/tests.yml`.
- README's "Module status" table previously grouped `cli.py`,
  `dashboard.py`, `scheduler.py`, `alerts.py`, `changes.py`, `reporting.py`
  under "Core, tested" alongside modules at 90-100% coverage. Measured
  actual coverage with `pytest --cov`: these are 10-52%
  (`reporting.py` is 10%). Rewrote the table into honest coverage tiers.
- **`pynetworkintel/architect/recommendation_engine.py:76`** `NameError`
  bug (see section 3 below, formerly listed as documented-not-fixed):
  `generate_roi_analysis` referenced an undefined `monthly_benefit`.
  Defined it as `annual_savings / 12` and fixed the payback guard
  (`monthly_benefit > 0` instead of a redundant `cost_impact / 12 > 0`
  check that could never be false when the first half of the `and` was
  true). Verified with new `tests/test_architect_recommendation_engine.py`
  and a full `pytest tests/ -v` run (171 passed, up from 168 - the 3 new
  tests). `architect/` is still unshipped/untested-in-CI, so this is fixed
  as a landmine-removal, not a claim that the module is now production
  ready.
- **5 `E402` findings in `pynetworkintel/cli.py`**: `AUTH_ENV_VAR` was
  assigned between two import blocks. Moved it below the imports;
  `ruff --select E402 pynetworkintel/` is now clean. Purely mechanical,
  verified with the full test suite.
- **Broken doc link**: `docs/DASHBOARD.md`'s "See Also" section linked to
  `CLI.md`, which does not exist anywhere in the repo (confirmed via
  `find . -iname "CLI*.md"`). Repointed to `README.md`'s real "CLI Usage"
  section.

---

## 2. Critical - needs a dedicated follow-up session

### 2.1 ~~`pynetworkintel.NetworkIntelligence` is a fake stub shipped in the public API~~ - RESOLVED

`pynetworkintel/_mcp_connector.py` and `pynetworkintel/_mcp_tools.py` were
real, shipped files. `NetworkIntelligence` is exported in
`pynetworkintel/__init__.py`'s `__all__`. But every method returned `{}` /
`{"anomalies": []}` / etc., the MCP handler returned **hardcoded fake data
that looked real** (`"src_ip": "192.168.1.100"`, `"anomaly_score": 0.15`,
`"packets": 5240`, regardless of input), and `_mcp_connector.py` imported a
non-existent `statguardian` package (with a local fallback stub) and shelled
out to a `dab` CLI binary that is not a dependency of this project. It was
untested (no `test_mcp*.py`) and undocumented.

Resolved in the 2026-10 pass by implementing it for real against the
SQLAlchemy scan database (option (b) below) rather than deleting it:

- `NetworkIntelligence` is now DB-backed (`db: Database = None` defaults to
  `pynetworkintel.db.get_db()`). Every method computes from scan history
  and/or the derived topology graph:
  - `analyze_network_flow` - real reachability from `TopologyMapper` output.
  - `detect_anomalies` - diffs the two most recent scans of a target via
    `ChangeDetector` (device discovered/removed, CVE discovered/resolved).
    Live-traffic anomaly types (ddos, ...) are reported unavailable, not
    guessed.
  - `threat_correlation` / `get_threat_intelligence` - real CVEs matched per
    indicator (IP/hostname) from scan history.
  - `get_asset_inventory` - real devices/findings from the latest scan.
  - `check_port_exposure` - real observed ports/services.
  - `analyze_dns_records` - system `getaddrinfo` A/AAAA, plus a DGA entropy
    heuristic; empty history is reported honestly (no provider).
  - `get_geolocation_analysis` - RFC 1918 / public / reserved classification
    via `ipaddress` only; explicitly notes no bundled geo database.
  - `behavioral_profiling` - first/last seen, scan count, device types,
    observed ports from scan history.
  - `remediation_recommendations` - from the stored finding's own guidance
    plus severity rules.
  - `network_segmentation_analysis` - real inferred subnets via
    `TopologyMapper`, with an explicit heuristic note.
  - `export_security_report` - real `ReportGenerator` markdown/json output.
- Capabilities with no backing infrastructure raise `NotImplementedError`
  instead of inventing data: `protocol_analysis`, the
  `start_mcp_connector`/`stop_mcp_connector` gateway (the `dab` subprocess
  is gone; tools are meant to be used directly via `PyNetworkIntelMCPHandler`),
  geolocation/country/VPN-lookup, and PDF report output.
- `_mcp_tools.py` handlers delegate to the same `NetworkIntelligence` object
  (the class takes it in its constructor and the handler validates it is an
  instance). `_with_error_result` turns `NotImplementedError` into an
  explicit `not_implemented: true` result. Descriptions no longer claim
  deep-packet-inspection or live threat-intel feeds.
- The `statguardian` import and the `dab` subprocess were removed.
- `scheduler.py` now surfaces these results too: `_detect_changes` returns
  `{"devices": ..., "vulnerabilities": ...}` from the real `ChangeDetector`
  (scoped to the same scan target, excluding the current scan), and
  `_generate_alerts` raises `device_discovered` / `new_vulnerability` alerts
  from actual scan diffs.
- Tested: `tests/test_mcp.py` (18 tests) covers every method, the
  `not_implemented` error surfacing, per-target change-detection scoping,
  and that tool descriptions don't overclaim. Full suite green.
- Still orphaned, unchanged: `pynetworkintel.toml` (MCP tool toggles/port/
  auth) is still not referenced by any Python code - see section 4.
- `examples/mcp_pynetworkintel.py` was deleted in the earlier pass (imported
  a nonexistent `PerceptionEngine`) and remains deleted - the new tests
  exercise the handler directly instead.

**Disposition note**: option (a) "delete the whole layer" from the original
recommendation was considered, but the "no fake stubs" policy is satisfied by
making the layer real against the data this project actually has; anyone doing
`from pynetworkintel import NetworkIntelligence` now gets genuine scan-derived
answers or an explicit `NotImplementedError`, never fabricated results.

### 2.2 Mislabeled/out-of-order git tag `v2.0.0`

The local repo has a tag `v2.0.0` pointing at commit `bb95530`
(2026-07-30, "Add comprehensive v1.0.1 release summary") - a commit that
predates and has far less functionality than `v1.4.0` (`faede69`,
2026-08-30). `git describe --tags` on current `main` correctly resolves to
`v1.4.0-3-g1afcba9` (nearest tag by ancestry), but anyone browsing GitHub's
tag/release list, or running `git checkout v2.0.0` expecting the newest
code, will get something old and broken-looking labeled "2.0.0". Whether
this tag has been pushed to `origin` could not be verified in this pass
(no network access to GitHub's API in this environment) - check
`git ls-remote --tags origin` and, if present, decide whether to delete
it from GitHub (this is a real operational decision - deleting a public
tag can break anything that already references it - so it's flagged
rather than silently done).

### 2.3 ~~`black` formatting not enforced~~ - DONE (2026-10-25)

`black pynetworkintel/` reformatted the 48 non-compliant files in their own
commit (behavior-preserving; full pytest suite still passes). The `lint`
CI job now runs `black --check pynetworkintel/` as a blocking step, and
`ruff check pynetworkintel/` is clean again after modernizing
`pynetworkintel/sarif.py`.

### 2.4 23 bare `except:` clauses

`ruff check pynetworkintel/ --select E722` finds 23 bare-except clauses,
all in the "lighter-tested" modules (already disclosed as such in
README's Module status table, not the well-tested core):

```
7  pynetworkintel/iot/discovery.py
6  pynetworkintel/cloud/credentials.py
3  pynetworkintel/devops/iac_validator.py
2  pynetworkintel/ml/anomaly.py
1  pynetworkintel/kubernetes/network_policy.py
1  pynetworkintel/kubernetes/discovery.py
1  pynetworkintel/enterprise/authentication.py (not shipped)
1  pynetworkintel/cloud/azure.py
1  pynetworkintel/cloud/aws.py
```

Bare `except:` swallows everything including `KeyboardInterrupt` and
`SystemExit`, and hides real bugs. Each needs a judgment call on the
correct specific exception type(s) to catch - not a mechanical fix, hence
deferred rather than done in this pass.

### 2.5 `paramiko` 3.5.1 has an open security advisory with no fix yet

`pip-audit` flags `paramiko` 3.5.1 (the version this repo's
`paramiko>=3.0,<4.0` bound resolves to) for **PYSEC-2026-2858**
("`rsakey.py` allows the SHA-1 algorithm"), with **no fixed version
listed** by the advisory as of this pass. `paramiko` is a core,
security-relevant dependency here (it's the entire SSH config-grabbing
code path, `pynetworkintel/discovery/ssh_config.py`). `paramiko` 4.0.0 and
5.0.0 exist on PyPI and are outside the current upper bound, but the
advisory text ("through 4.0.0 before a448945") doesn't clearly confirm
5.0.0 contains the fix, and a major-version bump (3.x -> 5.x) is a
non-trivial change that needs real testing against this project's SSH
connection/key-handling code before being done casually. Track this
advisory and re-evaluate when the situation changes; don't bump the major
version without dedicated testing.

---

## 3. Real tech debt (documented, not fixed - lower priority than section 2)

- **Test coverage gaps in modules README calls "core"**: measured with
  `pytest --cov=pynetworkintel`, actual line coverage is uneven within
  what used to be a single "Core, tested" bucket:
  - `pynetworkintel/reporting.py`: 10%
  - `pynetworkintel/changes.py`: 17%
  - `pynetworkintel/alerts.py`: 25%
  - `pynetworkintel/cli.py`: 28%
  - `pynetworkintel/scheduler.py`: 30%
  - `pynetworkintel/analysis/llm.py`: 34%
  - `pynetworkintel/core.py`: 48%
  - `pynetworkintel/dashboard.py`: 52%
  Versus `models.py`/`topology.py`/`topology_export.py`/`analysis/cve.py`/
  `db.py`/`config.py` at 83-100%. README's Module status table has been
  corrected to reflect this split (see section 1). Closing these gaps -
  especially `reporting.py` and `changes.py`, which are user-facing output
  paths - is real, warranted follow-up work, but is a multi-file test
  writing effort, not a docs-pass fix.
- **7 unused local variables** (`ruff --select F841`), e.g.
  `pynetworkintel/scheduler.py:179` (`detector = ChangeDetector(self.db)`
  assigned then never used - suggests the change-detection call in
  `_detect_changes` may be incomplete/a no-op; worth checking whether this
  function actually does anything useful), plus similar unused-assignment
  spots in `pynetworkintel/architect/` (excluded module). Left alone in
  this pass: several of these (`scheduler.py:179`,
  `pynetworkintel/config.py:200`'s unused `api_key` walrus assignment)
  look like symptoms of genuinely incomplete features, not dead code that
  can be mechanically deleted - removing the assignment without addressing
  the underlying no-op would just silence the lint warning.
- **5 remaining `F401` unused imports** in conditional/optional-dependency
  `try`/`except ImportError` blocks (e.g. `pynetworkintel/iot/discovery.py`
  importing `paho.mqtt.client` just to probe availability) - these are
  intentional feature-detection patterns, not left as auto-fixed since
  `ruff` itself suggests `importlib.util.find_spec` as the idiomatic
  alternative; a real (if minor) style improvement for a future pass.
- **CI lint/format gates**: `ruff check` and `black --check` are now
  blocking steps in the `lint` job (2026-10-25). A coverage threshold is
  still not enforced.
- **`pip-audit` CI job added but non-blocking** (`|| true` in
  `.github/workflows/tests.yml`): this is a direct consequence of 2.5 -
  gating on `pip-audit`'s exit code would make CI permanently red over an
  advisory with no available fix. Revisit and make it blocking once
  `paramiko`'s advisory is resolved upstream.

---

## 4. Accepted gaps (intentional design choices, not bugs)

- **No numpy/scipy/networkx dependency.** Topology is plain Python
  dicts/`ipaddress`. This is a deliberate design choice for a lightweight
  LAN tool, not a gap - do not "fix" this by adding a graph library.
- **No sparse/out-of-core graph handling.** Consistent with the above -
  this tool is scoped to LAN-sized topologies, not large-graph analytics.
- **`enterprise/` and `architect/` modules exist in the source tree but
  are not shipped** (excluded from `pyproject.toml`'s packages list) -
  this is intentional scope control, already disclosed in README, not a
  packaging bug. (Their code quality is still tracked above where a
  concrete bug was found, in case they're ever revisited.)
- **NVD CVE lookups are a live network call, not offline/bundled data**
  (`pynetworkintel/analysis/cve.py`) - by design, disclosed in CLAUDE.md.
- **`pynetworkintel.toml` at the repo root is unused** - it configures MCP
  tool toggles/port/auth for an MCP gateway this project no longer seeks to
  run (the `dab` subprocess layer was removed). Deleting it is safe but
  deferred to avoid touching anything a consumer might have wired to it.

---

## 5. Validation performed during this pass

- `pytest tests/ -v` - **168 passed**, 0 failed, run both before and after
  every change in this pass.
- `bash scripts/check-version-sync.sh` - now passes (`1.4.0` ==
  `1.4.0` between `pyproject.toml` and `pynetworkintel/__init__.py`).
- `ruff check pynetworkintel/` - went from 109 to 41 findings (68 safe
  auto-fixes applied and verified); remaining 41 documented above.
- **2026-09-21 quick-fix follow-up pass**: fixed the `monthly_benefit`
  `NameError` (section 1) and the 5 `E402` findings in `cli.py`, bringing
  `ruff check pynetworkintel/` down to 40 then 35 findings (23 `E722` + 7
  `F841` + 5 `F401`, all still deliberately deferred per section 2.4/3
  above). `pytest tests/ -v` - **171 passed** (168 + 3 new tests in
  `tests/test_architect_recommendation_engine.py`), 0 failed.
- `black --check --diff pynetworkintel/` - 48/62 files would reformat;
  not applied (see 2.3).
- `pip-audit` - went from 7 findings in 3 packages to 2 findings in 1
  package (`paramiko`, no fix available - see 2.5).
- **2026-10-11 MCP-implementation pass**: implemented `NetworkIntelligence`
  and the MCP tool handlers for real against the scan-history DB and
  `ChangeDetector` (section 2.1), plus `scheduler.py`
  `_detect_changes`/`_generate_alerts` wiring. Added `tests/test_mcp.py`
  (18 tests). `pytest tests/ -v` - **189 passed**, 0 failed. Only
  pre-existing lint findings remain (section 2.3/2.4/3).
- `actionlint .github/workflows/tests.yml` - clean (was 1 finding,
  `setup-python@v4` too old).
- `docker build .` - reproduced the real `COPY setup.py` failure, fixed
  it, confirmed the build gets past that step (further apt-get step fails
  in this sandbox due to no network access to Debian mirrors - an
  environment limitation, not a Dockerfile bug).
- `docker compose config` - clean after the `network_mode: host` fix (was
  producing a custom network that doesn't actually provide host
  networking).
- Manually ran `examples/dashboard_demo.py` and `examples/phase1_2_demo.py`
  end-to-end after fixes; confirmed no crash.
- Grepped for hardcoded credentials/API keys/private keys/`.env` files
  across the tree - none found.
