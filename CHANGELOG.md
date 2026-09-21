# Changelog

All notable changes to this project are documented in this file, in the
style of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Entries below `[Unreleased]` for versions prior to this file's creation
(2026-09) are reconstructed only from git tag dates and their tag commit
messages - they are not a full feature-by-feature history, since no
changelog was kept at the time. Nothing here is fabricated beyond what the
git history itself verifies.

## [Unreleased]

### Fixed
- `pynetworkintel/architect/recommendation_engine.py:76`: `generate_roi_analysis`
  referenced an undefined `monthly_benefit` variable, which would raise
  `NameError` on any call where `cost_impact > 0` (flagged by
  `ruff --select F821` and documented in `ROADMAP_HONEST.md`). Defined
  `monthly_benefit = annual_savings / 12` before use and fixed the payback
  guard to check `monthly_benefit > 0` instead of a redundant
  `cost_impact / 12 > 0` check. Verified with a new
  `tests/test_architect_recommendation_engine.py` (3 tests covering
  positive-cost, negative-cost/savings, and zero-cost paths) plus a manual
  run confirming no crash.
- `pynetworkintel/cli.py`: 5 `E402` findings (imports placed after the
  `AUTH_ENV_VAR` module-level constant). Moved the constant below the
  import block; no behavior change, `ruff --select E402` now clean.
- `docs/DASHBOARD.md`: "See Also" section linked to a `CLI.md` file that
  does not exist anywhere in the repo. Pointed it at `README.md`'s real
  "CLI Usage" section instead.
- `pynetworkintel/__init__.py` `__version__` had drifted to `1.3.1` while
  `pyproject.toml` had moved on to `1.4.0`; corrected to `1.4.0` and
  `scripts/check-version-sync.sh` now checks both files so this can't
  silently recur.
- `Dockerfile` was broken: it tried to `COPY setup.py ...`, a file that no
  longer exists in this repo, which failed the build immediately. Now
  copies `pyproject.toml`/`README.md`/`LICENSE` and installs via
  `pip install .`.
- `docker-compose.yml` defined a custom Docker network named `host` with
  `driver: host`, which does not give the container the actual host
  network view (needed for `nmap` to see the LAN being scanned). Replaced
  with the standard `network_mode: host`.
- `scripts/update-version.sh` never updated `pynetworkintel/__init__.py`
  and had a dead `sed` command targeting a README.md "Status" line that no
  longer exists (silent no-op). This was the root cause of the
  `__version__` drift above; fixed to update `__init__.py` and the dead
  sed removed.
- `pynetworkintel/db.py` used the deprecated
  `sqlalchemy.ext.declarative.declarative_base` import (SQLAlchemy 2.0
  deprecation warning on every import); switched to
  `sqlalchemy.orm.declarative_base`.
- Removed 68 unused imports / f-strings-without-placeholders across
  `pynetworkintel/` (`ruff check --fix --select F401,F541`), verified with
  the full test suite before and after.
- `.github/workflows/tests.yml` used `actions/setup-python@v4`
  (`actionlint`-flagged as too old); bumped to `@v5`.
- Bumped `dev` extra lower bounds for `pytest` (>=9.0.3) and `black`
  (>=26.3.1) to versions that fix known CVEs (PYSEC-2026-1845,
  PYSEC-2026-2120, PYSEC-2026-2121) flagged by `pip-audit`; the previous
  bounds (`pytest<9.0`, `black<25.0`) made it impossible to install a
  patched version.
- `examples/dashboard_demo.py` hardcoded the original author's local
  absolute path (`sys.path.insert(0, '/Users/georgimullassery/...')`),
  breaking the example for every other clone of the repo. Removed; the
  package works correctly when installed normally. Verified by running the
  script end-to-end after the fix (previously it raised `NameError`/relied
  on a path that doesn't exist on other machines).
- Removed `examples/mcp_pynetworkintel.py`: it imported
  `PerceptionEngine` from `pynetworkintel`, a class that has never existed
  in this package (confirmed: `ImportError` on import) - unmodified
  boilerplate copied from an unrelated project (its own comment said
  "Adjust import based on project" and was never adjusted). Even fixed to
  import the real `NetworkIntelligence` class instead, it would still not
  do anything real - see the fake-stub finding above.

### Added
- `.github/dependabot.yml` (pip + github-actions ecosystems, weekly).
- `pip-audit` CI job in `.github/workflows/tests.yml` (advisory/non-blocking
  for now - see that file and `ROADMAP_HONEST.md` for why).
- `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`,
  `.github/pull_request_template.md`.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `ROADMAP_HONEST.md`, this file.
- Stale-doc banners at the top of `docs/ARCHITECTURE.md`,
  `docs/PRODUCT_VISION.md`, and `docs/ROADMAP.md` pointing to the real
  current docs, since the disclosure previously existed only in
  `README.md` and not in the files themselves.
- CI badge in `README.md` linking to the real `tests.yml` workflow.

### Documented (no code change)
- `pynetworkintel.NetworkIntelligence` (`_mcp_connector.py`/`_mcp_tools.py`)
  is a shipped-but-fake stub returning hardcoded data, not real analysis -
  flagged in `README.md`, `CLAUDE.md`, and `ROADMAP_HONEST.md`.
- Local git tag `v2.0.0` points at a commit older and less complete than
  `v1.4.0` (mislabeled/out-of-order tag) - flagged in `ROADMAP_HONEST.md`.
- `paramiko` 3.5.1 has an open advisory (PYSEC-2026-2858) with no fixed
  release available yet.

## [1.4.0] - 2026-08-30
D3/vis.js node-link JSON and GraphML topology export formats added
(`pynetworkintel/topology_export.py`), wired into the CLI `--output` flag.

## [1.2.0] - 2026-08-06
Full public API exported from `pynetworkintel/__init__.py` (`Pipeline`,
`AlertManager`, `Dashboard`, `Config` classes, etc.).

## [1.0.1] - 2026-07-30
CLI stats dashboard added; emoji/icon cleanup in output.

## [1.0.0] - 2026-07-28
First tagged release.

## Not listed here
A `v2.0.0` git tag exists but points at a commit from 2026-07-30 - older
than `v1.0.1` and much older than `v1.4.0` - and does not represent a real
2.0 release; see `ROADMAP_HONEST.md`. It is intentionally omitted from this
changelog as a version entry.
