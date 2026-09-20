# Contributing to PyNetworkIntel

This is a solo-maintained, lightweight LAN-scan/topology tool. Contributions
are welcome; expectations are kept deliberately simple.

## Before you scan anything

If your contribution involves running the scanner against real hosts (for
testing, reproducing a bug, etc.), only do so against networks/devices you
own or have explicit written permission to test. Do not include real IPs,
hostnames, or scan output from third-party networks in issues, PRs, or
commit messages. See [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/Mullassery/PyNetworkIntel.git
cd PyNetworkIntel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

`nmap` must also be installed and on `PATH` for anything that does live
scanning; most of the test suite mocks `nmap`/SSH/network calls so it
doesn't require this, but a few integration-style tests exercise the real
subprocess/XML parsing path.

## Running tests, lint, and format checks

```bash
pytest tests/ -v          # test suite (168 tests as of this writing)
ruff check pynetworkintel/ # lint
black --check pynetworkintel/  # formatting (see ROADMAP_HONEST.md - not
                                # currently enforced in CI, so don't be
                                # surprised if `main` isn't fully compliant)
```

All 168 tests must pass before a PR is merged. `ruff`/`black` are
configured in `pyproject.toml` but not currently gated in CI - see
`ROADMAP_HONEST.md` for that gap. Please don't introduce *new* lint errors
even though old ones aren't blocked yet.

## Scope boundaries

Please read the README's "Use cases" and "Module status" sections before
proposing a feature. In particular, out of scope for this project:

- Enterprise platform features (multitenancy, HA, auth, a REST API) -
  `pynetworkintel/enterprise/` exists in the source tree but is explicitly
  excluded from the package and not maintained.
- A conversational architecture advisor - same story,
  `pynetworkintel/architect/`.
- Anything that would pull in `numpy`/`scipy`/`networkx` or similar for
  the core discovery/topology path - staying dependency-light for a LAN
  tool is an intentional design choice, not an oversight.

## Module status matters

Before touching `pynetworkintel/cloud/`, `kubernetes/`, `iot/`, `ml/`, or
`devops/`, know that these are real, shipped, but "lighter-tested" per the
README's Module status table - if you fix a bug there, please also add a
test, since coverage is genuinely thin.

## Submitting a change

1. Fork, branch, make your change.
2. Add/update tests - PRs that change behavior without a test won't be
   merged.
3. Run the test suite and lint locally (see above).
4. Update `README.md`/`CLAUDE.md`/`CHANGELOG.md` if behavior, status, or
   scope changed. Be as blunt about limitations as the existing docs are -
   this project's docs intentionally avoid marketing language.
5. Open a PR using the provided template.

## Reporting bugs / security issues

- Bugs: open a GitHub issue using the bug report template.
- Security vulnerabilities: see [SECURITY.md](SECURITY.md) - do not open a
  public issue.
