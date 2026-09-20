# Security Policy

## Authorized use only

PyNetworkIntel actively probes network hosts (`nmap` port/service scanning,
and optionally SSH connections to pull config files). **Only run it against
networks and devices you own or have explicit written permission to test.**
Scanning networks or devices without authorization may be illegal under
computer-crime laws in your jurisdiction (e.g. the US Computer Fraud and
Abuse Act, UK Computer Misuse Act, and equivalents elsewhere), independent
of intent.

The tool enforces a gate on this: `scan`/`analyze` refuse to run without
`--i-am-authorized`, `PYNETWORKINTEL_I_AM_AUTHORIZED=1`, or an interactive
confirmation (see `pynetworkintel/cli.py:confirm_authorization`). This is a
speed bump, not a technical control - it does not verify you actually have
authorization, it only ensures the tool never scans a target silently. You
are responsible for having real authorization before you bypass or answer
yes to that prompt.

Other security-relevant defaults, verified in the current code:
- No default SSH username (`--ssh-user` must be passed explicitly).
- No `--ssh-password` CLI flag (use `--ssh-key` or the
  `PYNETWORKINTEL_SSH_PASSWORD` environment variable) - avoids credentials
  in shell history/`ps` output.
- SSH passwords are never written to the persisted config file.
- Scan targets are validated before reaching the `nmap` command line to
  reject anything that looks like an injected flag.

See [README.md's Security section](README.md#security) for the full,
current list, and `ROADMAP_HONEST.md` for the one known open dependency
advisory (`paramiko`, no fix available yet) affecting the SSH code path.

## Reporting Security Issues

Please do not open public GitHub issues for security vulnerabilities.

Email security concerns to: mullassery@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 24 hours and provide updates on remediation progress.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest | Yes |
| Previous | Limited |
| Older | No |

## Security Best Practices

- Always use the latest version
- Report vulnerabilities privately
- Never share vulnerability details publicly before patch
- Use environment variables for secrets (not hardcoded)
- Keep dependencies updated
- Enable GitHub security features

## Vulnerability Disclosure

When a security issue is confirmed:
1. We develop and test a fix
2. We release a new version with security patch
3. We notify users of the vulnerability and fix
4. We credit the reporter (if desired)

## Contact

Security Team: mullassery@gmail.com
