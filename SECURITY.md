# Security Policy

## Supported versions

| Script | Target Ubuntu | Supported |
|--------|---------------|-----------|
| ubuntu-hardening-26-04.sh | 26.04 LTS | ✅ |
| ubuntu-hardening-24-04.sh | 24.04 LTS | ✅ |
| ubuntu-hardening-original.sh | 18.04 / 20.04 / 22.04 | ✅ (18.04/20.04 require Ubuntu Pro ESM) |
| ubuntu-hardening-25.sh | 25.04 / 25.10 | ⚠️ Target releases are EOL — kept for migration only |

## Reporting a vulnerability

If you find a security issue **in these scripts** (e.g., a change that weakens a
system, a privilege-escalation vector, an injection in generated configs):

1. **Do NOT open a public issue**
2. Use GitHub's [private vulnerability reporting](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/security/advisories/new) on this repository
3. Include: affected script + version, Ubuntu version, reproduction steps, impact
4. Allow reasonable time for a fix before public disclosure

Vulnerabilities in Ubuntu itself should go to the
[Ubuntu security team](https://ubuntu.com/security/disclosure-policy).

## Scope notes

These scripts harden systems but are not a compliance certification, a
substitute for patching, or a guarantee against compromise. Always test in a
non-production environment first and keep backups.
