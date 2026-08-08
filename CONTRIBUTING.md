# Contributing

Contributions of every size are welcome — bug reports, fixes, new features,
docs, and testing on different Ubuntu versions all help.

## Quick start

1. Fork and clone the repo
2. Create a branch: `git checkout -b feature/your-feature` or `fix/issue-description`
3. Make your changes
4. Validate: `bash -n script.sh` (and `shellcheck script.sh` if available)
5. Test in a **VM or container** — never on your workstation
6. Open a Pull Request explaining what and why

## What we need most

- **Testing** on different Ubuntu versions and environments (VMs, cloud, bare metal)
- **Bug fixes** — see [open issues](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/issues)
- **New controls** — CIS benchmark coverage, container security, cloud-specific hardening
- **Docs** — examples, tutorials, translations

Look for issues labeled `good first issue` or `help wanted`.

## Code standards

- Bash with `set -euo pipefail`; follow the existing style
- Package installs are best-effort (warn, don't abort); guard service restarts so
  a missing package can't kill the run
- Interactive prompts need non-interactive fallbacks (`[[ -t 0 ]]`) with safe defaults
- Always back up files before modifying them (use the `backup_file` helper)
- Never introduce a change that can lock a user out of SSH without a safety check

## Testing checklist

- [ ] `bash -n` passes
- [ ] Fresh Ubuntu VM of the target version
- [ ] Script runs start to finish
- [ ] All services start; no errors in the log
- [ ] SSH access still works after hardening

## Commit messages

```
Type: Brief description (50 chars or less)

What and why, wrapped at 72 characters.

Fixes: #issue-number
```

Types: `Fix:` `Add:` `Update:` `Docs:` `Test:` `Refactor:`

## Getting help

- [Discussions](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/discussions) for questions
- [Issues](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/issues) for bugs and features
- For major changes, open an issue first to discuss

All contributors are credited in the README (auto-updated weekly).
