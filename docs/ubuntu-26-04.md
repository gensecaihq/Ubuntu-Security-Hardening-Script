# Ubuntu 26.04 LTS Notes

Ubuntu 26.04 LTS "Resolute Raccoon" (released 23 April 2026, supported until
April 2031; ESM to 2036 with Ubuntu Pro) is the biggest security shift in years.
`ubuntu-hardening-26-04.sh` (v5.0) is built for it.

## What changed in 26.04 (security view)

| Area | 26.04 | Impact on hardening |
|------|-------|---------------------|
| Kernel | Linux 7.0 | Attack Vector Controls, BPF tokens, stack erasing by default, ML-DSA module signing |
| OpenSSL | 3.5 | Post-quantum ML-KEM/ML-DSA/SLH-DSA; default TLS 1.3 kex is hybrid X25519MLKEM768; security level raised to 2 |
| OpenSSH | 10.2 | Default kex `mlkem768x25519-sha256`; **DSA removed**; sshd split into `sshd`/`sshd-auth`/`sshd-session` |
| sudo | sudo-rs 0.2.13 | Memory-safe default; classic sudo available as `sudo.ws`; `sudo-ldap` removed |
| coreutils | uutils (Rust) | ~80 utilities; `cp`/`mv`/`rm` remain GNU (TOCTOU); GNU versions via `gnu` prefix |
| AppArmor | 5.0 | userns, io_uring, mqueue mediation; SHA-256 policy hashes |
| auditd | 4.1 | Split `auditd.service` + `audit-rules.service`; new `audisp-filter` |
| systemd | 259 | cgroup v1 fully removed; iptables backend removed (nftables only); SysV init deprecated |
| Time sync | Chrony 4.8 + NTS | NTS on by default (replaces systemd-timesyncd) |
| Disk encryption | TPM-backed FDE **GA** | First-class installer option, PCR-sealed keys |
| apt | 3.2 | Sequoia (Rust) crypto, `apt history-undo` / `history-rollback` |

## What the v5.0 script does about it

- SSH crypto list leads with `mlkem768x25519-sha256` (hybrid post-quantum),
  keeps sntrup761 + classical ECDH for older clients
- Removed sshd directives that OpenSSH 10.x rejects or deprecates
  (`Protocol`, `ChallengeResponseAuthentication`); added `PerSourcePenalties`
- fail2ban journal matching updated for the split sshd binaries
- Enables both auditd 4.1 units; removed the obsolete `dispatcher` config key
- Replaces the defunct `kernel.unprivileged_userns_clone` sysctl with AppArmor
  5.0's `kernel.apparmor_restrict_unprivileged_userns=1`
- Detects and reports sudo-rs, Rust coreutils, TPM presence, Intel TDX, AMD SEV-SNP
- OpenSCAP prefers the `ssg-ubuntu2604` datastream with automatic fallback
- Package list modernized (dropped tripwire/ecryptfs-utils/libopenscap8, added tpm2-tools)
- All prompts have non-interactive fallbacks with safe defaults (CI-friendly)

## Migration gotchas (read before hardening)

1. **DSA SSH keys stop working.** Migrate to Ed25519 first:
   `ssh-keygen -t ed25519` and update `authorized_keys` everywhere.
2. **sudo-rs**: standard sudoers files work; exotic sudoers features and plugins
   may not. Test admin workflows; keep `sudo.ws` installed as a fallback if unsure.
3. **Shell scripts and coreutils**: uutils aims for compatibility, but
   `split`/`sort`/locale edge cases can differ. Pin GNU behavior with `gnu`-prefixed
   binaries where it matters.
4. **cgroup v1 is gone.** Old container runtimes and Java heap-detection flags
   relying on v1 paths must be updated.
5. **Process monitoring**: match `sshd-session`/`sshd-auth` too, not just `sshd`.
6. **Coming from 25.10?** `do-release-upgrade` to 26.04 first — 25.x receives no
   security updates since July 2026.

## Verify post-quantum crypto after hardening

```bash
# SSH: confirm the negotiated kex on a new connection
ssh -v user@host 2>&1 | grep "kex: algorithm"
# expect: mlkem768x25519-sha256

# TLS: OpenSSL 3.5 defaults
openssl s_client -connect example.com:443 -brief 2>&1 | head
```
