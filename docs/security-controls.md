# Security Controls Reference

What each script actually applies, by area.

## 1. Authentication & Access

- SSH root login disabled, password authentication disabled (with SSH-key safety check first)
- PAM password quality enforcement (`libpam-pwquality`)
- Login attempt limits, session timeout, strong cipher suites (version-specific)
- FIDO2/WebAuthn security key support; SSH certificate scaffolding documented in `/etc/ssh/ssh-certificates-setup.md`

## 2. Network Security

- UFW default-deny incoming/routed, allow outgoing; SSH rate-limited (`ufw limit 22/tcp`)
- UFW log rotation configured (Issue #2 fix)
- TCP SYN flood protection, ICMP redirect prevention, source-route blocking, martian logging
- IPv6 hardening mirrors IPv4 settings
- Cloud metadata (IMDS at 169.254.169.254) egress restricted to root on AWS/Azure/GCP

## 3. System Integrity

- AIDE file integrity monitoring with daily systemd timer (cron on the legacy script)
- debsums package verification, needrestart, debsecan
- Comprehensive auditd ruleset: identity files, sudoers, SSH config, kernel modules,
  time changes, network config, cron, privileged commands
- **LOTL (Living-Off-The-Land) detection**: audit rules on wget/curl/scp/nc/socat/base64/
  python3/openssl/tar and more
- Container-escape detection (`unshare`, `setns`), privilege-escalation and ptrace-injection rules
- Audit config made immutable (`-e 2`, reboot required to change rules)

## 4. Kernel Hardening (sysctl)

Applied via `/etc/sysctl.d/99-security-hardening.conf`:

- ASLR (`kernel.randomize_va_space=2`), `kptr_restrict=2`, `dmesg_restrict=1`
- `yama.ptrace_scope=2`, kexec disabled, SysRq disabled, `perf_event_paranoid=3`
- BPF: `unprivileged_bpf_disabled=1`, JIT hardening
- io_uring restricted (`kernel.io_uring_disabled=2`)
- Hardlink/symlink/FIFO/regular-file protections
- **24.04+**: AppArmor-based unprivileged userns restriction
  (`kernel.apparmor_restrict_unprivileged_userns=1` on the 26.04 script)
- Kernel lockdown (`lockdown=integrity`) added to GRUB

## 5. Mandatory Access Control

- AppArmor enabled and enforcing (server) or desktop-safe complain mode (Issue #12 fix)
- **26.04**: AppArmor 5.0 with userns, io_uring and mqueue mediation
- Snap confinement settings

## 6. Malware & Rootkit Detection

- ClamAV with scheduled scans, quarantine to `/var/quarantine`, freshclam auto-updates
- rkhunter + chkrootkit + unhide

## 7. Time Synchronization

- **18.04–24.04**: systemd-timesyncd
- **25.x / 26.04**: Chrony with Network Time Security (NTS) against
  `time.cloudflare.com`, `nts.ntp.se`, `ptbtime1.ptb.de`, `time.dfm.dk`,
  with Ubuntu NTP pool fallback; command port disabled

## 8. Intrusion Prevention

- Fail2ban with systemd backend, progressive ban times, SSH + port-scan jails
- Tuned to avoid locking out legitimate users (maxretry 5, 10m initial ban, private networks ignored)

## 9. Automatic Updates

- unattended-upgrades: security + updates + ESM origins, mail reports, auto-fix dpkg
- needrestart configured for automatic service restarts

## 10. Systemd Service Sandboxing (24.04+)

Hardening drop-ins (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`,
`RestrictNamespaces`, capability bounding, etc.) for: ssh, fail2ban,
clamav-daemon, chrony, auditd. Plus systemd-oomd, resolved DNSSEC/DoT
(opportunistic), cgroup v2 memory limits for user slices.

## 11. Compliance Scanning

- OpenSCAP with CIS Level 1 Server profile by default (DISA STIG selectable via
  `OSCAP_PROFILE`), scheduled via systemd timer
- JSON compliance report for SIEM ingestion at
  `/var/log/security-hardening/compliance-report.json`
- Lynis baseline audit on completion

## Script Comparison

| Feature | Original (v2.0) | 24.04 (v3.0) | 25.x (v4.0) | 26.04 (v5.0) |
|---------|-----------------|--------------|-------------|--------------|
| Ubuntu | 18.04–22.04 | 24.04 LTS | 25.04/25.10 (EOL) | 26.04 LTS |
| Scheduling | Cron | systemd timers | systemd timers | systemd timers |
| Time sync | timesyncd | timesyncd | Chrony + NTS | Chrony 4.8 + NTS |
| Kernel | 4.15–5.15 | 6.8+ | 6.14/6.17 | 7.0 |
| SSH crypto | Modern | Modern | sntrup761 PQ kex | OpenSSH 10.2, ML-KEM PQ kex |
| sudo-rs | — | — | 25.10 | Default (detected) |
| Rust coreutils | — | — | 25.10 | Default (~80 utils) |
| AppArmor | 3.x | 4.0 | 4.x | 5.0 |
| auditd | 2.8/3.0 | 3.1 | 4.0 | 4.1 (split services) |
| TPM FDE detection | — | — | — | Yes (GA in 26.04) |
| TDX/SEV-SNP detection | — | — | TDX | TDX + SEV-SNP |
| Non-interactive mode | — | — | — | Yes |

## Compliance Frameworks

Controls are mapped to:

- CIS Ubuntu Linux Benchmarks (version-specific)
- NIST Cybersecurity Framework / NIST SP 800-53
- DISA STIG (partial)
- PCI DSS requirements (where applicable)

See [compliance.md](compliance.md) for scanning instructions.
