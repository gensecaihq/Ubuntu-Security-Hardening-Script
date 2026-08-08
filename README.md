# 🛡️ Ubuntu Security Hardening Scripts

**One command to harden Ubuntu — kernel to firewall, CIS-aligned, production-tested.**

[![GitHub release](https://img.shields.io/github/v/release/gensecaihq/Ubuntu-Security-Hardening-Script)](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-18.04%20→%2026.04%20LTS-orange)](https://ubuntu.com/)
[![Bash](https://img.shields.io/badge/Bash-5.0%2B-green)](https://www.gnu.org/software/bash/)
[![GitHub stars](https://img.shields.io/github/stars/gensecaihq/Ubuntu-Security-Hardening-Script?style=social)](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/stargazers)

Hardening a server properly means touching SSH, the kernel, auditd, AppArmor, the firewall, time sync, malware scanning, and a dozen other subsystems — and getting any of them wrong can lock you out or break production. These scripts do all of it in one run, with safety checks, automatic backups, and a full report of every change.

```bash
git clone https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script.git
cd Ubuntu-Security-Hardening-Script
sudo ./ubuntu-hardening-26-04.sh    # pick the script for your Ubuntu version
```

> ⭐ **If this saves you an afternoon of hardening work, star the repo** — it helps others find it.

## ✨ Why this project

- **Complete** — 17 hardening modules covering SSH, kernel sysctls, auditd, AppArmor, UFW, Fail2ban, AIDE, ClamAV, rootkit detection, automatic updates, systemd sandboxing, cloud metadata protection, and compliance scanning
- **Safe by design** — checks for SSH keys *before* disabling password auth, backs up every file it touches (with permissions), desktop detection prevents breaking GUI apps, and everything is logged
- **Current** — Ubuntu 26.04 LTS support with post-quantum SSH (ML-KEM), sudo-rs and Rust coreutils awareness, AppArmor 5.0, auditd 4.1
- **Auditable** — plain Bash you can read, a human report plus a JSON compliance report for your SIEM, and an OpenSCAP/Lynis baseline on completion
- **Battle-tested** — community-reported issues fixed across all scripts, plus a 2026 deep audit (v5.0) that eliminated SSH-lockout edge cases, made re-runs idempotent (no firewall-rule wipes, no duplicate configs), and removed a config that could open an unintended network listener
- **Safe to re-run** (v5.0 script) — running it again on an already-hardened box preserves your custom firewall rules and doesn't duplicate configuration

## 📦 Pick your script

| Your Ubuntu | Script | Status |
|-------------|--------|--------|
| **26.04 LTS** (supported to 2031) | `ubuntu-hardening-26-04.sh` v5.0 | ✅ Recommended |
| **24.04 LTS** | `ubuntu-hardening-24-04.sh` v3.0 | ✅ Supported |
| **22.04 / 20.04 / 18.04** | `ubuntu-hardening-original.sh` v2.0 | ✅ Supported¹ |
| 25.04 / 25.10 | `ubuntu-hardening-25.sh` v4.0 | ⛔ EOL — [upgrade to 26.04](docs/ubuntu-26-04.md) |

¹ 20.04/18.04 standard support has ended — they need [Ubuntu Pro ESM](https://ubuntu.com/pro) for security updates.

## 🔐 What gets hardened

**Access** — SSH key-only auth with lockout prevention, root login disabled, post-quantum key exchange (26.04), PAM password quality, FIDO2 support
**Network** — UFW default-deny with rate-limited SSH, SYN-flood/redirect/spoofing protection, cloud IMDS lockdown (AWS/Azure/GCP)
**Kernel** — 40+ sysctl hardening keys, kernel lockdown, restricted eBPF/io_uring/ptrace, unprivileged userns restrictions
**Integrity** — AIDE file monitoring, comprehensive auditd rules with Living-Off-The-Land and container-escape detection
**Malware** — ClamAV with quarantine, rkhunter, chkrootkit, scheduled scans
**Compliance** — OpenSCAP CIS/DISA-STIG scanning, Lynis audit, JSON report for SIEM

Full details: [docs/security-controls.md](docs/security-controls.md)

## 🆕 Ubuntu 26.04 LTS support (v5.0)

Built for the biggest Ubuntu security shift in years:

- 🔮 **Post-quantum SSH** — hybrid `mlkem768x25519-sha256` key exchange (OpenSSH 10.2 / FIPS 203)
- 🦀 **Memory-safe defaults** — sudo-rs and Rust coreutils detected and handled
- 🛡️ **AppArmor 5.0** — user-namespace and io_uring mediation
- 🔐 **TPM-backed FDE** detection, Intel TDX + AMD SEV-SNP confidential computing
- 🤖 **CI-friendly** — fully non-interactive mode with safe defaults

Details and migration gotchas (DSA keys, sudo-rs, cgroup v1 removal): [docs/ubuntu-26-04.md](docs/ubuntu-26-04.md)

## 📚 Documentation

| Guide | What's in it |
|-------|--------------|
| [Installation](docs/installation.md) | Requirements, pre-flight checklist, CI usage, verification |
| [Security Controls](docs/security-controls.md) | Every control applied, script comparison matrix |
| [Configuration](docs/configuration.md) | Firewall rules, SSH tweaks, Ubuntu Pro, AIDE/audit maintenance |
| [Monitoring](docs/monitoring.md) | Reports, log locations, routine commands, cadence |
| [Troubleshooting](docs/troubleshooting.md) | SSH lockout recovery, service failures, rollbacks |
| [Compliance](docs/compliance.md) | OpenSCAP, CIS/DISA-STIG profiles, `usg`, SIEM integration |
| [Ubuntu 26.04 Notes](docs/ubuntu-26-04.md) | What changed in 26.04 and how the script handles it |

## ⚠️ Before you run it

1. **Snapshot first.** These scripts change a lot of system state.
2. **SSH keys working?** Password auth gets disabled (the script checks and warns if no keys are found).
3. **Console access ready?** Only rate-limited SSH is allowed through the firewall afterward.
4. **Test in a VM** before production. Review the report at `/var/log/security-hardening/`.

## 🤝 Contributing

Bug reports, fixes, and testing on different Ubuntu versions are all hugely welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Look for [`good first issue`](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/issues) to get started.

Found a security issue? Please report it privately — see [SECURITY.md](SECURITY.md).

## 🙏 Thanks to Our Contributors

We're grateful to everyone who has contributed to making this project better! This includes opening issues, submitting pull requests, writing code, and participating in discussions.
<!-- ALL-CONTRIBUTORS-START -->
<!-- This section is automatically updated by GitHub Actions -->

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/BoozeLee">
        <img src="https://avatars.githubusercontent.com/u/96494827?v=4" width="80px;" alt="BoozeLee"/><br />
        <sub><b>BoozeLee</b></sub>
      </a><br />
      <sub>📖 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/Kingcitaldo125">
        <img src="https://avatars.githubusercontent.com/u/25781344?v=4" width="80px;" alt="Kingcitaldo125"/><br />
        <sub><b>Kingcitaldo125</b></sub>
      </a><br />
      <sub>🐛 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/MoezLog">
        <img src="https://avatars.githubusercontent.com/u/179240440?v=4" width="80px;" alt="MoezLog"/><br />
        <sub><b>MoezLog</b></sub>
      </a><br />
      <sub>🐛 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/Shekhar0050M">
        <img src="https://avatars.githubusercontent.com/u/62455266?v=4" width="80px;" alt="Shekhar0050M"/><br />
        <sub><b>Shekhar0050M</b></sub>
      </a><br />
      <sub>🐛 </sub>
    </td>
    </tr>
    <tr>
    <td align="center">
      <a href="https://github.com/actions-user">
        <img src="https://avatars.githubusercontent.com/u/65916846?v=4" width="80px;" alt="actions-user"/><br />
        <sub><b>actions-user</b></sub>
      </a><br />
      <sub>💻 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/alokemajumder">
        <img src="https://avatars.githubusercontent.com/u/26596583?v=4" width="80px;" alt="alokemajumder"/><br />
        <sub><b>alokemajumder</b></sub>
      </a><br />
      <sub>💻 🐛 📖 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/benj-ntu">
        <img src="https://avatars.githubusercontent.com/u/196352206?v=4" width="80px;" alt="benj-ntu"/><br />
        <sub><b>benj-ntu</b></sub>
      </a><br />
      <sub>🐛 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/coderabbitai[bot]">
        <img src="https://avatars.githubusercontent.com/in/347564?v=4" width="80px;" alt="coderabbitai[bot]"/><br />
        <sub><b>coderabbitai[bot]</b></sub>
      </a><br />
      <sub>💬</sub>
    </td>
    </tr>
    <tr>
    <td align="center">
      <a href="https://github.com/cropduster32">
        <img src="https://avatars.githubusercontent.com/u/76622404?v=4" width="80px;" alt="cropduster32"/><br />
        <sub><b>cropduster32</b></sub>
      </a><br />
      <sub>🐛 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/gainskills">
        <img src="https://avatars.githubusercontent.com/u/1937472?v=4" width="80px;" alt="gainskills"/><br />
        <sub><b>gainskills</b></sub>
      </a><br />
      <sub>📖 </sub>
    </td>
    <td align="center">
      <a href="https://github.com/gensecai-dev">
        <img src="https://avatars.githubusercontent.com/u/216218359?v=4" width="80px;" alt="gensecai-dev"/><br />
        <sub><b>gensecai-dev</b></sub>
      </a><br />
      <sub>💻 </sub>
    </td>
  </tr>
</table>

**Legend:** 💻 Code | 🐛 Bug Reports | 📖 Documentation | 🚧 Maintenance | 💬 Discussions | 👀 Reviews

<!-- ALL-CONTRIBUTORS-END -->

> **Note:** This section is automatically updated when new contributors join the project.

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=gensecaihq/Ubuntu-Security-Hardening-Script&type=Date)](https://star-history.com/#gensecaihq/Ubuntu-Security-Hardening-Script&Date)

## 📜 License & Disclaimer

MIT — see [LICENSE](LICENSE).

Provided "AS IS" without warranty. These scripts make significant system changes: **back up first, test in a non-production environment, review the code before running.** The authors are not responsible for damage, data loss, or service interruption.

---

**Version 5.0** · Updated August 8, 2026 · Supports Ubuntu 18.04 → 26.04 LTS · [Issues](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/issues) · [Discussions](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/discussions)
