# Installation Guide

## System Requirements

- **Ubuntu**: 26.04 LTS (recommended), 24.04 LTS, 22.04 LTS, 18.04/20.04 (ESM), or legacy 25.x
- **Disk space**: 2 GB free minimum
- **RAM**: 1 GB minimum (2 GB recommended)
- **Access**: root or sudo privileges
- **Network**: internet connection for package downloads

## Which script do I run?

| Your Ubuntu version | Script | Status |
|---------------------|--------|--------|
| 26.04 LTS (Resolute Raccoon) | `ubuntu-hardening-26-04.sh` | ✅ Recommended |
| 24.04 LTS (Noble Numbat) | `ubuntu-hardening-24-04.sh` | ✅ Supported |
| 22.04 / 20.04 / 18.04 | `ubuntu-hardening-original.sh` | ✅ Supported (20.04/18.04 need Ubuntu Pro ESM) |
| 25.04 / 25.10 | `ubuntu-hardening-25.sh` | ⛔ EOL — upgrade to 26.04 LTS first |

Check your version:

```bash
lsb_release -a
```

## Pre-Installation Checklist

- [ ] Create a system backup or VM snapshot
- [ ] Ensure SSH **key** access works (password auth will be disabled)
- [ ] Document any custom configurations
- [ ] Note the firewall ports your services need
- [ ] Have console/physical access ready in case of SSH issues
- [ ] **Ubuntu 26.04**: migrate any DSA (`ssh-dss`) keys to Ed25519 — OpenSSH 10.2 removed DSA entirely

## Install

```bash
git clone https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script.git
cd Ubuntu-Security-Hardening-Script
chmod +x ubuntu-hardening-*.sh
sudo ./ubuntu-hardening-26-04.sh   # pick the script for your version
```

### With logging to a file

```bash
sudo ./ubuntu-hardening-26-04.sh 2>&1 | tee hardening-install.log
```

### Non-interactive / CI use (26.04 script only)

The 26.04 script detects non-interactive sessions and uses safe defaults
(weekly scans, password auth kept enabled if no SSH keys are present, abort on
unsupported Ubuntu versions):

```bash
sudo ./ubuntu-hardening-26-04.sh < /dev/null
```

## During installation

The script interactively prompts for:

- ClamAV scan frequency (daily/weekly/monthly)
- OpenSCAP scan frequency (daily/weekly/monthly)
- Confirmation before proceeding, and before disabling SSH password auth if no keys are found

## Verify after installation

```bash
# 1. Critical services
sudo systemctl status auditd apparmor ufw fail2ban unattended-upgrades

# 2. Firewall
sudo ufw status verbose

# 3. SSH access — from ANOTHER terminal before disconnecting!
ssh -i ~/.ssh/your_key user@server

# 4. Time sync (25.x/26.04)
chronyc sources
chronyc tracking

# 5. Review the report
sudo cat /var/log/security-hardening/hardening_report_*.txt
```

See [troubleshooting.md](troubleshooting.md) if anything fails.
