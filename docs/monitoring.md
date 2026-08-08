# Monitoring & Maintenance

## Reports

```bash
# Hardening report (generated at install time)
sudo cat /var/log/security-hardening/hardening_report_*.txt

# JSON compliance report (for SIEM ingestion)
sudo cat /var/log/security-hardening/compliance-report.json

# Initial audit results
ls /var/log/security-hardening/initial-audit/
```

## Log locations

| What | Where |
|------|-------|
| Hardening logs | `/var/log/security-hardening/` |
| Audit logs | `/var/log/audit/audit.log` |
| ClamAV | `/var/log/clamav/` |
| UFW (rotated daily) | `/var/log/ufw.log` |
| Fail2ban | `/var/log/fail2ban.log` |
| OpenSCAP reports | `/var/log/openscap/` |
| Chrony (25.x/26.04) | `/var/log/chrony/` |

## Routine commands

```bash
# Comprehensive audit
sudo lynis audit system

# Rootkit checks
sudo rkhunter -c
sudo chkrootkit

# File integrity
sudo aide --check

# Audit summaries
sudo aureport --summary
sudo aureport --auth --failure

# Compliance scan
sudo /usr/local/bin/openscap-scan.sh

# Intrusion prevention status
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Service health
sudo systemctl status auditd apparmor clamav-daemon ufw fail2ban

# Scheduled jobs (24.04+ use systemd timers)
systemctl list-timers 'aide-*' 'clamav-*' 'openscap-*'
```

## Keeping definitions current

```bash
sudo apt update && sudo apt upgrade   # packages
sudo freshclam                        # virus definitions
sudo rkhunter --update                # rootkit signatures
sudo aide --update                    # integrity baseline (after changes)
```

## Suggested cadence

- **Daily** (automated): AIDE check, unattended-upgrades, freshclam
- **Weekly**: review fail2ban bans, UFW logs, audit failures; ClamAV/OpenSCAP scans
- **Monthly**: `lynis audit system`, review report deltas
- **Quarterly**: re-run the hardening script after review; test restore procedures
