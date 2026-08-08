# Post-Installation Configuration

## Open firewall ports for your services

Only rate-limited SSH and DHCP are allowed by default:

```bash
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 3306/tcp comment 'MySQL'
sudo ufw status verbose
```

## Adjust SSH settings

The hardened config lives in a drop-in (the stock `sshd_config` is untouched):

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
sudo sshd -t                      # always test first
sudo systemctl restart ssh
```

Common tweaks:

- `AllowTcpForwarding yes` — if you need SSH tunnels
- `X11Forwarding yes` — if you need X11
- Add `AllowUsers`/`AllowGroups` to restrict who may log in

## Automatic updates

```bash
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
sudo unattended-upgrade --dry-run --debug   # test
```

To enable automatic reboots after kernel updates, set
`Unattended-Upgrade::Automatic-Reboot "true";`.

## Fail2ban trusted IPs

Add your CI/CD, monitoring and admin IPs to `ignoreip`:

```bash
sudo nano /etc/fail2ban/jail.local     # [DEFAULT] ignoreip = ...
sudo systemctl restart fail2ban
```

## Chrony / NTS (25.x and 26.04)

```bash
chronyc sources      # view time sources (NTS servers marked)
chronyc tracking     # sync status
chronyc ntsdump      # NTS key data
sudo nano /etc/chrony/chrony.conf   # change servers if needed
```

## AIDE database updates

After intentional system changes (package installs, config edits), refresh the
baseline so integrity checks don't alert on your own changes:

```bash
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

## Audit rules

Rules are immutable at runtime (`-e 2`). To modify:

```bash
sudo nano /etc/audit/rules.d/hardening.rules
sudo reboot          # required — immutable mode blocks reloads
```

## OpenSCAP profile selection

```bash
# Default: CIS Level 1 Server. For DISA STIG:
sudo OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig /usr/local/bin/openscap-scan.sh
```

## SSH certificates and FIDO2 keys

See the generated guide on your system: `/etc/ssh/ssh-certificates-setup.md`

```bash
# FIDO2 hardware-backed key (YubiKey, SoloKey, ...)
ssh-keygen -t ed25519-sk -O resident -O verify-required
```

## Ubuntu Pro (recommended on LTS)

```bash
sudo pro attach <token>
sudo pro enable esm-infra esm-apps livepatch
sudo pro enable usg        # certified CIS/DISA-STIG tooling
```
