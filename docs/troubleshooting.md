# Troubleshooting

## Locked out of SSH

Use console/physical access, then:

```bash
sudo ufw allow ssh
sudo systemctl restart ssh
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip <your-ip>
```

If you disabled password auth without working keys, re-enable temporarily:

```bash
sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/99-hardening.conf
sudo sed -i 's/^AuthenticationMethods publickey$/AuthenticationMethods publickey,password/' /etc/ssh/sshd_config.d/99-hardening.conf
sudo sshd -t && sudo systemctl restart ssh
```

Add your key, then revert both lines.

## A service won't start

```bash
sudo systemctl status <service>
sudo journalctl -u <service> -n 50 --no-pager
sudo systemctl restart <service>
```

If a systemd sandboxing drop-in is the cause, remove it and reload:

```bash
sudo rm /etc/systemd/system/<service>.service.d/hardening.conf
sudo systemctl daemon-reload && sudo systemctl restart <service>
```

## Chrony not syncing (25.x/26.04)

```bash
sudo systemctl status chrony
chronyc sources -v          # NTS servers need outbound 123/udp + 4460/tcp (NTS-KE)
chronyc tracking
sudo systemctl restart chrony
```

If NTS handshakes fail behind a strict egress firewall, allow TCP 4460 out, or
remove the `nts` option from servers in `/etc/chrony/chrony.conf`.

## ClamAV eating CPU/RAM

```bash
sudo systemctl stop clamav-daemon
sudo systemctl disable clamav-daemon      # scheduled scans still work via clamscan
```

## Audit rules problems

```bash
sudo auditctl -l                          # active rules
sudo nano /etc/audit/rules.d/hardening.rules
sudo reboot                               # rules are immutable (-e 2); reload needs reboot
```

On 26.04, remember both units must run: `auditd.service` and `audit-rules.service`.

## Firewall debugging

```bash
sudo ufw status verbose
sudo tail -f /var/log/ufw.log
sudo ufw disable    # emergency only — re-enable ASAP
sudo ufw enable
```

## An application broke after kernel hardening

Most likely candidates in `/etc/sysctl.d/99-security-hardening.conf`:

- `kernel.io_uring_disabled=2` — breaks io_uring-based apps (some DBs, proxies)
- `kernel.unprivileged_bpf_disabled=1` — breaks unprivileged eBPF tooling
- `kernel.apparmor_restrict_unprivileged_userns=1` — breaks unpackaged apps that
  sandbox via user namespaces (browsers installed outside apt/snap)
- `kernel.yama.ptrace_scope=2` — breaks debuggers/profilers attaching to processes

Relax the specific key, then `sudo sysctl --system`.

## Ubuntu 26.04 specific

- **DSA key rejected**: OpenSSH 10.2 removed DSA. Generate a new key: `ssh-keygen -t ed25519`
- **sudo behaves differently**: sudo-rs doesn't support every legacy sudoers feature.
  Install classic sudo: `sudo apt install sudo.ws` (available as `sudo.ws` command)
- **Script parsing differences**: coreutils are Rust (uutils). GNU versions are
  available with a `gnu` prefix (`gnucp`, `gnudate`, `gnusha256sum`, ...)
- **Monitoring lost sshd**: process names are now `sshd`, `sshd-auth`, `sshd-session`

## Rolling back

Every modified config is backed up with timestamp + permissions metadata:

```bash
ls /var/backups/security-hardening/
# restore example:
sudo cp /var/backups/security-hardening/sshd_config.<timestamp>.bak /etc/ssh/sshd_config
```

Still stuck? [Open an issue](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/issues) with your Ubuntu version, script version, and the relevant log from `/var/log/security-hardening/`.
