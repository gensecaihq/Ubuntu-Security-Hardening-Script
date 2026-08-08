# Compliance Scanning

The scripts implement controls aligned with **CIS Ubuntu Linux Benchmarks**,
**NIST CSF / SP 800-53**, **DISA STIG** (partial), and PCI DSS where applicable.
Alignment is not certification — run the scanners below for evidence.

## OpenSCAP

Installed and scheduled automatically. Manual usage:

```bash
# List available profiles for your release
sudo oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu*.xml

# CIS Level 1 Server scan (default profile of the bundled scan script)
sudo /usr/local/bin/openscap-scan.sh

# DISA STIG profile instead
sudo OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig /usr/local/bin/openscap-scan.sh

# Reports (HTML + XML + generated remediation script)
ls -lh /var/log/openscap/
```

The 26.04 script prefers the `ssg-ubuntu2604` datastream and automatically
falls back to the newest Ubuntu datastream available on the system.

## Ubuntu Security Guide (Ubuntu Pro)

For Canonical-certified CIS/DISA-STIG audit and remediation on LTS releases:

```bash
sudo pro enable usg
sudo apt install usg
sudo usg audit cis_level1_server
sudo usg fix cis_level1_server      # review before running in production!
```

## SIEM integration

Each run writes a machine-readable summary to
`/var/log/security-hardening/compliance-report.json` including applied controls,
kernel lockdown state, post-quantum crypto status (26.04), and framework mappings.

## Lynis

```bash
sudo lynis audit system             # hardening index + prioritized suggestions
```

A baseline Lynis report from install time is kept in
`/var/log/security-hardening/initial-audit/`.
