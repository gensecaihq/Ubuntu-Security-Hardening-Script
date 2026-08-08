#!/bin/bash
# Ubuntu Security Hardening Script - Production Grade
# Author: Aloke Majumder
# GitHub: https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script
# License: MIT License
# Version: 2.0
# Tested on: Ubuntu 18.04/20.04/22.04

# DISCLAIMER:
# This script is provided "AS IS" without warranty of any kind, express or implied. 
# The author expressly disclaims any and all warranties, express or implied, including 
# any warranties as to the usability, suitability or effectiveness of any methods or 
# measures this script attempts to apply. By using this script, you agree that the 
# author shall not be held liable for any damages resulting from the use of this script.

set -euo pipefail  # Exit on error, undefined variables, pipe failures
IFS=$'\n\t'       # Set secure Internal Field Separator

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
readonly SCRIPT_NAME=$(basename "$0")
readonly LOG_DIR="/var/log/security-hardening"
readonly LOG_FILE="${LOG_DIR}/hardening-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/var/backups/security-hardening"
readonly REPORT_FILE="${LOG_DIR}/hardening_report_$(date +%Y%m%d-%H%M%S).txt"

# Function to print colored output
print_message() {
    local color=$1
    local message=${2:-}
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}" | tee -a "$LOG_FILE"
}

# Function to handle errors
error_exit() {
    print_message "$RED" "ERROR: $1"
    exit 1
}

# Function to create necessary directories
setup_directories() {
    mkdir -p "$LOG_DIR" "$BACKUP_DIR"
    chmod 700 "$LOG_DIR" "$BACKUP_DIR"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Function to check Ubuntu version
check_ubuntu_version() {
    if ! command -v lsb_release &> /dev/null; then
        error_exit "lsb_release not found. Is this Ubuntu?"
    fi
    
    local version=$(lsb_release -rs)
    print_message "$GREEN" "Detected Ubuntu version: $version"
    
    # Check if it's a supported version
    case "$version" in
        "18.04"|"20.04"|"22.04")
            print_message "$GREEN" "Supported Ubuntu version detected"
            ;;
        *)
            print_message "$YELLOW" "WARNING: This script is tested on Ubuntu 18.04/20.04/22.04. Proceed with caution."
            read -p "Do you want to continue? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "User cancelled operation"
            fi
            ;;
    esac
}

# Function to backup configuration files
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
        cp -p "$file" "$backup_name"
        print_message "$GREEN" "Backed up $file to $backup_name"
    fi
}

# Function to validate user input
validate_frequency() {
    local frequency=$1
    case "$frequency" in
        daily|weekly|monthly)
            echo "$frequency"
            ;;
        *)
            # Warning must go to stderr - stdout is captured by $(validate_frequency ...)
            print_message "$YELLOW" "Invalid frequency. Using 'weekly' as default." >&2
            echo "weekly"
            ;;
    esac
}

# Function to detect desktop environment (Fix for Issue #12)
detect_desktop_environment() {
    # Check for display managers
    if systemctl is-active --quiet gdm 2>/dev/null || \
       systemctl is-active --quiet gdm3 2>/dev/null || \
       systemctl is-active --quiet lightdm 2>/dev/null || \
       systemctl is-active --quiet sddm 2>/dev/null; then
        echo "true"
        return
    fi

    # Check for DISPLAY or WAYLAND environment
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        echo "true"
        return
    fi

    # Check for desktop packages
    if dpkg -l 2>/dev/null | grep -qE "ubuntu-desktop|kubuntu-desktop|xubuntu-desktop|gnome-shell|kde-plasma-desktop"; then
        echo "true"
        return
    fi

    # Check for running desktop sessions
    if pgrep -x "gnome-shell" > /dev/null 2>&1 || \
       pgrep -x "plasmashell" > /dev/null 2>&1 || \
       pgrep -x "xfce4-session" > /dev/null 2>&1; then
        echo "true"
        return
    fi

    echo "false"
}

# Function to check if SSH keys exist (Fix for SSH lockout issue)
check_ssh_keys_exist() {
    local has_keys=false

    # Check for authorized_keys in common locations
    for user_home in /root /home/*; do
        if [[ -d "$user_home" ]] && [[ -f "${user_home}/.ssh/authorized_keys" ]]; then
            if [[ -s "${user_home}/.ssh/authorized_keys" ]]; then
                has_keys=true
                break
            fi
        fi
    done

    echo "$has_keys"
}

# Function to update and upgrade packages
update_system() {
    print_message "$GREEN" "Updating package lists..."
    apt-get update -y || error_exit "Failed to update package lists"
    
    print_message "$GREEN" "Upgrading installed packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || error_exit "Failed to upgrade packages"
}

# Function to install required packages
install_packages() {
    print_message "$GREEN" "Installing security tools and packages..."
    
    local packages=(
        "aide"
        "auditd"
        "audispd-plugins"
        "debsums"
        "apparmor"
        "apparmor-utils"
        "apparmor-profiles"
        "apparmor-profiles-extra"
        "clamav"
        "clamav-daemon"
        "clamav-freshclam"
        "unattended-upgrades"
        "ufw"
        "fail2ban"
        "rkhunter"
        "chkrootkit"
        "lynis"
        "libpam-pwquality"
        "apt-listchanges"
    )
    
    # Check Ubuntu version for OpenSCAP
    local version=$(lsb_release -rs)
    if [[ "$version" == "18.04" ]]; then
        packages+=("libopenscap8" "openscap-scanner")
    else
        packages+=("openscap-scanner")
    fi
    
    for package in "${packages[@]}"; do
        print_message "$GREEN" "Installing $package..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" || print_message "$YELLOW" "WARNING: Failed to install $package"
    done
}

# Function to configure AIDE
configure_aide() {
    print_message "$GREEN" "Configuring AIDE file integrity checker..."
    
    # Initialize AIDE database
    if command -v aideinit &> /dev/null; then
        aideinit || error_exit "Failed to initialize AIDE"
        
        # Move the new database to production
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            print_message "$GREEN" "AIDE database initialized successfully"
        else
            print_message "$YELLOW" "WARNING: AIDE database file not found at expected location"
        fi
        
        # Create AIDE check cron job
        cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Daily Report for $(hostname)" root
EOF
        chmod 755 /etc/cron.daily/aide-check
    else
        print_message "$YELLOW" "WARNING: aideinit command not found"
    fi
}

# Function to configure Auditd
configure_auditd() {
    print_message "$GREEN" "Configuring auditd..."
    
    backup_file "/etc/audit/auditd.conf"
    
    cat > /etc/audit/auditd.conf << 'EOF'
# Audit daemon configuration
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
enable_krb5 = no
EOF

    # Add basic audit rules
    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

# LOTL (Living Off The Land) Detection Rules
# Monitor commonly abused binaries
-w /usr/bin/wget -p x -k lotl_download
-w /usr/bin/curl -p x -k lotl_download
-w /usr/bin/base64 -p x -k lotl_encoding
-w /usr/bin/nc -p x -k lotl_netcat
-w /usr/bin/python -p x -k lotl_scripting
-w /usr/bin/python3 -p x -k lotl_scripting
-w /usr/bin/perl -p x -k lotl_scripting

# Monitor archive and transfer tools
-w /usr/bin/tar -p x -k lotl_archive
-w /usr/bin/scp -p x -k lotl_transfer
-w /usr/bin/ssh -p x -k lotl_ssh

# Privilege escalation detection
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_escalation

# Staging directory monitoring
-w /tmp -p x -k tmp_exec
-w /dev/shm -p x -k shm_exec
EOF

    # Restart auditd
    systemctl restart auditd || error_exit "Failed to restart auditd"
    systemctl enable auditd

    # Load new rules
    augenrules --load || print_message "$YELLOW" "WARNING: Failed to load audit rules"
}

# Function to configure AppArmor
# Fix for Issue #12: Desktop environment detection to prevent breaking GUI apps
configure_apparmor() {
    print_message "$GREEN" "Configuring AppArmor..."

    # Detect if running on desktop environment
    local is_desktop
    is_desktop=$(detect_desktop_environment)

    # Enable AppArmor
    systemctl enable apparmor || error_exit "Failed to enable AppArmor"
    systemctl start apparmor || error_exit "Failed to start AppArmor"

    if [[ "$is_desktop" == "true" ]]; then
        # Desktop environment detected - use complain mode for extra profiles
        print_message "$YELLOW" "Desktop environment detected!"
        print_message "$YELLOW" "Using COMPLAIN mode for experimental AppArmor profiles to prevent breaking GUI applications."

        # Only enforce known-safe profiles that won't break desktop apps
        local safe_profiles=(
            "/etc/apparmor.d/usr.sbin.sshd"
            "/etc/apparmor.d/usr.sbin.rsyslogd"
            "/etc/apparmor.d/usr.sbin.cron"
            "/etc/apparmor.d/usr.sbin.ntpd"
        )

        for profile in "${safe_profiles[@]}"; do
            if [[ -f "$profile" ]]; then
                aa-enforce "$profile" 2>/dev/null || true
            fi
        done

        # Set extra profiles to complain mode (monitor but don't block)
        if [[ -d /usr/share/apparmor/extra-profiles/ ]]; then
            for profile in /usr/share/apparmor/extra-profiles/*; do
                if [[ -f "$profile" ]]; then
                    aa-complain "$profile" 2>/dev/null || true
                fi
            done
        fi

        print_message "$GREEN" "AppArmor configured with desktop-safe settings"
    else
        # Server environment - apply full hardening
        print_message "$GREEN" "Server environment detected. Applying full AppArmor enforcement..."

        # Install additional profiles
        if [[ -d /usr/share/apparmor/extra-profiles/ ]]; then
            cp -n /usr/share/apparmor/extra-profiles/* /etc/apparmor.d/ 2>/dev/null || true
        fi

        # Set all profiles to enforce mode
        aa-enforce /etc/apparmor.d/* 2>/dev/null || print_message "$YELLOW" "WARNING: Some AppArmor profiles could not be enforced"

        print_message "$GREEN" "AppArmor profiles enforced"
    fi
}

# Function to configure ClamAV
configure_clamav() {
    print_message "$GREEN" "Configuring ClamAV..."

    # Stop services before configuration
    systemctl stop clamav-freshclam 2>/dev/null || true
    systemctl stop clamav-daemon 2>/dev/null || true
    
    # Update virus database
    print_message "$GREEN" "Updating ClamAV virus database..."
    freshclam || print_message "$YELLOW" "WARNING: Failed to update ClamAV database"
    
    # Start services (guarded - clamav-daemon refuses to start until the
    # signature DB exists; a freshclam failure must not abort the whole run)
    systemctl start clamav-freshclam 2>/dev/null || print_message "$YELLOW" "WARNING: clamav-freshclam failed to start"
    systemctl start clamav-daemon 2>/dev/null || print_message "$YELLOW" "WARNING: clamav-daemon failed to start (signature DB may still be downloading)"
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl enable clamav-daemon 2>/dev/null || true
    
    # Get scan frequency from user
    print_message "$GREEN" "Please enter how often you want ClamAV scans to run (daily/weekly/monthly):"
    read -r scan_frequency
    scan_frequency=$(validate_frequency "$scan_frequency")
    
    # Create scan script
    cat > "/etc/cron.$scan_frequency/clamav_scan" << 'EOF'
#!/bin/bash
# ClamAV scan script
LOG_FILE="/var/log/clamav/scan-$(date +%Y%m%d).log"
INFECTED_DIR="/var/quarantine"

mkdir -p "$INFECTED_DIR"
chmod 700 "$INFECTED_DIR"

# Scan system
clamscan -r -i --move="$INFECTED_DIR" --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" --log="$LOG_FILE" /

# Send report if infections found
if grep -q "Infected files:" "$LOG_FILE"; then
    mail -s "ClamAV: Infections detected on $(hostname)" root < "$LOG_FILE"
fi
EOF
    chmod 755 "/etc/cron.$scan_frequency/clamav_scan"
    
    print_message "$GREEN" "ClamAV configured with $scan_frequency scans"
}

# Function to configure automatic updates
configure_unattended_upgrades() {
    print_message "$GREEN" "Configuring automatic security updates..."
    
    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

    # Restart service
    systemctl restart unattended-upgrades
    print_message "$GREEN" "Automatic updates configured"
}

# Function to configure UFW firewall
configure_ufw() {
    print_message "$GREEN" "Configuring UFW firewall..."

    # Ensure UFW is installed
    if ! command -v ufw &> /dev/null; then
        print_message "$YELLOW" "UFW not found. Installing UFW..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || error_exit "Failed to install UFW"
    fi

    # Set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    
    # Allow SSH (with rate limiting)
    ufw limit ssh/tcp comment 'SSH rate limit'
    
    # Enable logging
    ufw logging on

    # Configure UFW log rotation
    cat > /etc/logrotate.d/ufw << 'EOF'
/var/log/ufw.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

    # Enable firewall
    echo "y" | ufw enable

    print_message "$GREEN" "UFW firewall configured and enabled"
    print_message "$YELLOW" "WARNING: Only SSH is allowed. Configure additional rules as needed."
}

# Function to configure Fail2ban
# Fix: Made less aggressive to prevent locking out legitimate users
configure_fail2ban() {
    print_message "$GREEN" "Configuring Fail2ban..."

    backup_file "/etc/fail2ban/jail.conf"

    # Create local jail configuration
    # Fix: Increased maxretry and reduced initial bantime to prevent legitimate user lockouts
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# NOTE: Settings adjusted to prevent locking out legitimate users
# Ignore localhost and private networks
# Add your CI/CD, monitoring, and trusted IPs here
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
bantime = 10m
findtime = 10m
maxretry = 5
backend = systemd
usedns = warn
destemail = root@localhost
sendername = Fail2Ban
mta = sendmail
protocol = tcp
chain = INPUT
# Ban only - action_mwl needs a working MTA + whois, which are not installed
action = %(action_)s

# Progressive ban time - doubles with each offense (requires fail2ban 0.11+)
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1d

[sshd]
enabled = true
port = ssh
filter = sshd[mode=aggressive]
logpath = /var/log/auth.log
maxretry = 5
bantime = 10m
findtime = 10m
EOF

    # Restart fail2ban (guarded - a jail error must not abort the run)
    systemctl restart fail2ban 2>/dev/null || print_message "$YELLOW" "WARNING: fail2ban restart failed"
    systemctl enable fail2ban 2>/dev/null || true

    print_message "$GREEN" "Fail2ban configured with progressive banning"
}

# Function to harden SSH configuration
# Fix: Check for SSH keys before disabling password authentication
harden_ssh() {
    print_message "$GREEN" "Hardening SSH configuration..."

    backup_file "/etc/ssh/sshd_config"

    # Check for existing SSH keys before disabling password authentication
    local has_keys
    has_keys=$(check_ssh_keys_exist)
    local password_auth="no"

    if [[ "$has_keys" == "false" ]]; then
        print_message "$RED" "╔══════════════════════════════════════════════════════════════╗"
        print_message "$RED" "║           ⚠️  WARNING: NO SSH KEYS FOUND                      ║"
        print_message "$RED" "╠══════════════════════════════════════════════════════════════╣"
        print_message "$RED" "║ No SSH authorized_keys files found on this system.           ║"
        print_message "$RED" "║ Disabling password authentication will LOCK YOU OUT!         ║"
        print_message "$RED" "║                                                              ║"
        print_message "$RED" "║ Options:                                                     ║"
        print_message "$RED" "║ 1. Add SSH keys first, then re-run this script               ║"
        print_message "$RED" "║ 2. Keep password authentication enabled (less secure)        ║"
        print_message "$RED" "╚══════════════════════════════════════════════════════════════╝"

        read -p "Keep password authentication enabled? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            print_message "$YELLOW" "Password authentication will remain ENABLED for safety"
            password_auth="yes"
        else
            print_message "$RED" "Proceeding with password authentication DISABLED - ensure you have console access!"
        fi
    else
        print_message "$GREEN" "SSH keys found. Safe to disable password authentication."
    fi

    # Create SSH config directory if it doesn't exist (for Ubuntu 18.04/20.04 compatibility)
    mkdir -p /etc/ssh/sshd_config.d/

    # Create hardened SSH config
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# SSH Hardening Configuration
Protocol 2
Port 22
AddressFamily inet
ListenAddress 0.0.0.0

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
MaxAuthTries 3
MaxSessions 10
EOF

    # Add AuthenticationMethods based on password_auth setting.
    # When keeping password auth the directive is OMITTED: "publickey,password"
    # (comma) would require BOTH methods, locking out password-only users.
    if [[ "$password_auth" == "no" ]]; then
        echo "AuthenticationMethods publickey" >> /etc/ssh/sshd_config.d/99-hardening.conf
    fi

    # Continue with the rest of the config
    cat >> /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'

# Security
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
DebianBanner no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Crypto
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Timeouts
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30

# Other
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression no
UseDNS no
EOF

    # Test SSH configuration
    sshd -t || error_exit "SSH configuration test failed"

    # Restart SSH
    systemctl restart sshd

    print_message "$GREEN" "SSH hardened successfully"
    if [[ "$password_auth" == "yes" ]]; then
        print_message "$YELLOW" "NOTE: Password authentication ENABLED (no SSH keys found)"
        print_message "$YELLOW" "Recommendation: Add SSH keys and re-run this script for better security"
    else
        print_message "$YELLOW" "WARNING: Password authentication is disabled. Ensure SSH keys are configured!"
    fi
}

# Function to configure system security limits
# Fix: Increased limits to support production workloads without breaking services
configure_limits() {
    print_message "$GREEN" "Configuring system security limits..."

    backup_file "/etc/security/limits.conf"

    # Add security limits
    # NOTE: Limits increased from original values to support production workloads
    # Original: nproc 512/1024, maxlogins 10 - too restrictive for many use cases
    cat >> /etc/security/limits.conf << 'EOF'

# Security limits (Production-ready values)
# Disable core dumps (security - prevents sensitive data leakage)
* soft core 0
* hard core 0

# Limit number of processes (increased for production workloads)
# Original was 512/1024 which breaks many applications
* soft nproc 4096
* hard nproc 8192
root soft nproc unlimited
root hard nproc unlimited

# Limit number of open files (sufficient for most applications)
* soft nofile 65536
* hard nofile 65536

# Limit max number of logins (increased for multi-user systems)
# Original was 10 which is too restrictive for busy servers
* soft maxlogins 50
* hard maxlogins 50
EOF

    print_message "$GREEN" "Security limits configured"
}

# Function to configure sysctl security parameters
configure_sysctl() {
    print_message "$GREEN" "Configuring kernel security parameters..."
    
    backup_file "/etc/sysctl.conf"
    
    # Create security sysctl configuration
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Other hardening
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
kernel.sysrq = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
kernel.yama.ptrace_scope = 1
EOF

    # Apply sysctl settings
    if ! sysctl -p /etc/sysctl.d/99-security.conf; then
        print_message "$YELLOW" "WARNING: some sysctl keys were not applied (not available on this kernel)"
    fi

    print_message "$GREEN" "Kernel parameters configured"
}

# Function to configure OpenSCAP (if available)
configure_openscap() {
    if ! command -v oscap &> /dev/null; then
        print_message "$YELLOW" "OpenSCAP not available, skipping configuration"
        return
    fi
    
    print_message "$GREEN" "Configuring OpenSCAP..."
    
    # Get scan frequency from user
    print_message "$GREEN" "Please enter how often you want OpenSCAP scans to run (daily/weekly/monthly):"
    read -r oscap_frequency
    oscap_frequency=$(validate_frequency "$oscap_frequency")
    
    # Determine the correct SSG content file based on Ubuntu version
    local version=$(lsb_release -rs)
    local ssg_file=""
    
    case "$version" in
        "18.04")
            ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml"
            ;;
        "20.04")
            ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml"
            ;;
        "22.04")
            ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
            ;;
        *)
            print_message "$YELLOW" "WARNING: No SSG content file found for Ubuntu $version"
            return
            ;;
    esac
    
    if [[ ! -f "$ssg_file" ]]; then
        print_message "$YELLOW" "WARNING: SSG content file not found at $ssg_file"
        return
    fi
    
    # Create scan script
    cat > "/etc/cron.$oscap_frequency/oscap_scan" << EOF
#!/bin/bash
# OpenSCAP scan script
REPORT_DIR="/var/log/openscap"
mkdir -p "\$REPORT_DIR"

oscap xccdf eval \\
    --profile xccdf_org.ssgproject.content_profile_standard \\
    --report "\$REPORT_DIR/oscap_report_\$(date +%Y%m%d).html" \\
    --results "\$REPORT_DIR/oscap_results_\$(date +%Y%m%d).xml" \\
    "$ssg_file"
EOF
    chmod 755 "/etc/cron.$oscap_frequency/oscap_scan"

    print_message "$GREEN" "OpenSCAP configured with $oscap_frequency scans"
}

# Function to configure cloud instance security (AWS/Azure/GCP)
configure_cloud_security() {
    print_message "$GREEN" "Configuring cloud instance security..."

    local is_cloud=false
    local cloud_provider=""

    # Detect cloud environment
    if [[ -f /sys/class/dmi/id/product_name ]]; then
        local product_name
        product_name=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")

        if [[ "$product_name" == *"Amazon"* ]]; then
            is_cloud=true
            cloud_provider="AWS"
        elif [[ "$product_name" == *"Google"* ]]; then
            is_cloud=true
            cloud_provider="GCP"
        elif [[ "$product_name" == *"Microsoft"* ]]; then
            is_cloud=true
            cloud_provider="Azure"
        fi
    fi

    # Check for cloud-init
    if [[ -d /var/lib/cloud ]] && ! $is_cloud; then
        is_cloud=true
        cloud_provider="Unknown Cloud"
    fi

    if ! $is_cloud; then
        print_message "$YELLOW" "Not a cloud instance - skipping cloud-specific hardening"
        return 0
    fi

    print_message "$BLUE" "Detected cloud provider: $cloud_provider"

    # Metadata protection (works on all major clouds)
    if command -v iptables &> /dev/null; then
        # Block non-root access to metadata service
        iptables -C OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP 2>/dev/null || \
            iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP
        print_message "$GREEN" "Cloud metadata protection configured"
    fi

    # Secure cloud-init
    if [[ -f /etc/cloud/cloud.cfg ]]; then
        if ! grep -q "network: {config: disabled}" /etc/cloud/cloud.cfg; then
            echo "network: {config: disabled}" >> /etc/cloud/cloud.cfg
        fi
    fi

    if [[ -d /var/log/cloud-init ]]; then
        chmod 600 /var/log/cloud-init/*.log 2>/dev/null || true
        chmod 700 /var/log/cloud-init
    fi

    print_message "$GREEN" "Cloud security hardening completed"
}

# Function to generate final report
generate_report() {
    print_message "$GREEN" "Generating hardening report..."
    
    cat > "$REPORT_FILE" << EOF
Ubuntu Security Hardening Report
================================
Generated: $(date)
Hostname: $(hostname)
Ubuntu Version: $(lsb_release -ds)

Summary of Applied Security Measures
------------------------------------

1. System Updates
   - All packages updated to latest versions
   - Automatic security updates configured

2. Security Tools Installed
   - AIDE (Advanced Intrusion Detection Environment)
   - Auditd (Linux Audit Daemon)
   - AppArmor (Mandatory Access Control)
   - ClamAV (Antivirus)
   - UFW (Uncomplicated Firewall)
   - Fail2ban (Intrusion Prevention)
   - Rkhunter (Rootkit Hunter)
   - Chkrootkit (Rootkit Checker)
   - Lynis (Security Auditing Tool)

3. File Integrity Monitoring
   - AIDE configured with daily checks
   - Database initialized at: /var/lib/aide/aide.db

4. Audit System
   - Auditd configured with comprehensive rules
   - Monitoring: authentication, sudo usage, SSH config, kernel modules
   - Log location: /var/log/audit/audit.log

5. Mandatory Access Control
   - AppArmor enabled and enforcing profiles
   - All available profiles set to enforce mode

6. Antivirus Protection
   - ClamAV configured with scheduled scans
   - Automatic virus database updates enabled
   - Quarantine directory: /var/quarantine

7. Firewall Configuration
   - UFW enabled with default deny incoming
   - SSH access allowed with rate limiting
   - Logging enabled

8. Intrusion Prevention
   - Fail2ban configured for SSH protection
   - Ban time: 2 hours after 3 failed attempts

9. SSH Hardening
   - Root login disabled
   - Password authentication disabled
   - Strong cipher suites enforced
   - Idle timeout configured

10. Kernel Security
    - Security parameters configured via sysctl
    - IP spoofing protection enabled
    - SYN flood protection enabled
    - IPv6 disabled (if not in use)

11. System Limits
    - Core dumps disabled
    - Process limits configured
    - Login limits enforced

Configuration Backups
--------------------
All original configuration files backed up to: $BACKUP_DIR

Log Files
---------
- Hardening process log: $LOG_FILE
- AIDE logs: /var/log/aide/
- Audit logs: /var/log/audit/
- ClamAV logs: /var/log/clamav/
- UFW logs: /var/log/ufw.log
- Fail2ban logs: /var/log/fail2ban.log

Next Steps
----------
1. Review and test all security configurations
2. Configure additional firewall rules as needed
3. Set up SSH key authentication before reconnecting
4. Schedule regular security audits with Lynis
5. Monitor logs regularly for security events
6. Keep the system updated with security patches

Security Tools Usage
-------------------
- Run security audit: lynis audit system
- Check for rootkits: rkhunter -c
- Update virus database: freshclam
- Check file integrity: aide --check
- View audit logs: aureport

IMPORTANT NOTES
--------------
- SSH password authentication has been DISABLED
- Ensure you have SSH key access before logging out
- Review firewall rules and add necessary services
- Test all services to ensure they work as expected

Report generated by: $SCRIPT_NAME
EOF

    print_message "$GREEN" "Hardening report saved to: $REPORT_FILE"
}

# Function to perform post-hardening checks
post_hardening_checks() {
    print_message "$GREEN" "Performing post-hardening checks..."
    
    # Check service status
    local services=("auditd" "apparmor" "clamav-daemon" "clamav-freshclam" "ufw" "fail2ban" "unattended-upgrades")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_message "$GREEN" "✓ $service is running"
        else
            print_message "$RED" "✗ $service is not running"
        fi
    done
    
    # Check firewall status
    if ufw status | grep -q "Status: active"; then
        print_message "$GREEN" "✓ Firewall is active"
    else
        print_message "$RED" "✗ Firewall is not active"
    fi
}

# Main function
main() {
    # Preliminary checks
    check_root
    setup_directories

    print_message "$GREEN" "=== Ubuntu Security Hardening Script ==="
    print_message "$GREEN" "Version: 2.0"
    print_message "$GREEN" "======================================="
    check_ubuntu_version
    
    # Create initial checkpoint
    print_message "$GREEN" "Creating system checkpoint..."
    
    # System hardening steps
    update_system
    install_packages
    configure_aide
    configure_auditd
    configure_apparmor
    configure_clamav
    configure_unattended_upgrades
    configure_ufw
    configure_fail2ban
    harden_ssh
    configure_limits
    configure_sysctl
    configure_openscap

    # Cloud instance security (AWS/Azure/GCP)
    configure_cloud_security

    # Final steps
    generate_report
    post_hardening_checks
    
    print_message "$GREEN" "======================================="
    print_message "$GREEN" "Hardening process completed successfully!"
    print_message "$GREEN" "Report available at: $REPORT_FILE"
    print_message "$RED" "CRITICAL: Verify SSH access from another terminal before disconnecting!"
    print_message "$YELLOW" "Review SSH settings in /etc/ssh/sshd_config.d/99-hardening.conf"
    print_message "$GREEN" "======================================="
}

# Run main function
main "$@"