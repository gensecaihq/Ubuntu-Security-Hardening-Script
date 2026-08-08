#!/bin/bash
# Ubuntu 24.04 LTS Security Hardening Script - Production Grade
# Author: Aloke Majumder
# GitHub: https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script
# License: MIT License
# Version: 3.0
# Specifically optimized for Ubuntu 24.04 LTS (Noble Numbat)

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
readonly SCRIPT_VERSION="3.0"
readonly LOG_DIR="/var/log/security-hardening"
readonly LOG_FILE="${LOG_DIR}/hardening-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/var/backups/security-hardening"
readonly REPORT_FILE="${LOG_DIR}/hardening_report_$(date +%Y%m%d-%H%M%S).txt"
readonly UBUNTU_VERSION="24.04"

# Ubuntu 24.04 specific features
readonly SUPPORTS_DBUS_BROKER=true
readonly SUPPORTS_SYSTEMD_RESOLVED=true
readonly SUPPORTS_NETPLAN=true
readonly SUPPORTS_SNAP_STRICT_CONFINEMENT=true

# Function to print colored output with timestamp
print_message() {
    local color=$1
    local message=${2:-}
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}" | tee -a "$LOG_FILE"
}

# Function to handle errors gracefully
error_exit() {
    print_message "$RED" "ERROR: $1"
    cleanup_on_error
    exit 1
}

# Function to cleanup on error
cleanup_on_error() {
    print_message "$YELLOW" "Performing cleanup due to error..."
    # Add any necessary cleanup operations here
}

# Function to create necessary directories with proper permissions
setup_directories() {
    mkdir -p "$LOG_DIR" "$BACKUP_DIR"
    chmod 700 "$LOG_DIR" "$BACKUP_DIR"
    # Set proper SELinux context if available
    if command -v semanage &> /dev/null; then
        semanage fcontext -a -t admin_home_t "$LOG_DIR" 2>/dev/null || true
        semanage fcontext -a -t admin_home_t "$BACKUP_DIR" 2>/dev/null || true
        restorecon -R "$LOG_DIR" "$BACKUP_DIR" 2>/dev/null || true
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Function to verify Ubuntu 24.04 LTS
check_ubuntu_version() {
    if ! command -v lsb_release &> /dev/null; then
        error_exit "lsb_release not found. Is this Ubuntu?"
    fi

    local version=$(lsb_release -rs)
    local codename=$(lsb_release -cs)

    print_message "$GREEN" "Detected Ubuntu version: $version ($codename)"

    if [[ "$version" != "$UBUNTU_VERSION" ]]; then
        print_message "$YELLOW" "WARNING: This script is optimized for Ubuntu 24.04 LTS"
        print_message "$YELLOW" "Current version: $version"
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "User cancelled operation"
        fi
    fi
}

# Function to check system requirements
check_system_requirements() {
    print_message "$GREEN" "Checking system requirements..."

    # Check available disk space (minimum 2GB)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 2097152 ]]; then
        error_exit "Insufficient disk space. At least 2GB required."
    fi

    # Check memory (minimum 1GB)
    local total_memory=$(free -m | awk 'NR==2 {print $2}')
    if [[ $total_memory -lt 1024 ]]; then
        print_message "$YELLOW" "WARNING: Low memory detected. Some operations may be slow."
    fi

    # Check if running in container
    if systemd-detect-virt -c &>/dev/null; then
        print_message "$YELLOW" "WARNING: Running in a container. Some features may not work."
    fi
}

# Function to backup configuration files with metadata
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
        cp -p "$file" "$backup_name"
        # Save file permissions and ownership
        stat -c "%a %U:%G" "$file" > "${backup_name}.meta"
        print_message "$GREEN" "Backed up $file to $backup_name"
    fi
}

# Function to validate user input for frequency
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

# Function to update and upgrade packages with Ubuntu Pro integration
update_system() {
    print_message "$GREEN" "Updating package lists..."

    # Check for Ubuntu Pro status
    if command -v pro &> /dev/null; then
        print_message "$BLUE" "Checking Ubuntu Pro status..."
        pro status --format=json > "${LOG_DIR}/ubuntu-pro-status.json" 2>/dev/null || true
    fi

    # Update package lists
    apt-get update -y || error_exit "Failed to update package lists"

    # Upgrade packages
    print_message "$GREEN" "Upgrading installed packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || error_exit "Failed to upgrade packages"

    # Perform distribution upgrade if available
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || true
}

# Function to install required packages for Ubuntu 24.04
install_packages() {
    print_message "$GREEN" "Installing security tools and packages..."

    # Core security packages for Ubuntu 24.04
    local packages=(
        # File integrity and monitoring
        "aide"
        "aide-common"
        "tripwire"

        # Auditing and compliance
        "auditd"
        "audispd-plugins"
        "auditd-plugin-clickhouse"

        # System integrity
        "debsums"
        "apt-listchanges"
        "needrestart"
        "debsecan"

        # Access control
        "apparmor"
        "apparmor-utils"
        "apparmor-profiles"
        "apparmor-profiles-extra"
        "apparmor-notify"

        # Antivirus and malware detection
        "clamav"
        "clamav-daemon"
        "clamav-freshclam"
        "clamdscan"

        # Automatic updates
        "unattended-upgrades"
        "update-notifier-common"

        # Firewall
        "ufw"
        "gufw"

        # Intrusion detection/prevention
        "fail2ban"
        "fail2ban-systemd"
        "psad"
        "snort"

        # Rootkit detection
        "rkhunter"
        "chkrootkit"
        "unhide"

        # Security auditing
        "lynis"
        "tiger"
        "nmap"

        # Authentication and PAM
        "libpam-pwquality"
        "libpam-tmpdir"
        "libpam-apparmor"
        "libpam-cap"
        "libpam-modules-bin"
        "libpam-faillock"

        # Cryptography
        "cryptsetup"
        "cryptsetup-initramfs"
        "ecryptfs-utils"

        # SELinux tools (optional but recommended)
        "selinux-utils"
        "selinux-policy-default"

        # Network security
        "arpwatch"
        "net-tools"
        "iftop"
        "tcpdump"

        # System monitoring
        "sysstat"
        "acct"
        "aide-dynamic"

        # Ubuntu 24.04 specific
        "ubuntu-advantage-tools"
        "systemd-oomd"
        "systemd-homed"
    )

    # Install OpenSCAP for Ubuntu 24.04
    packages+=("libopenscap8" "openscap-scanner" "openscap-utils" "scap-security-guide")

    # Install packages with error handling
    for package in "${packages[@]}"; do
        print_message "$GREEN" "Installing $package..."
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" 2>/dev/null; then
            print_message "$YELLOW" "WARNING: Failed to install $package (may not be available)"
        fi
    done

    # Enable additional Ubuntu Pro features if available
    if command -v pro &> /dev/null && pro status | grep -q "entitled"; then
        print_message "$BLUE" "Enabling Ubuntu Pro security features..."
        pro enable usg || true
        pro enable cis || true
    fi
}

# Function to configure AIDE with Ubuntu 24.04 optimizations
configure_aide() {
    print_message "$GREEN" "Configuring AIDE file integrity checker..."

    backup_file "/etc/aide/aide.conf"

    # Configure AIDE for Ubuntu 24.04
    cat >> /etc/aide/aide.conf << 'EOF'

# Ubuntu 24.04 specific exclusions
!/snap/
!/var/snap/
!/var/lib/snapd/
!/run/snapd/
!/sys/
!/proc/
!/dev/
!/run/
!/var/lib/docker/
!/var/lib/containerd/
!/var/lib/lxc/
!/var/lib/lxd/
EOF

    # Initialize AIDE database
    print_message "$GREEN" "Initializing AIDE database (this may take several minutes)..."
    aideinit || error_exit "Failed to initialize AIDE"

    # Move database to production location
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        chmod 600 /var/lib/aide/aide.db
        print_message "$GREEN" "AIDE database initialized successfully"
    fi

    # Create systemd timer for AIDE checks (Ubuntu 24.04 preferred method)
    cat > /etc/systemd/system/aide-check.service << 'EOF'
[Unit]
Description=AIDE File Integrity Check
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aide
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    cat > /etc/systemd/system/aide-check.timer << 'EOF'
[Unit]
Description=Run AIDE check daily
Requires=aide-check.service

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable aide-check.timer
    systemctl start aide-check.timer
}

# Function to configure Auditd with Ubuntu 24.04 enhancements
configure_auditd() {
    print_message "$GREEN" "Configuring auditd with Ubuntu 24.04 optimizations..."

    backup_file "/etc/audit/auditd.conf"
    backup_file "/etc/audit/rules.d/audit.rules"

    # Configure auditd for Ubuntu 24.04
    cat > /etc/audit/auditd.conf << 'EOF'
# Ubuntu 24.04 Optimized Audit Configuration
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
distribute_network = no
q_depth = 1200
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
end_of_event_timeout = 2
EOF

    # Create comprehensive audit rules for Ubuntu 24.04
    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Ubuntu 24.04 Security Audit Rules
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor systemd
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# Monitor snap changes (Ubuntu specific)
-w /snap/bin/ -p wa -k snap_changes
-w /var/lib/snapd/ -p wa -k snap_changes

# Monitor AppArmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/apparmor/ -p wa -k apparmor

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module -k module_insertion
-a always,exit -F arch=b64 -S delete_module -k module_deletion

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/netplan/ -p wa -k network_config

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# ============================================
# LOTL (Living Off The Land) Detection Rules
# ============================================

# Monitor commonly abused binaries for data exfiltration
-w /usr/bin/wget -p x -k lotl_download
-w /usr/bin/curl -p x -k lotl_download
-w /usr/bin/scp -p x -k lotl_transfer
-w /usr/bin/sftp -p x -k lotl_transfer
-w /usr/bin/rsync -p x -k lotl_transfer
-w /usr/bin/ftp -p x -k lotl_transfer

# Monitor encoding/decoding tools (often used to obfuscate)
-w /usr/bin/base64 -p x -k lotl_encoding
-w /usr/bin/xxd -p x -k lotl_encoding
-w /usr/bin/uuencode -p x -k lotl_encoding
-w /usr/bin/uudecode -p x -k lotl_encoding

# Monitor network reconnaissance tools
-w /usr/bin/nc -p x -k lotl_netcat
-w /usr/bin/ncat -p x -k lotl_netcat
-w /usr/bin/netcat -p x -k lotl_netcat
-w /usr/bin/nmap -p x -k lotl_recon
-w /usr/bin/tcpdump -p x -k lotl_capture
-w /usr/bin/tshark -p x -k lotl_capture
-w /usr/sbin/tcpdump -p x -k lotl_capture

# Monitor compilers and interpreters (often used in attacks)
-w /usr/bin/gcc -p x -k lotl_compile
-w /usr/bin/g++ -p x -k lotl_compile
-w /usr/bin/make -p x -k lotl_compile
-w /usr/bin/python -p x -k lotl_scripting
-w /usr/bin/python3 -p x -k lotl_scripting
-w /usr/bin/perl -p x -k lotl_scripting
-w /usr/bin/ruby -p x -k lotl_scripting

# Monitor reverse shell / tunneling tools
-w /usr/bin/socat -p x -k lotl_tunnel
-w /usr/bin/ssh -p x -k lotl_ssh
-w /usr/bin/openssl -p x -k lotl_crypto

# Monitor file manipulation that could indicate data staging
-w /usr/bin/tar -p x -k lotl_archive
-w /usr/bin/gzip -p x -k lotl_archive
-w /usr/bin/zip -p x -k lotl_archive
-w /usr/bin/7z -p x -k lotl_archive

# Monitor package managers (could be used to install backdoors)
-w /usr/bin/apt -p x -k lotl_package
-w /usr/bin/apt-get -p x -k lotl_package
-w /usr/bin/dpkg -p x -k lotl_package
-w /snap/bin -p x -k lotl_snap

# Container escape detection
-a always,exit -F arch=b64 -S unshare -k container_escape
-a always,exit -F arch=b64 -S setns -k container_escape
-a always,exit -F arch=b32 -S unshare -k container_escape
-a always,exit -F arch=b32 -S setns -k container_escape

# Privilege escalation detection - commands run as root by non-root users
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_escalation
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_escalation

# Detect suspicious process injection
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b32 -S ptrace -k process_injection

# Monitor /tmp and /dev/shm for executable activity (common attack staging)
-w /tmp -p x -k tmp_exec
-w /dev/shm -p x -k shm_exec
-w /var/tmp -p x -k vartmp_exec

# Make configuration immutable
-e 2
EOF

    # Load rules and restart auditd
    augenrules --load
    systemctl restart auditd
    systemctl enable auditd

    # Configure audit log rotation
    cat > /etc/logrotate.d/audit << 'EOF'
/var/log/audit/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s USR1 auditd.service >/dev/null 2>&1 || true
    endscript
}
EOF
}

# Function to configure AppArmor with Ubuntu 24.04 profiles
# Fix for Issue #12: Desktop environment detection to prevent breaking GUI apps
configure_apparmor() {
    print_message "$GREEN" "Configuring AppArmor with Ubuntu 24.04 profiles..."

    # Detect if running on desktop environment
    local is_desktop
    is_desktop=$(detect_desktop_environment)

    # Ensure AppArmor is enabled
    systemctl enable apparmor
    systemctl start apparmor

    # Set kernel parameter
    if ! grep -q "apparmor=1" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
        update-grub
    fi

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

        # Enable all profiles
        find /etc/apparmor.d -maxdepth 1 -type f -exec aa-enforce {} \; 2>/dev/null || true

        print_message "$GREEN" "AppArmor profiles enforced"
    fi

    # Configure snap confinement (Ubuntu 24.04 specific)
    if command -v snap &> /dev/null; then
        print_message "$BLUE" "Configuring strict snap confinement..."
        snap set system experimental.parallel-instances=true 2>/dev/null || true
    fi
}

# Function to configure ClamAV with Ubuntu 24.04 optimizations
configure_clamav() {
    print_message "$GREEN" "Configuring ClamAV with performance optimizations..."

    # Configure ClamAV for Ubuntu 24.04
    backup_file "/etc/clamav/clamd.conf"
    backup_file "/etc/clamav/freshclam.conf"

    # Optimize ClamAV configuration
    cat >> /etc/clamav/clamd.conf << 'EOF'

# Ubuntu 24.04 Optimizations
MaxThreads 4
MaxDirectoryRecursion 20
FollowDirectorySymlinks false
FollowFileSymlinks false
CrossFilesystems false
ScanPE true
ScanELF true
DetectBrokenExecutables true
ScanOLE2 true
ScanPDF true
ScanSWF true
ScanHTML true
ScanXMLDOCS true
ScanHWP3 true
ScanArchive true
MaxScanTime 300000
MaxScanSize 400M
MaxFileSize 100M
MaxRecursion 16
MaxFiles 10000
EOF

    # Configure freshclam for automatic updates
    sed -i 's/^Checks.*/Checks 24/' /etc/clamav/freshclam.conf 2>/dev/null || true

    # Stop services for configuration
    systemctl stop clamav-freshclam 2>/dev/null || true
    systemctl stop clamav-daemon 2>/dev/null || true

    # Update virus database
    print_message "$GREEN" "Updating ClamAV virus database..."
    freshclam || print_message "$YELLOW" "WARNING: Failed to update ClamAV database"

    # Start and enable services (guarded - clamav-daemon refuses to start
    # until the signature DB exists; must not abort the whole run)
    systemctl start clamav-freshclam 2>/dev/null || print_message "$YELLOW" "WARNING: clamav-freshclam failed to start"
    systemctl start clamav-daemon 2>/dev/null || print_message "$YELLOW" "WARNING: clamav-daemon failed to start (signature DB may still be downloading)"
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl enable clamav-daemon 2>/dev/null || true

    # Get scan frequency
    print_message "$GREEN" "Please enter how often you want ClamAV scans to run (daily/weekly/monthly):"
    read -r scan_frequency
    scan_frequency=$(validate_frequency "$scan_frequency")

    # Create systemd timer for scans (Ubuntu 24.04 preferred)
    cat > /etc/systemd/system/clamav-scan.service << 'EOF'
[Unit]
Description=ClamAV Virus Scan
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/clamav-scan.sh
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    # Create scan script
    cat > /usr/local/bin/clamav-scan.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/clamav/scan-$(date +%Y%m%d-%H%M%S).log"
INFECTED_DIR="/var/quarantine"

mkdir -p "$INFECTED_DIR"
chmod 700 "$INFECTED_DIR"

# Exclude virtual filesystems and large directories
EXCLUDE_DIRS="--exclude-dir=^/sys --exclude-dir=^/proc --exclude-dir=^/dev --exclude-dir=^/run --exclude-dir=^/snap --exclude-dir=^/var/lib/docker --exclude-dir=^/var/lib/containerd"

# Scan with optimized settings
nice -n 19 ionice -c 3 clamscan -r -i \
    --move="$INFECTED_DIR" \
    $EXCLUDE_DIRS \
    --max-filesize=100M \
    --max-scansize=400M \
    --max-recursion=16 \
    --max-dir-recursion=20 \
    --log="$LOG_FILE" \
    / 2>/dev/null

# Send notification if infections found
if grep -q "Infected files:" "$LOG_FILE" && grep -q "Infected files: [1-9]" "$LOG_FILE"; then
    # Use systemd journal for notifications
    echo "ClamAV: Infections detected on $(hostname)" | systemd-cat -t clamav -p err
    # Send email if mail is configured
    if command -v mail &>/dev/null; then
        mail -s "ClamAV: Infections detected on $(hostname)" root < "$LOG_FILE"
    fi
fi
EOF
    chmod 755 /usr/local/bin/clamav-scan.sh

    # Create timer based on frequency
    case "$scan_frequency" in
        daily)
            timer_schedule="daily"
            ;;
        weekly)
            timer_schedule="weekly"
            ;;
        monthly)
            timer_schedule="monthly"
            ;;
        *)
            timer_schedule="weekly"
            ;;
    esac

    cat > /etc/systemd/system/clamav-scan.timer << EOF
[Unit]
Description=Run ClamAV scan $scan_frequency
Requires=clamav-scan.service

[Timer]
OnCalendar=$timer_schedule
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable clamav-scan.timer
    systemctl start clamav-scan.timer

    print_message "$GREEN" "ClamAV configured with $scan_frequency scans"
}

# Function to configure automatic updates for Ubuntu 24.04
configure_unattended_upgrades() {
    print_message "$GREEN" "Configuring automatic security updates for Ubuntu 24.04..."

    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"

    # Configure unattended-upgrades for Ubuntu 24.04
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Ubuntu 24.04 Automatic Updates Configuration
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
        "${distro_id}:${distro_codename}-updates";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
        "${distro_id}:${distro_codename}-proposed";
};

// Automatically fix interrupted dpkg
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Do automatic removal of unused packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot if required
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Keep updated packages
Unattended-Upgrade::Keep-Debs-After-Install "false";

// Email notifications
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";

// Do upgrade in minimal steps
Unattended-Upgrade::MinimalSteps "true";

// Set download speed limit (KB/s)
// Acquire::http::Dl-Limit "70";

// Set package blacklist
Unattended-Upgrade::Package-Blacklist {
    // "package1";
    // "package2";
};

// Ubuntu 24.04 specific - enable Livepatch if available
Unattended-Upgrade::DevRelease "auto";
EOF

    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Verbose "1";
EOF

    # Enable update-notifier for desktop systems
    if dpkg -l | grep -q "update-notifier"; then
        cat > /etc/apt/apt.conf.d/99update-notifier << 'EOF'
DPkg::Post-Invoke { "if [ -d /var/lib/update-notifier ]; then touch /var/lib/update-notifier/dpkg-run-stamp; fi"; };
EOF
    fi

    # Configure needrestart for automatic service restarts
    if command -v needrestart &> /dev/null; then
        cat > /etc/needrestart/conf.d/auto.conf << 'EOF'
# Automatically restart services
$nrconf{restart} = 'a';
# Disable kernel checks (we handle reboots separately)
$nrconf{kernelhints} = 0;
EOF
    fi

    systemctl restart unattended-upgrades
    systemctl enable unattended-upgrades
}

# Function to configure UFW with Ubuntu 24.04 enhancements
configure_ufw() {
    print_message "$GREEN" "Configuring UFW firewall with IPv6 support..."

    # Ensure UFW is installed
    if ! command -v ufw &> /dev/null; then
        print_message "$YELLOW" "UFW not found. Installing UFW..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || error_exit "Failed to install UFW"
    fi

    backup_file "/etc/default/ufw"

    # Enable IPv6 support
    sed -i 's/IPV6=.*/IPV6=yes/' /etc/default/ufw

    # Reset firewall to defaults
    ufw --force reset

    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed

    # Configure logging
    ufw logging on
    ufw logging medium

    # Configure UFW log rotation (Fix for Issue #2)
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

    # Basic rules with rate limiting
    ufw limit 22/tcp comment 'SSH rate limit'

    # Allow DHCP client (important for cloud instances)
    ufw allow 68/udp comment 'DHCP client'

    # Enable firewall
    echo "y" | ufw enable

    # Save firewall rules with netfilter-persistent (if available)
    # Note: iptables-persistent removed to avoid conflicts with UFW (Fix for Issue #4)
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
        systemctl enable netfilter-persistent
    fi

    print_message "$GREEN" "UFW firewall configured and enabled"
    print_message "$YELLOW" "NOTE: Only SSH (rate-limited) and DHCP are allowed"
}

# Function to configure Fail2ban with Ubuntu 24.04 optimizations
# Fix: Made less aggressive to prevent locking out legitimate users
configure_fail2ban() {
    print_message "$GREEN" "Configuring Fail2ban with systemd integration..."

    backup_file "/etc/fail2ban/jail.conf"

    # Create jail.local with Ubuntu 24.04 optimizations
    # Fix: Increased maxretry and reduced initial bantime to prevent legitimate user lockouts
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ubuntu 24.04 Fail2ban Configuration
# NOTE: Settings adjusted to prevent locking out legitimate users
bantime  = 10m
findtime  = 10m
maxretry = 5
backend = systemd
usedns = warn
logencoding = utf-8
enabled = false
mode = normal
filter = %(__name__)s[mode=%(mode)s]

# Progressive ban time - doubles with each offense (requires fail2ban 0.11+)
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1d

# Destination email
destemail = root@localhost
sender = root@localhost
mta = sendmail

# Action: ban only - action_mwl needs a working MTA + whois, which are not installed
action = %(action_)s

# Ignore localhost and private networks
# Add your CI/CD, monitoring, and trusted IPs here
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
mode = aggressive
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 5
bantime = 10m
findtime = 10m

# Protect against port scanning (UFW BLOCK lines from the kernel journal;
# backend=systemd is inherited from DEFAULT so no logpath is needed)
[port-scan]
enabled = true
filter = port-scan
journalmatch = _TRANSPORT=kernel
maxretry = 2
bantime = 1d
findtime = 1d

# Additional jails for common services
[apache-auth]
enabled = false
port = http,https
logpath = %(apache_error_log)s

[nginx-http-auth]
enabled = false
port = http,https
logpath = %(nginx_error_log)s

[postfix]
enabled = false
mode = aggressive
port = smtp,465,submission
logpath = %(postfix_log)s
backend = %(postfix_backend)s
EOF

    # Create custom filters
    mkdir -p /etc/fail2ban/filter.d

    # Port scan filter
    cat > /etc/fail2ban/filter.d/port-scan.conf << 'EOF'
[Definition]
failregex = .*UFW BLOCK.* SRC=<HOST>
ignoreregex =
EOF

    # Restart fail2ban (guarded - a jail error must not abort the run)
    systemctl restart fail2ban 2>/dev/null || print_message "$YELLOW" "WARNING: fail2ban restart failed"
    systemctl enable fail2ban

    print_message "$GREEN" "Fail2ban configured with systemd integration"
}

# Function to harden SSH for Ubuntu 24.04
# Fix: Check for SSH keys before disabling password authentication
harden_ssh() {
    print_message "$GREEN" "Hardening SSH configuration for Ubuntu 24.04..."

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

    # Create hardened SSH config using Include directive (Ubuntu 24.04 style)
    mkdir -p /etc/ssh/sshd_config.d/
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# Ubuntu 24.04 SSH Hardening Configuration
# Protocol and Network
Protocol 2
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Host Keys (Ubuntu 24.04 defaults)
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
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

    # Continue with the rest of the config (using heredoc with literal content)
    cat >> /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'

# Security Features
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
IgnoreUserKnownHosts yes

# Forwarding Options
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitUserRC no
GatewayPorts no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Crypto (Ubuntu 24.04 strong defaults)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Connection Settings
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30s
MaxStartups 10:30:60
TCPKeepAlive yes
Compression no
UseDNS no

# Misc Security
PermitUserEnvironment no
DebianBanner no
VersionAddendum none
PrintMotd no
PrintLastLog yes
PidFile /run/sshd.pid
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# Ubuntu 24.04 - Restrict users/groups (customize as needed)
# AllowUsers user1 user2
# AllowGroups sshusers
# DenyUsers nobody
# DenyGroups nogroup

# ============================================
# SSH Certificate Authentication (Optional)
# ============================================
# To enable SSH certificates, create a CA and configure:
# TrustedUserCAKeys /etc/ssh/ca.pub
# AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
# HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub

# ============================================
# FIDO2/WebAuthn Security Key Support
# ============================================
# Requires OpenSSH 8.2+ (Ubuntu 24.04 has 9.x)
# Add to PubkeyAcceptedAlgorithms if using FIDO2 keys:
PubkeyAcceptedAlgorithms +sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
EOF

    # Create SSH certificate helper documentation
    mkdir -p /etc/ssh/auth_principals
    cat > /etc/ssh/ssh-certificates-setup.md << 'CERTDOC'
# SSH Certificate Authentication Setup Guide

## Creating a Certificate Authority (CA)

1. Generate CA key pair (do this on a secure system):
   ```bash
   ssh-keygen -t ed25519 -f /path/to/ca -C "SSH CA"
   ```

2. Copy ca.pub to the server:
   ```bash
   sudo cp ca.pub /etc/ssh/ca.pub
   ```

3. Enable CA in sshd_config:
   ```
   TrustedUserCAKeys /etc/ssh/ca.pub
   ```

## Signing User Keys

Sign a user's public key:
```bash
ssh-keygen -s /path/to/ca -I user@hostname -n username -V +52w id_ed25519.pub
```

## FIDO2 Security Keys

Generate a FIDO2-backed SSH key:
```bash
# Resident key (stored on device, portable)
ssh-keygen -t ed25519-sk -O resident -O verify-required

# Non-resident key (handle stored on disk)
ssh-keygen -t ed25519-sk
```

Benefits:
- Keys never leave the hardware security key
- Requires physical touch for each authentication
- Optional PIN verification
- Phishing resistant
CERTDOC

    # Test configuration
    sshd -t || error_exit "SSH configuration test failed"

    # Create SSH banner
    cat > /etc/issue.net << 'EOF'
********************************************************************************
*                            AUTHORIZED ACCESS ONLY                            *
* Unauthorized access to this system is forbidden and will be prosecuted by    *
* law. By accessing this system, you consent to monitoring and recording.      *
********************************************************************************
EOF

    # Update main sshd_config to use banner
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config.d/99-hardening.conf

    # Restart SSH service (Ubuntu 24.04 uses socket activation)
    systemctl restart ssh.socket

    print_message "$GREEN" "SSH hardened successfully"
    if [[ "$password_auth" == "no" ]]; then
        print_message "$YELLOW" "WARNING: Password authentication is disabled. Ensure SSH keys are configured!"
    else
        print_message "$YELLOW" "NOTE: Password authentication is still enabled. Add SSH keys and re-run for better security."
    fi
}

# Function to configure system limits for Ubuntu 24.04
# Fix: Increased limits to prevent service denial on production systems
configure_limits() {
    print_message "$GREEN" "Configuring system security limits..."

    backup_file "/etc/security/limits.conf"

    # Add security limits
    # Fix: Increased process and login limits for production workloads
    cat >> /etc/security/limits.conf << 'EOF'

# Ubuntu 24.04 Security Limits
# NOTE: Limits increased to support production workloads (web servers, databases, CI/CD)

# Disable core dumps (security measure)
* soft core 0
* hard core 0

# Limit number of processes (increased for server workloads)
* soft nproc 4096
* hard nproc 8192
root soft nproc unlimited
root hard nproc unlimited

# Limit number of open files (increased for databases and web servers)
* soft nofile 65536
* hard nofile 65536

# Limit max locked memory (increased for databases)
* soft memlock 64
* hard memlock 128

# Limit max address space
* soft as unlimited
* hard as unlimited

# Limit max file size
* soft fsize unlimited
* hard fsize unlimited

# Limit max cpu time
* soft cpu unlimited
* hard cpu unlimited

# Limit max number of logins (increased for multi-user systems)
* soft maxlogins 50
* hard maxlogins 50

# Limit priority
* soft priority 0
* hard priority 0

# Limit max number of system logins
* soft maxsyslogins 50
* hard maxsyslogins 50
EOF

    # Configure systemd limits (increased to match limits.conf)
    mkdir -p /etc/systemd/system.conf.d/
    cat > /etc/systemd/system.conf.d/99-limits.conf << 'EOF'
[Manager]
# Ubuntu 24.04 Systemd Limits (increased for production workloads)
DefaultLimitCORE=0
DefaultLimitNOFILE=65536:65536
DefaultLimitNPROC=4096:8192
DefaultLimitMEMLOCK=128M
DefaultTasksMax=4096
EOF

    # Reload systemd
    systemctl daemon-reload

    print_message "$GREEN" "System limits configured for production workloads"
}

# Function to configure kernel parameters for Ubuntu 24.04
configure_sysctl() {
    print_message "$GREEN" "Configuring kernel security parameters for Ubuntu 24.04..."

    backup_file "/etc/sysctl.conf"

    # Create comprehensive sysctl security configuration
    cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
# Ubuntu 24.04 Kernel Security Hardening

### Network Security ###

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# TCP timestamps stay enabled (disabling breaks PAWS; uptime leak moot since kernel 4.10)
net.ipv4.tcp_timestamps = 1

# Enable TCP RFC 1337
net.ipv4.tcp_rfc1337 = 1

# Secure ICMP
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# ARP security
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

### Kernel Security ###

# Enable ExecShield (if available)
# kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 2

# Disable kexec
kernel.kexec_load_disabled = 1

# Harden BPF JIT
net.core.bpf_jit_harden = 2

# Restrict performance events
kernel.perf_event_paranoid = 3

# Disable SysRq
kernel.sysrq = 0

# Restrict core dumps
fs.suid_dumpable = 0

# Protect hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2

# ASLR
kernel.randomize_va_space = 2

# Restrict unprivileged userns
kernel.unprivileged_userns_clone = 0

# Ubuntu 24.04 specific
kernel.unprivileged_bpf_disabled = 1
# net.core.bpf_jit_enable = 0
# kernel.modules_disabled = 0
kernel.io_uring_disabled = 2

### IPv6 Security (disable if not needed) ###
# Uncomment to disable IPv6
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
# net.ipv6.conf.lo.disable_ipv6 = 1

### Performance and Resource Protection ###
vm.swappiness = 10
vm.vfs_cache_pressure = 50
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fastopen = 3

# Increase system file limits
fs.file-max = 65536

# Restrict access to kernel logs
kernel.printk = 3 3 3 3
EOF

    # Apply sysctl settings
    if ! sysctl -p /etc/sysctl.d/99-security-hardening.conf; then
        print_message "$YELLOW" "WARNING: some sysctl keys were not applied (not available on this kernel)"
    fi

    print_message "$GREEN" "Kernel parameters configured"
}

# Function to configure kernel lockdown mode
configure_kernel_lockdown() {
    print_message "$GREEN" "Configuring kernel lockdown mode..."

    # Check if lockdown is already enabled
    if [[ -f /sys/kernel/security/lockdown ]]; then
        local current_lockdown
        current_lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -oP '\[\K[^\]]+')
        if [[ "$current_lockdown" == "integrity" ]] || [[ "$current_lockdown" == "confidentiality" ]]; then
            print_message "$GREEN" "Kernel lockdown already enabled: $current_lockdown"
            return 0
        fi
    fi

    # Check if Secure Boot is enabled (lockdown is often auto-enabled with Secure Boot)
    local secure_boot_enabled=false
    if command -v mokutil &> /dev/null; then
        if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
            secure_boot_enabled=true
            print_message "$BLUE" "Secure Boot is enabled - kernel lockdown may be auto-enabled"
        fi
    fi

    # Configure kernel lockdown in GRUB
    if [[ -f /etc/default/grub ]]; then
        # Backup GRUB config
        cp /etc/default/grub "$BACKUP_DIR/grub.backup"

        # Check if lockdown parameter already exists
        if ! grep -q "lockdown=" /etc/default/grub; then
            print_message "$BLUE" "Adding kernel lockdown=integrity to GRUB..."

            # Add lockdown=integrity to GRUB_CMDLINE_LINUX_DEFAULT
            if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub; then
                sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 lockdown=integrity"/' /etc/default/grub
            else
                echo 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lockdown=integrity"' >> /etc/default/grub
            fi

            # Update GRUB
            if command -v update-grub &> /dev/null; then
                update-grub
                print_message "$GREEN" "GRUB updated with kernel lockdown=integrity"
                print_message "$YELLOW" "NOTE: Reboot required to enable kernel lockdown"
            fi
        else
            print_message "$YELLOW" "Kernel lockdown parameter already configured in GRUB"
        fi
    fi

    # Create documentation about lockdown modes
    cat > /etc/security/kernel-lockdown.info << 'EOF'
Kernel Lockdown Mode Information
================================

Kernel lockdown restricts access to kernel features that could allow
arbitrary code execution or modification of kernel memory.

Modes:
------
- none: No restrictions (default without Secure Boot)
- integrity: Blocks features that allow userspace to modify kernel
  - Loading unsigned kernel modules
  - Accessing /dev/mem and /dev/kmem
  - Writing to MSRs
  - Using kexec with unsigned images

- confidentiality: integrity + blocks extracting kernel secrets
  - Reading kernel memory via /proc/kallsyms
  - Using perf in some modes
  - BPF read of kernel memory

Current Status: Check with 'cat /sys/kernel/security/lockdown'

To change mode: Add 'lockdown=integrity' or 'lockdown=confidentiality'
to kernel parameters in /etc/default/grub and run update-grub

WARNING: Some debugging tools and features may not work with lockdown enabled
EOF

    print_message "$GREEN" "Kernel lockdown configuration completed"
}

# Function to configure OpenSCAP for Ubuntu 24.04
configure_openscap() {
    if ! command -v oscap &> /dev/null; then
        print_message "$YELLOW" "OpenSCAP not available, skipping configuration"
        return
    fi

    print_message "$GREEN" "Configuring OpenSCAP for Ubuntu 24.04..."

    # Get scan frequency
    print_message "$GREEN" "Please enter how often you want OpenSCAP scans to run (daily/weekly/monthly):"
    read -r oscap_frequency
    oscap_frequency=$(validate_frequency "$oscap_frequency")

    # Find the appropriate SCAP content
    local ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
    if [[ ! -f "$ssg_file" ]]; then
        # Try alternative location
        ssg_file="/usr/share/openscap/ssg/ssg-ubuntu2204-ds.xml"
    fi

    if [[ ! -f "$ssg_file" ]]; then
        print_message "$YELLOW" "WARNING: SCAP Security Guide content not found"
        return
    fi

    # Create enhanced scan script with profile selection
    cat > /usr/local/bin/openscap-scan.sh << EOF
#!/bin/bash
# OpenSCAP Security Compliance Scan for Ubuntu 24.04
# Supports CIS Benchmarks and DISA STIG profiles

REPORT_DIR="/var/log/openscap"
mkdir -p "\$REPORT_DIR"
TIMESTAMP=\$(date +%Y%m%d-%H%M%S)

# Profile selection (change as needed)
# CIS Profiles:
#   xccdf_org.ssgproject.content_profile_cis_level1_server
#   xccdf_org.ssgproject.content_profile_cis_level2_server
# DISA STIG Profile:
#   xccdf_org.ssgproject.content_profile_stig
# Other:
#   xccdf_org.ssgproject.content_profile_standard
#   xccdf_org.ssgproject.content_profile_pci-dss

PROFILE="\${OSCAP_PROFILE:-xccdf_org.ssgproject.content_profile_cis_level1_server}"

echo "Running OpenSCAP scan with profile: \$PROFILE"
echo "Timestamp: \$TIMESTAMP"

# Run compliance scan
oscap xccdf eval \\
    --profile "\$PROFILE" \\
    --report "\$REPORT_DIR/report_\${TIMESTAMP}.html" \\
    --results "\$REPORT_DIR/results_\${TIMESTAMP}.xml" \\
    --oval-results \\
    "$ssg_file" 2>&1 | tee "\$REPORT_DIR/scan_\${TIMESTAMP}.log"

# Store exit code
SCAN_RESULT=\$?

# Generate remediation script
oscap xccdf generate fix \\
    --profile "\$PROFILE" \\
    --output "\$REPORT_DIR/remediation_\${TIMESTAMP}.sh" \\
    "\$REPORT_DIR/results_\${TIMESTAMP}.xml" 2>/dev/null

# Generate summary
echo ""
echo "=== Scan Summary ==="
echo "Profile: \$PROFILE"
echo "Report: \$REPORT_DIR/report_\${TIMESTAMP}.html"
echo "Results: \$REPORT_DIR/results_\${TIMESTAMP}.xml"
echo "Remediation: \$REPORT_DIR/remediation_\${TIMESTAMP}.sh"

exit \$SCAN_RESULT
EOF
    chmod 755 /usr/local/bin/openscap-scan.sh

    # Create systemd timer
    cat > /etc/systemd/system/openscap-scan.service << 'EOF'
[Unit]
Description=OpenSCAP Security Compliance Scan
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openscap-scan.sh
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    # Configure timer based on frequency
    case "$oscap_frequency" in
        daily)
            timer_schedule="daily"
            ;;
        weekly)
            timer_schedule="weekly"
            ;;
        monthly)
            timer_schedule="monthly"
            ;;
        *)
            timer_schedule="weekly"
            ;;
    esac

    cat > /etc/systemd/system/openscap-scan.timer << EOF
[Unit]
Description=Run OpenSCAP scan $oscap_frequency
Requires=openscap-scan.service

[Timer]
OnCalendar=$timer_schedule
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable openscap-scan.timer
    systemctl start openscap-scan.timer

    print_message "$GREEN" "OpenSCAP configured with $oscap_frequency scans"
}

# Function to configure additional Ubuntu 24.04 security features
configure_ubuntu_24_features() {
    print_message "$GREEN" "Configuring Ubuntu 24.04 specific security features..."

    # Configure systemd security features
    print_message "$BLUE" "Configuring systemd security features..."

    # Enable systemd-oomd (Out of Memory Daemon)
    if systemctl list-unit-files | grep -q systemd-oomd; then
        systemctl enable systemd-oomd
        systemctl start systemd-oomd
    fi

    # Configure enhanced systemd service sandboxing
    print_message "$BLUE" "Applying enhanced systemd service sandboxing..."

    # NOTE: no sandbox drop-in for ssh.service - sshd spawns user sessions
    # that inherit ProtectSystem/ProtectHome/NoNewPrivileges, which gives
    # users a read-only filesystem and breaks sudo/su/passwd.

    # Fail2ban service hardening
    mkdir -p /etc/systemd/system/fail2ban.service.d/
    cat > /etc/systemd/system/fail2ban.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_AUDIT_READ CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW
EOF

    # ClamAV service hardening
    mkdir -p /etc/systemd/system/clamav-daemon.service.d/
    cat > /etc/systemd/system/clamav-daemon.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictRealtime=yes
EOF

    # Auditd service hardening (limited - needs kernel access)
    mkdir -p /etc/systemd/system/auditd.service.d/
    cat > /etc/systemd/system/auditd.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
RestrictRealtime=yes
LockPersonality=yes
EOF

    # Reload systemd to apply changes
    systemctl daemon-reload

    print_message "$GREEN" "Systemd service sandboxing applied"

    # Configure DNSStubListener if using systemd-resolved
    if systemctl is-active systemd-resolved; then
        mkdir -p /etc/systemd/resolved.conf.d/
        cat > /etc/systemd/resolved.conf.d/security.conf << 'EOF'
[Resolve]
DNSStubListener=yes
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic
EOF
        systemctl restart systemd-resolved
    fi

    # Configure snap security
    if command -v snap &> /dev/null; then
        print_message "$BLUE" "Hardening snap security..."
        # Refresh snaps to ensure latest security updates
        snap refresh || true
    fi

    # Configure netplan security (if used)
    if command -v netplan &> /dev/null && [[ -d /etc/netplan ]]; then
        print_message "$BLUE" "Securing netplan configuration..."
        chmod 600 /etc/netplan/*.yaml 2>/dev/null || true
    fi
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

        if [[ "$product_name" == *"Amazon"* ]] || { [[ -f /sys/hypervisor/uuid ]] && grep -qi "ec2" /sys/hypervisor/uuid 2>/dev/null; }; then
            is_cloud=true
            cloud_provider="AWS"
        elif [[ "$product_name" == *"Google"* ]]; then
            is_cloud=true
            cloud_provider="GCP"
        elif [[ "$product_name" == *"Microsoft"* ]] || [[ "$product_name" == *"Virtual Machine"* ]]; then
            is_cloud=true
            cloud_provider="Azure"
        fi
    fi

    # Check for cloud-init (another indicator)
    if [[ -d /var/lib/cloud ]] && ! $is_cloud; then
        is_cloud=true
        cloud_provider="Unknown Cloud"
    fi

    if ! $is_cloud; then
        print_message "$YELLOW" "Not a cloud instance - skipping cloud-specific hardening"
        return 0
    fi

    print_message "$BLUE" "Detected cloud provider: $cloud_provider"

    # AWS-specific hardening
    if [[ "$cloud_provider" == "AWS" ]]; then
        print_message "$BLUE" "Applying AWS-specific security controls..."

        # IMDSv2 enforcement - block IMDSv1 at firewall level
        # This provides defense-in-depth even if instance metadata isn't configured for IMDSv2
        if command -v iptables &> /dev/null; then
            # Create a script to enforce metadata protection
            cat > /etc/network/if-up.d/block-imds << 'IMDSEOF'
#!/bin/bash
# Block direct access to IMDS for non-root users (defense against SSRF)
# IMDSv2 should be enforced at the AWS level, this is additional protection

# Only allow root to access metadata service
iptables -C OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP 2>/dev/null || \
    iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP

# Log attempts to access metadata from non-root
iptables -C OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j LOG --log-prefix "IMDS-ACCESS: " 2>/dev/null || \
    iptables -I OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j LOG --log-prefix "IMDS-ACCESS: "
IMDSEOF
            chmod +x /etc/network/if-up.d/block-imds

            # Apply immediately
            /etc/network/if-up.d/block-imds 2>/dev/null || true
        fi

        print_message "$GREEN" "AWS IMDS protection configured"
    fi

    # Azure-specific hardening
    if [[ "$cloud_provider" == "Azure" ]]; then
        print_message "$BLUE" "Applying Azure-specific security controls..."

        # Block Azure IMDS for non-root (similar protection)
        if command -v iptables &> /dev/null; then
            iptables -C OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP 2>/dev/null || \
                iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP
        fi

        print_message "$GREEN" "Azure metadata protection configured"
    fi

    # GCP-specific hardening
    if [[ "$cloud_provider" == "GCP" ]]; then
        print_message "$BLUE" "Applying GCP-specific security controls..."

        # Block GCP metadata for non-root
        if command -v iptables &> /dev/null; then
            iptables -C OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP 2>/dev/null || \
                iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP
            # GCP also uses metadata.google.internal
            iptables -C OUTPUT -d 169.254.169.254 -p tcp --dport 80 -m owner ! --uid-owner 0 -j DROP 2>/dev/null || \
                iptables -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -m owner ! --uid-owner 0 -j DROP
        fi

        print_message "$GREEN" "GCP metadata protection configured"
    fi

    # Universal cloud hardening
    print_message "$BLUE" "Applying universal cloud security controls..."

    # Disable cloud-init network configuration after initial setup (prevents reconfiguration attacks)
    if [[ -f /etc/cloud/cloud.cfg ]]; then
        if ! grep -q "network: {config: disabled}" /etc/cloud/cloud.cfg; then
            echo "network: {config: disabled}" >> /etc/cloud/cloud.cfg
            print_message "$GREEN" "Cloud-init network reconfiguration disabled"
        fi
    fi

    # Secure cloud-init logs (may contain sensitive data)
    if [[ -d /var/log/cloud-init ]]; then
        chmod 600 /var/log/cloud-init/*.log 2>/dev/null || true
        chmod 700 /var/log/cloud-init
    fi

    # Remove any cached user-data (may contain secrets)
    if [[ -f /var/lib/cloud/instance/user-data.txt ]]; then
        # Keep a hash for verification, remove actual content
        sha256sum /var/lib/cloud/instance/user-data.txt > /var/lib/cloud/instance/user-data.sha256 2>/dev/null || true
        : > /var/lib/cloud/instance/user-data.txt
        print_message "$GREEN" "Cleared cached user-data"
    fi

    print_message "$GREEN" "Cloud security hardening completed for $cloud_provider"
}

# Function to perform security audits
perform_security_audit() {
    print_message "$GREEN" "Performing initial security audit..."

    local audit_dir="${LOG_DIR}/initial-audit"
    mkdir -p "$audit_dir"

    # Run Lynis audit
    if command -v lynis &> /dev/null; then
        print_message "$BLUE" "Running Lynis security audit..."
        lynis audit system --quick --quiet --report-file "$audit_dir/lynis-report.txt" || true
    fi

    # Run rkhunter
    if command -v rkhunter &> /dev/null; then
        print_message "$BLUE" "Running rkhunter check..."
        rkhunter --update || true
        rkhunter --check --skip-keypress --report-file "$audit_dir/rkhunter-report.txt" || true
    fi

    # Check for listening services
    print_message "$BLUE" "Checking listening services..."
    ss -tulpn > "$audit_dir/listening-services.txt" 2>&1

    # Check for running processes
    ps auxf > "$audit_dir/running-processes.txt" 2>&1

    # Check system users
    awk -F: '$3 >= 1000 {print $1}' /etc/passwd > "$audit_dir/system-users.txt"

    print_message "$GREEN" "Security audit completed. Results in: $audit_dir"
}

# Function to generate JSON compliance report (for SIEM integration)
generate_compliance_json() {
    print_message "$GREEN" "Generating JSON compliance report..."

    local json_file="${LOG_DIR}/compliance-report.json"

    cat > "$json_file" << EOF
{
  "compliance_report": {
    "timestamp": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "os_version": "$(lsb_release -ds 2>/dev/null || echo 'Ubuntu')",
    "kernel": "$(uname -r)",
    "script_version": "$SCRIPT_VERSION",
    "hardening_profile": "CIS Level 1 + Custom",
    "controls_applied": {
      "system_updates": {
        "status": "applied",
        "unattended_upgrades": $(systemctl is-enabled unattended-upgrades 2>/dev/null && echo '"enabled"' || echo '"disabled"')
      },
      "firewall": {
        "status": "applied",
        "ufw_enabled": $(ufw status | grep -q "active" && echo "true" || echo "false"),
        "default_policy": "deny incoming"
      },
      "ssh_hardening": {
        "status": "applied",
        "root_login": "disabled",
        "password_auth": "disabled",
        "fido2_support": "enabled"
      },
      "audit_logging": {
        "status": "applied",
        "auditd_enabled": $(systemctl is-enabled auditd 2>/dev/null && echo "true" || echo "false"),
        "lotl_detection": "enabled"
      },
      "file_integrity": {
        "aide_enabled": $(systemctl is-enabled aide.timer 2>/dev/null && echo "true" || echo "false")
      },
      "malware_protection": {
        "clamav_enabled": $(systemctl is-enabled clamav-daemon 2>/dev/null && echo "true" || echo "false"),
        "freshclam_enabled": $(systemctl is-enabled clamav-freshclam 2>/dev/null && echo "true" || echo "false")
      },
      "intrusion_prevention": {
        "fail2ban_enabled": $(systemctl is-enabled fail2ban 2>/dev/null && echo "true" || echo "false")
      },
      "apparmor": {
        "status": "applied",
        "enforced_profiles": $(aa-status 2>/dev/null | grep -c "enforce" || echo "0")
      },
      "kernel_hardening": {
        "sysctl_applied": true,
        "lockdown_mode": "$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -oP '\[\K[^\]]+' || echo 'none')"
      },
      "cloud_security": {
        "metadata_protection": "enabled",
        "imds_hardening": "applied"
      },
      "systemd_sandboxing": {
        "ssh_hardened": true,
        "fail2ban_hardened": true,
        "clamav_hardened": true
      }
    },
    "compliance_frameworks": [
      "CIS Ubuntu Linux 24.04 LTS Benchmark",
      "NIST SP 800-53",
      "PCI-DSS (partial)"
    ],
    "next_scan": "Run: /usr/local/bin/openscap-scan.sh"
  }
}
EOF

    chmod 600 "$json_file"
    print_message "$GREEN" "JSON compliance report: $json_file"
}

# Function to generate comprehensive report
generate_report() {
    print_message "$GREEN" "Generating comprehensive hardening report..."

    cat > "$REPORT_FILE" << EOF
Ubuntu 24.04 LTS Security Hardening Report
==========================================
Generated: $(date)
Hostname: $(hostname)
Ubuntu Version: $(lsb_release -ds)
Kernel: $(uname -r)
Script Version: $SCRIPT_VERSION

Executive Summary
-----------------
This system has been hardened according to security best practices for Ubuntu 24.04 LTS.
All security tools have been installed and configured with appropriate policies.

Applied Security Measures
-------------------------

1. SYSTEM UPDATES
   ✓ All packages updated to latest versions
   ✓ Automatic security updates enabled via unattended-upgrades
   ✓ Update notifications configured
   ✓ Kernel live patching ready (if Ubuntu Pro enabled)

2. FILE INTEGRITY MONITORING
   ✓ AIDE configured with systemd timer
   ✓ Daily integrity checks scheduled
   ✓ Tripwire available as secondary option
   ✓ Database location: /var/lib/aide/aide.db

3. AUDIT SYSTEM
   ✓ Auditd configured with comprehensive ruleset
   ✓ Monitoring: auth, sudo, SSH, systemd, kernel modules
   ✓ Ubuntu 24.04 specific paths included
   ✓ Log rotation configured

4. MANDATORY ACCESS CONTROL
   ✓ AppArmor enabled and enforcing
   ✓ All profiles in enforce mode
   ✓ Snap confinement configured
   ✓ Additional profiles installed

5. ANTIVIRUS PROTECTION
   ✓ ClamAV installed and configured
   ✓ Scheduled scans: $scan_frequency
   ✓ Real-time scanning enabled
   ✓ Automatic updates configured

6. FIREWALL
   ✓ UFW enabled with secure defaults
   ✓ IPv6 support enabled
   ✓ Rate limiting on SSH
   ✓ Logging enabled at medium level

7. INTRUSION PREVENTION
   ✓ Fail2ban configured with systemd backend
   ✓ SSH protection enabled
   ✓ Port scan detection enabled
   ✓ Custom jails configured

8. SSH HARDENING
   ✓ Root login disabled
   ✓ Password authentication disabled
   ✓ Strong crypto algorithms only
   ✓ Connection limits configured

9. KERNEL HARDENING
   ✓ Sysctl parameters optimized
   ✓ ASLR enabled
   ✓ Core dumps restricted
   ✓ Module loading restrictions

10. SYSTEM LIMITS
    ✓ Resource limits configured
    ✓ Process limits enforced
    ✓ Systemd limits applied
    ✓ Core dumps disabled

11. UBUNTU 24.04 FEATURES
    ✓ Systemd security features enabled
    ✓ OOM daemon configured
    ✓ DNS security enhanced
    ✓ Private tmp enabled for services

12. COMPLIANCE SCANNING
    ✓ OpenSCAP configured
    ✓ CIS benchmark scanning
    ✓ Scheduled assessments

Important File Locations
------------------------
Configuration Backups: $BACKUP_DIR
Log Files: $LOG_DIR
Audit Logs: /var/log/audit/
ClamAV Logs: /var/log/clamav/
Fail2ban Logs: /var/log/fail2ban.log
UFW Logs: /var/log/ufw.log
OpenSCAP Reports: /var/log/openscap/

Security Tool Commands
----------------------
# System Audit
lynis audit system                    # Comprehensive security audit
rkhunter -c                          # Rootkit check
chkrootkit                           # Alternative rootkit check

# File Integrity
aide --check                         # Check file integrity
aide --update                        # Update AIDE database

# Audit System
aureport --summary                   # Audit report summary
ausearch -m LOGIN --success no       # Failed login attempts

# Firewall
ufw status verbose                   # Firewall status
ufw show raw                         # Raw firewall rules

# Intrusion Detection
fail2ban-client status              # Fail2ban status
fail2ban-client status sshd         # SSH jail status

# Updates
unattended-upgrade --dry-run        # Test automatic updates

# Compliance
/usr/local/bin/openscap-scan.sh    # Run compliance scan

Post-Installation Checklist
---------------------------
□ Review and test all configurations
□ Configure SSH keys for all users
□ Add necessary firewall rules for services
□ Review audit logs regularly
□ Schedule regular security reviews
□ Configure log forwarding if needed
□ Set up monitoring and alerting
□ Document any custom changes
□ Test system recovery procedures

⚠️  CRITICAL WARNINGS ⚠️
------------------------
1. SSH password authentication is DISABLED
   - Ensure SSH keys are configured before disconnecting
   - Test SSH key access from another terminal

2. Firewall is blocking all incoming except SSH
   - Add rules for required services using: ufw allow <port>/<protocol>

3. Some kernel parameters may affect applications
   - Test all critical applications thoroughly

4. Automatic updates are enabled
   - Review /etc/apt/apt.conf.d/50unattended-upgrades for exclusions

Next Steps
----------
1. Run 'lynis audit system' for detailed recommendations
2. Review OpenSCAP compliance reports
3. Configure centralized logging if applicable
4. Set up regular backup procedures
5. Create system recovery documentation
6. Train staff on security procedures

Support and Maintenance
-----------------------
- Check system logs regularly
- Monitor security mailing lists
- Keep security tools updated
- Review hardening quarterly
- Test incident response procedures

This report was generated by: $SCRIPT_NAME v$SCRIPT_VERSION
For issues or updates: https://github.com/alokemajumder
EOF

    # Set appropriate permissions
    chmod 600 "$REPORT_FILE"

    print_message "$GREEN" "Comprehensive report saved to: $REPORT_FILE"
}

# Function to perform final system checks
final_system_checks() {
    print_message "$GREEN" "Performing final system checks..."

    # Check critical services
    local services=(
        "auditd"
        "apparmor"
        "clamav-daemon"
        "clamav-freshclam"
        "ufw"
        "fail2ban"
        "unattended-upgrades"
        "systemd-resolved"
    )

    print_message "$BLUE" "Service Status:"
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_message "$GREEN" "  ✓ $service is running"
        else
            print_message "$YELLOW" "  ⚠ $service is not running (may not be required)"
        fi
    done

    # Check firewall
    print_message "$BLUE" "Firewall Status:"
    if ufw status | grep -q "Status: active"; then
        print_message "$GREEN" "  ✓ UFW firewall is active"
        ufw status numbered | grep -E "^\[[0-9]+\]" | head -5
    else
        print_message "$RED" "  ✗ UFW firewall is not active"
    fi

    # Check for updates
    print_message "$BLUE" "Checking for remaining updates..."
    if apt-get -s upgrade | grep -q "0 upgraded"; then
        print_message "$GREEN" "  ✓ System is fully updated"
    else
        print_message "$YELLOW" "  ⚠ Updates are available"
    fi
}

# Main function
main() {
    # Pre-flight checks
    check_root
    setup_directories

    print_message "$GREEN" "╔══════════════════════════════════════════════════════╗"
    print_message "$GREEN" "║     Ubuntu 24.04 LTS Security Hardening Script       ║"
    print_message "$GREEN" "║                   Version $SCRIPT_VERSION                        ║"
    print_message "$GREEN" "╚══════════════════════════════════════════════════════╝"
    check_ubuntu_version
    check_system_requirements

    # Create system restore point notification
    print_message "$YELLOW" "Consider creating a system backup/snapshot before proceeding"
    read -p "Press Enter to continue or Ctrl+C to cancel..."

    # Main hardening process
    print_message "$GREEN" "Starting security hardening process..."

    update_system
    install_packages

    # Core security configurations
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
    configure_kernel_lockdown
    configure_openscap

    # Ubuntu 24.04 specific features
    configure_ubuntu_24_features

    # Cloud instance security (AWS/Azure/GCP)
    configure_cloud_security

    # Auditing and reporting
    perform_security_audit
    generate_report
    generate_compliance_json
    final_system_checks

    # Completion
    print_message "$GREEN" "╔══════════════════════════════════════════════════════╗"
    print_message "$GREEN" "║        Security Hardening Completed Successfully!     ║"
    print_message "$GREEN" "╚══════════════════════════════════════════════════════╝"
    print_message "$GREEN" ""
    print_message "$YELLOW" "📋 Report Location: $REPORT_FILE"
    print_message "$YELLOW" "📁 Backup Location: $BACKUP_DIR"
    print_message "$YELLOW" "📊 Audit Results: ${LOG_DIR}/initial-audit/"
    print_message ""
    print_message "$RED" "⚠️  CRITICAL: Ensure you have SSH key access before disconnecting!"
    print_message "$RED" "⚠️  Password authentication has been disabled for security."
    print_message ""
    print_message "$GREEN" "Next: Review the report and test all services before production use."
}

# Trap errors
trap 'error_exit "Script failed at line $LINENO"' ERR

# Run main function
main "$@"