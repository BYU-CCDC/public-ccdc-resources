#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo)"
  exit
fi

echo "Installing ClamAV..."

# Check for APT (Ubuntu/Debian)
if command -v apt &> /dev/null; then
    apt update
    apt install -y clamav clamav-daemon
    
    # Stop daemon briefly to update the database
    systemctl stop clamav-daemon
    freshclam
    systemctl enable --now clamav-daemon

# Check for YUM/DNF (RHEL/CentOS/Oracle/Fedora)
elif command -v yum &> /dev/null; then
    # Install EPEL (Required for RHEL/CentOS/Oracle)
    yum install -y epel-release 2>/dev/null
    yum install -y clamav clamav-update clamav-scanner-systemd
    
    sed -i 's/^Example/#Example/' /etc/freshclam.conf
    sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf
    sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamd.d/scan.conf
    
    freshclam
    systemctl enable --now clamd@scan

else
    echo "Error: Could not detect apt or yum. OS not supported."
    exit 1
fi


# Create log directory 
mkdir -p /var/log/clamav

echo "Success! ClamAV is installed, running, and scheduled to scan daily."


# 1. Define the job as a variable
CRON_JOB="*/30 * * * * /usr/bin/clamscan -r --log=/var/log/clamav/scan.log --exclude-dir=\"^/sys\" --exclude-dir=\"^/proc\" --exclude-dir=\"^/dev\" /"

# 2. Check if the job already exists to avoid duplicates
# We use 'crontab -l' to list current jobs, and grep to search for our specific command.
(sudo crontab -l 2>/dev/null | grep -F "$CRON_JOB") || (sudo crontab -l 2>/dev/null; echo "$CRON_JOB") | sudo crontab -
clamscan
echo -e "\033[0;32mCrontab Job for 30-minute Scanning on $(hostname)\033[0m"
sudo crontab -l
echo "Run `systemctl status clamav-daemon` on Ubuntu and 'systemctl status clamd@scan' on Fedora/Oracle"
