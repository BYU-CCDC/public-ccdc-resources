#!/bin/bash
# Universal Headless Wazuh Manager Installer
# Works on: Debian/Ubuntu (apt), RHEL/CentOS/Alma/Rocky (dnf/yum)
=======


    sudo apt install curl

set -e

# --- 1. Check for Root Privileges ---
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root. Please use sudo." >&2
    exit 1
fi

echo "--- Starting Universal Wazuh Manager Install ---"

# --- 2. Detect Package Manager & Install Prerequisites ---
# We need curl and tar to download and run the Wazuh script.
# We use '-y' to ensure it doesn't hang waiting for "Y/n".

if command -v apt-get &> /dev/null; then
    echo "--- Detected 'apt' (Debian/Ubuntu) ---"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y curl tar gnupg

elif command -v dnf &> /dev/null; then
    echo "--- Detected 'dnf' (RHEL 8+/Fedora/CentOS Stream) ---"
    dnf install -y curl tar

elif command -v yum &> /dev/null; then
    echo "--- Detected 'yum' (RHEL 7/CentOS 7) ---"
    yum install -y curl tar

else
    echo "Error: No supported package manager found (apt, dnf, or yum)."
    exit 1
fi

# --- 3. Download and Run Wazuh Installer ---
echo "--- Downloading Wazuh Installation Script ---"
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

echo "--- Running Installer (This may take several minutes) ---"
echo "Credentials will be saved to: wazuh_install_log.txt"

bash wazuh-install.sh -a -i | tee wazuh_install_log.txt

# --- 4. Final Status Check ---
echo ""
echo "--- checking service status ---"
if systemctl is-active --quiet wazuh-manager; then
    echo "SUCCESS: Wazuh Manager is running."
    echo "IMPORTANT: Read 'wazuh_install_log.txt' to find your login password!"
else
    echo "WARNING: Wazuh Manager service is not active. Check logs."
    systemctl status wazuh-manager --no-pager
fi
echo -e "\033[0;32mMake sure to add firewall rules to allow inbound/outbound on ports 443, 1514, and 1515\033[0m"
echo -e "\033[0;32mUse these credentials when you log into the dashboard at https://$(hostname -I | awk '{print $1}')\033[0m"
grep -A 5 "User:" wazuh_install_log.txt
systemctl status wazuh-manager
