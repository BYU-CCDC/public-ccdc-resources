#!/bin/bash
# Unified Wazuh Agent Installation Script
# Works on: CentOS 7/8/Stream, Rocky Linux, AlmaLinux, RHEL
# Author: Gemini (Combined from user inputs)

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
WAZUH_MANAGER_IP="192.168.220.240"

# 1. Check for Root Privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: This script must be run as root. Please use sudo." >&2
  exit 1
fi

# 2. OS and Package Manager Detection
if [ -f /etc/os-release ]; then
    source /etc/os-release
    echo "--- Detected OS: $PRETTY_NAME ---"
else
    echo "--- Starting Installation Process (RHEL/CentOS/Rocky) ---"
fi

# Determine if we should use dnf or yum
if command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
else
    echo "Error: Neither dnf nor yum found. Cannot proceed." >&2
    exit 1
fi
echo "--- Using Package Manager: $PKG_MANAGER"

# 3. Import the GPG Key
echo "--- Importing GPG Key..."
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

# 4. Add Wazuh Repository
echo "--- Adding Wazuh Repository..."
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# 5. Install Wazuh Agent
echo "--- Installing Wazuh Agent pointing to $WAZUH_MANAGER_IP..."
# We use the detected $PKG_MANAGER here
WAZUH_MANAGER="$WAZUH_MANAGER_IP" $PKG_MANAGER install -y wazuh-agent

# 6. Enable and Start Wazuh Service
echo "--- Starting Wazuh agent..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# 7. Verification
echo ""
echo "--- Installation Complete! ---"
echo "Verifying Wazuh Agent connection..."
# --no-pager prevents the script from hanging on an interactive screen
systemctl status wazuh-agent --no-pager

echo ""
echo "Done."
