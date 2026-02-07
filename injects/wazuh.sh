#!/bin/bash
# Unified Wazuh Agent Installation Script
# Supports: Debian, Ubuntu, CentOS, RHEL, Rocky Linux, AlmaLinux

# Exit immediately if a command exits with a non-zero status.
set -e

# --- 1. Check for Root Privileges ---
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root. Please use sudo." >&2
    exit 1
fi

# --- 2. User Input for Configuration ---
read -p "Enter the Wazuh Manager IP address: " WAZUH_MANAGER_IP

if [ -z "$WAZUH_MANAGER_IP" ]; then
    echo "Error: No IP address provided. Exiting."
    exit 1
fi

# --- 3. OS Detection & Installation Logic ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    # Fallback for older systems
    OS=$(uname -s)
    VER=$(uname -r)
fi

echo "--- Detected OS: $OS ---"

if [[ "$OS" == *"Debian"* || "$OS" == *"Ubuntu"* ]]; then
    # ==========================================
    # DEBIAN / UBUNTU INSTALLATION BLOCK
    # ==========================================
    echo "--- Starting Debian/Ubuntu Installation ---"

    # 1. Cleanup old attempts
    rm -f /usr/share/keyrings/wazuh.gpg
    rm -f /etc/apt/sources.list.d/wazuh.list

    # 2. Install prerequisites if missing
    apt-get update && apt-get install -y curl gnupg apt-transport-https

    # 3. Download and install GPG key
    echo "--- Importing GPG Key..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg

    # 4. Add Repository
    echo "--- Adding Wazuh Repository..."
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

    # 5. Update and Install
    echo "--- Updating package lists..."
    apt-get update
    
    echo "--- Installing Wazuh Agent 4.7 pointing to $WAZUH_MANAGER_IP..."
    WAZUH_MANAGER="$WAZUH_MANAGER_IP" apt-get install -y --allow-downgrades wazuh-agent=4.7.2-1

elif [[ "$OS" == *"CentOS"* || "$OS" == *"Red Hat"* || "$OS" == *"Rocky"* || "$OS" == *"AlmaLinux"* || "$OS" == *"Fedora"* ]]; then
    # ==========================================
    # RHEL / CENTOS / ROCKY INSTALLATION BLOCK
    # ==========================================
    echo "--- Starting RHEL/CentOS/Rocky Installation ---"

    # 1. Import GPG Key
    echo "--- Importing GPG Key..."
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

    # 2. Add Wazuh Repository
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

    # 3. Determine Package Manager (dnf vs yum)
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    else
        echo "Error: Neither dnf nor yum found. Cannot proceed." >&2
        exit 1
    fi

    # 4. Install Agent
    echo "--- Installing Wazuh Agent 4.7 using $PKG_MANAGER..."
    WAZUH_MANAGER="$WAZUH_MANAGER_IP" $PKG_MANAGER install -y wazuh-agent-4.7.2-1

else
    echo "Error: Unsupported Operating System: $OS"
    exit 1
fi

# --- 4. Enable and Start Service (Common to all) ---
echo "--- Starting Wazuh Agent Service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# --- 5. Verification ---
echo ""
echo "--- Installation Complete! ---"
echo "Verifying service status..."
systemctl status wazuh-agent
