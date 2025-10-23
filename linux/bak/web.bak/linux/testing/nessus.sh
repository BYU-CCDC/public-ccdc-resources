#!/bin/bash

# Define variables
nessusDownloadUrl="https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/16394/download?i_agree_to_tenable_license_agreement=true"
nessusInstaller="/tmp/Nessus-Installer.rpm"
logFile="/var/log/nessus_install_log.txt"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Download Nessus Installer
log_event "Downloading Nessus installer..."
curl -L -o "$nessusInstaller" "$nessusDownloadUrl"

# Verify download success
if [[ -f "$nessusInstaller" ]]; then
    log_event "Nessus installer downloaded successfully."
else
    log_event "Error: Nessus installer download failed."
    exit 1
fi

# Step 2: Install Nessus
log_event "Installing Nessus..."
if [[ -f "/etc/debian_version" ]]; then
    # For Debian/Ubuntu
    sudo dpkg -i "$nessusInstaller"
    sudo apt-get install -f -y  # Install any missing dependencies
elif [[ -f "/etc/redhat-release" ]]; then
    # For RHEL/CentOS/Fedora
    sudo rpm -ivh "$nessusInstaller"
else
    log_event "Unsupported OS. Only Debian/Ubuntu or RHEL/CentOS/Fedora are supported."
    exit 1
fi

log_event "Nessus installation completed."

# Step 3: Start and Enable Nessus Service
log_event "Starting and enabling Nessus service..."
sudo systemctl enable nessusd
sudo systemctl start nessusd

# Verify Nessus is running
if sudo systemctl status nessusd | grep -q "active (running)"; then
    log_event "Nessus service started successfully."
else
    log_event "Error: Nessus service failed to start."
    exit 1
fi

# Step 4: Provide Access Instructions
log_event "Nessus installation and setup complete. Access Nessus at: https://localhost:8834/"
log_event "To complete the setup, open the link in a browser and follow the prompts."
log_event "Register at https://www.tenable.com/products/nessus/nessus-essentials to obtain an activation code if needed."

echo -e "\nTo access Nessus, open https://localhost:8834/ in your web browser and follow the setup instructions."
echo "If you haven't registered yet, you can obtain a free activation code at https://www.tenable.com/products/nessus/nessus-essentials."

# Clean up installer
rm -f "$nessusInstaller"
log_event "Cleaned up Nessus installer file."

log_event "Nessus installation and configuration script completed."
