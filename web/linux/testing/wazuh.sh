#!/bin/bash

# Define variables
logFile="/var/log/wazuh_install_log.txt"
wazuhServer="localhost"  # Set this to the Wazuh server IP if installing an agent
installMode="agent"      # Options: "agent" or "server"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Update the system and install prerequisites
log_event "Updating system packages and installing prerequisites..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https lsb-release gnupg

# Step 2: Add Wazuh repository and install the GPG key
log_event "Adding Wazuh repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Step 3: Install Wazuh based on the selected mode (agent or server)
if [[ "$installMode" == "server" ]]; then
    log_event "Installing Wazuh Manager (server)..."
    sudo apt install -y wazuh-manager
    sudo systemctl enable wazuh-manager
    sudo systemctl start wazuh-manager
    log_event "Wazuh Manager (server) installed and started."
elif [[ "$installMode" == "agent" ]]; then
    log_event "Installing Wazuh Agent..."
    sudo apt install -y wazuh-agent
    log_event "Configuring Wazuh Agent to connect to the server at $wazuhServer."
    
    # Configure Wazuh Agent to connect to the specified server
    sudo sed -i "s/^address=.*/address=$wazuhServer/" /var/ossec/etc/ossec.conf
    
    # Enable and start the agent
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    log_event "Wazuh Agent installed, configured, and started."
else
    log_event "Invalid install mode. Please set installMode to 'agent' or 'server'."
    exit 1
fi

# Step 4: Verify Installation and Services
log_event "Checking the status of Wazuh services..."

if [[ "$installMode" == "server" && $(sudo systemctl is-active wazuh-manager) == "active" ]]; then
    log_event "Wazuh Manager is running successfully."
elif [[ "$installMode" == "agent" && $(sudo systemctl is-active wazuh-agent) == "active" ]]; then
    log_event "Wazuh Agent is running successfully."
else
    log_event "Error: Wazuh service failed to start."
    exit 1
fi

log_event "Wazuh installation and configuration completed. Logs are available at $logFile."
