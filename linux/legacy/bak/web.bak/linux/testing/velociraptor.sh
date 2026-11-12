#!/bin/bash

# Define variables
velociraptorUrl="https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-v0.6.8-linux-amd64"  # Replace with the latest version URL if needed
installDir="/usr/local/bin"
configDir="/etc/velociraptor"
logFile="/var/log/velociraptor_install_log.txt"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Download and Install Velociraptor
log_event "Downloading Velociraptor..."
curl -L -o "$installDir/velociraptor" "$velociraptorUrl"

# Verify download success
if [[ -f "$installDir/velociraptor" ]]; then
    chmod +x "$installDir/velociraptor"
    log_event "Velociraptor downloaded and made executable."
else
    log_event "Error: Velociraptor download failed."
    exit 1
fi

# Step 2: Generate Server Configuration (for Server setup)
log_event "Generating Velociraptor server configuration..."
mkdir -p "$configDir"
"$installDir/velociraptor" config generate > "$configDir/server.config.yaml"

if [[ -f "$configDir/server.config.yaml" ]]; then
    log_event "Velociraptor server configuration generated at $configDir/server.config.yaml."
else
    log_event "Error: Failed to generate Velociraptor server configuration."
    exit 1
fi

# Step 3: Start Velociraptor in Server Mode
log_event "Starting Velociraptor in server mode..."
nohup "$installDir/velociraptor" --config "$configDir/server.config.yaml" frontend &

# Step 4: Set Up Velociraptor as a Systemd Service
log_event "Setting up Velociraptor as a systemd service..."

# Create a systemd service file
cat <<EOL | sudo tee /etc/systemd/system/velociraptor.service
[Unit]
Description=Velociraptor Server
After=network.target

[Service]
ExecStart=$installDir/velociraptor --config $configDir/server.config.yaml frontend
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL

# Enable and start the Velociraptor service
sudo systemctl daemon-reload
sudo systemctl enable velociraptor
sudo systemctl start velociraptor

# Check if the service is running
if systemctl is-active --quiet velociraptor; then
    log_event "Velociraptor service started successfully."
else
    log_event "Error: Velociraptor service failed to start."
    exit 1
fi

log_event "Velociraptor installation and setup completed. Logs are available at $logFile."



# "$installDir/velociraptor" config generate --client > "$configDir/client.config.yaml"
# 


