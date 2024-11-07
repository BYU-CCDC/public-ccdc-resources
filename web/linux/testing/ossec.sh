#!/bin/bash

# Define variables
ossecDir="/var/ossec"
logFile="/var/log/ossec_install_log.txt"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Update the system and install prerequisites
log_event "Updating system and installing prerequisites..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y wget build-essential libssl-dev libpcre2-dev unzip

# Step 2: Download OSSEC
log_event "Downloading OSSEC..."
wget -O /tmp/ossec.tar.gz https://github.com/ossec/ossec-hids/archive/master.tar.gz

# Verify download success
if [[ -f "/tmp/ossec.tar.gz" ]]; then
    log_event "OSSEC downloaded successfully."
else
    log_event "Error: OSSEC download failed."
    exit 1
fi

# Step 3: Extract and install OSSEC
log_event "Extracting OSSEC..."
tar -zxvf /tmp/ossec.tar.gz -C /tmp
cd /tmp/ossec-hids-master

log_event "Installing OSSEC..."
sudo ./install.sh <<EOF
server

/var/ossec

n

y

y

y

EOF

log_event "OSSEC installation completed."

# Step 4: Start and enable OSSEC service
log_event "Starting OSSEC service..."
sudo systemctl enable ossec
sudo systemctl start ossec

# Verify OSSEC is running
if sudo systemctl status ossec | grep -q "active (running)"; then
    log_event "OSSEC service started successfully."
else
    log_event "Error: OSSEC service failed to start."
    exit 1
fi

# Step 5: Configure OSSEC
log_event "Configuring OSSEC..."

# Example: Enable email notifications
sudo sed -i 's/<email_notification>no<\/email_notification>/<email_notification>yes<\/email_notification>/' $ossecDir/etc/ossec.conf
sudo sed -i 's/<email_to>you@example.com<\/email_to>/<email_to>admin@example.com<\/email_to>/' $ossecDir/etc/ossec.conf
sudo sed -i 's/<smtp_server>localhost<\/smtp_server>/<smtp_server>your.smtp.server.com<\/smtp_server>/' $ossecDir/etc/ossec.conf

log_event "OSSEC configuration completed. Email notifications enabled."

# Step 6: Clean up
log_event "Cleaning up installation files..."
rm -rf /tmp/ossec.tar.gz /tmp/ossec-hids-master

log_event "OSSEC installation and configuration completed. Logs are available at $logFile."
