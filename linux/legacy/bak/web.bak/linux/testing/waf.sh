#!/bin/bash

# Define variables
modsecConfDir="/etc/nginx/modsecurity"
modsecConfigFile="$modsecConfDir/modsecurity.conf"
nginxConfDir="/etc/nginx"
logFile="/var/log/modsecurity_install_log.txt"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Update and Install Nginx with ModSecurity
log_event "Updating system packages and installing prerequisites..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y nginx libnginx-mod-security modsecurity

log_event "Nginx and ModSecurity installation completed."

# Step 2: Enable ModSecurity and Create Configuration Directory
log_event "Enabling ModSecurity and setting up configuration..."

# Create directory for ModSecurity configurations
sudo mkdir -p "$modsecConfDir"
sudo cp /etc/modsecurity/modsecurity.conf-recommended "$modsecConfigFile"

# Set ModSecurity to DetectionOnly mode
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$modsecConfigFile"

# Step 3: Configure Nginx to Use ModSecurity
log_event "Configuring Nginx to use ModSecurity..."

# Add ModSecurity configuration to Nginx
cat <<EOL | sudo tee "$modsecConfDir/modsec_rules.conf"
# Basic ModSecurity configuration with recommended OWASP Core Rule Set

Include /usr/share/modsecurity-crs/owasp-crs.load
Include $modsecConfDir/modsecurity.conf
EOL

# Update Nginx configuration to load ModSecurity
cat <<EOL | sudo tee /etc/nginx/conf.d/modsecurity.conf
server {
    listen 80;
    server_name localhost;

    location / {
        ModSecurityEnabled on;
        ModSecurityConfig $modsecConfDir/modsecurity.conf;

        proxy_pass http://127.0.0.1:8080;  # Update to your backend server if applicable
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOL

# Step 4: Enable OWASP ModSecurity Core Rule Set (CRS)
log_event "Installing and enabling the OWASP Core Rule Set (CRS)..."

# Download and enable the OWASP CRS
sudo apt install -y modsecurity-crs
sudo ln -s /usr/share/modsecurity-crs /etc/nginx/modsecurity-crs

# Step 5: Test and Start Nginx
log_event "Testing Nginx configuration..."
sudo nginx -t

if [[ $? -ne 0 ]]; then
    log_event "Nginx configuration test failed. Please check for errors."
    exit 1
fi

log_event "Starting Nginx with ModSecurity..."
sudo systemctl enable nginx
sudo systemctl restart nginx

# Step 6: Verify ModSecurity Logs
log_event "ModSecurity setup complete. Monitoring logs for ModSecurity at /var/log/modsec_audit.log"
echo "ModSecurity log file: /var/log/modsec_audit.log" | tee -a "$logFile"

log_event "ModSecurity installation and setup completed successfully. Logs are available at $logFile."
