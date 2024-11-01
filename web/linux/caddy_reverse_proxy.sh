#!/bin/bash

# Define variables
CADDY_INSTALL_DIR="/etc/caddy"
CADDYFILE="$CADDY_INSTALL_DIR/Caddyfile"
LOG_FILE="/var/log/caddy_setup.log"
CURRENT_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Step 1: Install Caddy
echo "$CURRENT_DATE - Installing Caddy..." | tee -a $LOG_FILE
sudo apt update
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy -y

# Verify Caddy installation
if ! command -v caddy &> /dev/null; then
    echo "$CURRENT_DATE - Caddy installation failed. Exiting." | tee -a $LOG_FILE
    exit 1
fi
echo "$CURRENT_DATE - Caddy installed successfully." | tee -a $LOG_FILE

# Step 2: Get user input for reverse proxy configuration
read -p "Enter the domain you want to use for the reverse proxy (e.g., example.com): " DOMAIN
read -p "Enter the backend server URL to proxy to (e.g., http://localhost:8080): " BACKEND

# Step 3: Create the Caddyfile configuration
echo "$CURRENT_DATE - Creating Caddyfile at $CADDYFILE..." | tee -a $LOG_FILE
sudo mkdir -p $CADDY_INSTALL_DIR
sudo bash -c "cat > $CADDYFILE" <<EOL
# Caddy reverse proxy configuration
$DOMAIN {
    reverse_proxy $BACKEND
}
EOL
echo "$CURRENT_DATE - Caddyfile created with domain $DOMAIN and backend $BACKEND" | tee -a $LOG_FILE

# Step 4: Start and enable the Caddy service
echo "$CURRENT_DATE - Starting and enabling Caddy service..." | tee -a $LOG_FILE
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl start caddy

# Verify Caddy service
if sudo systemctl status caddy | grep -q "active (running)"; then
    echo "$CURRENT_DATE - Caddy service started successfully and is running." | tee -a $LOG_FILE
else
    echo "$CURRENT_DATE - Caddy service failed to start. Check logs for details." | tee -a $LOG_FILE
fi
