#!/bin/bash

# BloodHound Setup Script for Linux
# This script downloads, installs, and configures BloodHound with Neo4j on Linux.

# Define Variables
NEO4J_VERSION="4.4.12"
NEO4J_URL="https://neo4j.com/artifact.php?name=neo4j-community-$NEO4J_VERSION-unix.tar.gz"
NEO4J_ARCHIVE="/tmp/neo4j.tar.gz"
NEO4J_INSTALL_DIR="/opt/neo4j"
BLOODHOUND_URL="https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip"
BLOODHOUND_ARCHIVE="/tmp/bloodhound.zip"
BLOODHOUND_INSTALL_DIR="/opt/BloodHound"
SHARPHOUND_URL="https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe"
SHARPHOUND_PATH="$BLOODHOUND_INSTALL_DIR/SharpHound.exe"
NEO4J_USER="neo4j"
NEO4J_PASSWORD="bloodhound"  # Default password, change if necessary

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Function to install Neo4j
install_neo4j() {
    echo "Installing Neo4j..."
    wget -qO $NEO4J_ARCHIVE $NEO4J_URL
    mkdir -p $NEO4J_INSTALL_DIR
    tar -xzf $NEO4J_ARCHIVE -C $NEO4J_INSTALL_DIR --strip-components=1
    rm $NEO4J_ARCHIVE
    echo "Neo4j installed to $NEO4J_INSTALL_DIR"
}

# Function to configure Neo4j as a service
configure_neo4j_service() {
    echo "Configuring Neo4j service..."
    cat <<EOF > /etc/systemd/system/neo4j.service
[Unit]
Description=Neo4j Graph Database
After=network.target

[Service]
Type=forking
ExecStart=$NEO4J_INSTALL_DIR/bin/neo4j start
ExecStop=$NEO4J_INSTALL_DIR/bin/neo4j stop
User=root
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable neo4j
    systemctl start neo4j
    echo "Neo4j service configured and started."
}

# Function to set Neo4j password
set_neo4j_password() {
    echo "Setting Neo4j password..."
    sleep 15  # Allow Neo4j to fully start
    curl -s -H "Content-Type: application/json" \
         -X POST -d "{\"password\":\"$NEO4J_PASSWORD\"}" \
         -u "$NEO4J_USER:neo4j" \
         http://localhost:7474/user/neo4j/password
    echo "Neo4j password set to $NEO4J_PASSWORD."
}

# Function to install BloodHound
install_bloodhound() {
    echo "Installing BloodHound..."
    wget -qO $BLOODHOUND_ARCHIVE $BLOODHOUND_URL
    mkdir -p $BLOODHOUND_INSTALL_DIR
    unzip -q $BLOODHOUND_ARCHIVE -d $BLOODHOUND_INSTALL_DIR
    rm $BLOODHOUND_ARCHIVE
    echo "BloodHound installed to $BLOODHOUND_INSTALL_DIR"
}

# Function to download SharpHound
download_sharphound() {
    echo "Downloading SharpHound..."
    wget -qO $SHARPHOUND_PATH $SHARPHOUND_URL
    echo "SharpHound downloaded to $SHARPHOUND_PATH"
}

# Function to start BloodHound
start_bloodhound() {
    echo "Starting BloodHound..."
    nohup $BLOODHOUND_INSTALL_DIR/BloodHound &>/dev/null &
    echo "BloodHound started. Access it by opening BloodHound in the UI."
}

# Main Execution
install_neo4j
configure_neo4j_service
set_neo4j_password
install_bloodhound
download_sharphound
start_bloodhound

echo "BloodHound setup completed successfully."
