# Consider shifting to critical web only... 

#!/bin/bash

# Define variables
REPO_URL="https://github.com/username/repository-name.git"  # Replace with your repository URL
DEST_DIR="$HOME/ComprehensiveSetup"
LOG_FILE="$DEST_DIR/setup_log.txt"

# Function to log actions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Step 1: Clone the repository if it doesn’t already exist
if [ ! -d "$DEST_DIR" ]; then
    log "Cloning repository..."
    git clone "$REPO_URL" "$DEST_DIR"
    log "Repository cloned to $DEST_DIR."
else
    log "Repository already exists at $DEST_DIR. Pulling latest changes..."
    cd "$DEST_DIR" || exit
    git pull
    log "Repository updated."
fi

# Step 2: Make all .sh files executable
log "Making all .sh files executable..."
chmod +x "$DEST_DIR"/*.sh
chmod +x "$DEST_DIR"/*/*.sh
log "All .sh files have been set to executable."

# Define functions for each module based on the previous script

# === Compliance and Security Audit ===
function run_compliance_audit {
    log "Running Compliance Audit..."
    "$DEST_DIR/compliance_audit.sh"
    "$DEST_DIR/csp_enforcement.sh"
    log "Compliance Audit completed."
}

function enable_dlp {
    log "Enabling Data Loss Prevention..."
    "$DEST_DIR/dlp.sh"
    log "Data Loss Prevention setup completed."
}

# === Service Management ===
function setup_caddy_reverse_proxy {
    log "Setting up Caddy Reverse Proxy..."
    "$DEST_DIR/caddy_reverse_proxy.sh"
    log "Caddy Reverse Proxy setup completed."
}

function dockerize_services {
    log "Dockerizing Services..."
    "$DEST_DIR/dockerize.sh"
    log "Dockerization of services completed."
}

function setup_kubernetes_cluster {
    log "Setting up Kubernetes Cluster..."
    "$DEST_DIR/k8_cluster.sh"
    log "Kubernetes Cluster setup completed."
}

# === Monitoring and Security Tools ===
function setup_nessus {
    log "Setting up Nessus Vulnerability Scanner..."
    "$DEST_DIR/nessus.sh"
    log "Nessus setup completed."
}

function setup_ossec {
    log "Setting up OSSEC for Host-based Intrusion Detection..."
    "$DEST_DIR/ossec.sh"
    log "OSSEC setup completed."
}

function setup_wazuh {
    log "Setting up Wazuh for Endpoint Monitoring..."
    "$DEST_DIR/wazuh.sh"
    log "Wazuh setup completed."
}

function enable_fim {
    log "Setting up File Integrity Monitoring..."
    "$DEST_DIR/fim.sh"
    log "File Integrity Monitoring setup completed."
}

function setup_waf {
    log "Setting up Web Application Firewall..."
    "$DEST_DIR/waf.sh"
    log "WAF setup completed."
}

# === Privileged Identity Management (PIM) ===
function configure_pim {
    log "Configuring Privileged Identity Management..."
    "$DEST_DIR/pim.sh"
    log "Privileged Identity Management configured."
}

# === Backup and Recovery ===
function setup_backup {
    log "Setting up Backup for Web Applications..."
    "$DEST_DIR/web_backup.sh"
    log "Backup setup completed."
}

function secure_pii {
    log "Securing Personally Identifiable Information (PII)..."
    "$DEST_DIR/pii.sh"
    log "PII security setup completed."
}

# === Digital Forensics and Incident Response (DFIR) ===
function deploy_velociraptor {
    log "Deploying Velociraptor for DFIR..."
    "$DEST_DIR/velociraptor_dfir.sh"
    log "Velociraptor setup completed."
}

# === LLM Setup ===
function setup_llm {
    log "Setting up Lightweight Language Model..."
    "$DEST_DIR/llm/llm.sh"
    log "LLM setup completed."
}

# === Execute All Functions ===
log "Starting Comprehensive Setup..."

run_compliance_audit
enable_dlp

setup_caddy_reverse_proxy
dockerize_services
setup_kubernetes_cluster

setup_nessus
setup_ossec
setup_wazuh
enable_fim
setup_waf

configure_pim

setup_backup
secure_pii

deploy_velociraptor

setup_llm

log "Comprehensive setup completed successfully."
echo "Comprehensive setup completed. Check the log file at $LOG_FILE for details."
