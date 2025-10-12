#!/bin/bash

# linPEAS Automation Script
# This script downloads, prepares, and runs linPEAS for Linux privilege escalation enumeration.

# Define variables
REPO_URL="https://github.com/carlospolop/PEASS-ng.git"
SCRIPT_DIR="$HOME/PEASS-ng/linPEAS"
LOG_FILE="$HOME/linPEAS_scan_$(date +'%Y%m%d_%H%M%S').log"

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "Git is not installed. Please install git to continue."
    exit 1
fi

# Check if linPEAS directory exists; if not, clone the repository
if [ ! -d "$SCRIPT_DIR" ]; then
    echo "Cloning linPEAS from the PEASS-ng repository..."
    git clone "$REPO_URL" "$HOME/PEASS-ng"
    echo "Repository cloned to $HOME/PEASS-ng."
else
    echo "PEASS-ng repository already exists. Pulling the latest changes..."
    cd "$HOME/PEASS-ng" && git pull
fi

# Navigate to linPEAS directory
cd "$SCRIPT_DIR" || exit

# Make the linpeas.sh script executable
chmod +x linpeas.sh

# Run linPEAS and log output
echo "Running linPEAS... This may take a while."
./linpeas.sh | tee "$LOG_FILE"

echo "linPEAS scan completed. Results saved to $LOG_FILE."
