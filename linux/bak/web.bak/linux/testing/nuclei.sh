#!/bin/bash

# Nuclei Automation Script in Bash
# This script downloads, installs (if needed), updates templates, and runs Nuclei for vulnerability scanning.

# Define variables
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip"
NUCLEI_ZIP="/tmp/nuclei.zip"
INSTALL_DIR="/usr/local/bin"
TEMPLATES_DIR="$HOME/nuclei-templates"
OUTPUT_FILE="$HOME/nuclei_scan_$(date +'%Y%m%d_%H%M%S').txt"

# Function to check if Nuclei is installed
function check_nuclei_installed {
    if ! command -v nuclei &> /dev/null; then
        echo "Nuclei is not installed. Installing Nuclei..."
        install_nuclei
    else
        echo "Nuclei is already installed."
    fi
}

# Function to download and install Nuclei
function install_nuclei {
    echo "Downloading Nuclei..."
    wget -q -O "$NUCLEI_ZIP" "$NUCLEI_URL"
    unzip -qo "$NUCLEI_ZIP" -d "$INSTALL_DIR"
    rm -f "$NUCLEI_ZIP"
    echo "Nuclei installed successfully."
}

# Function to update Nuclei templates
function update_templates {
    echo "Updating Nuclei templates..."
    if [ ! -d "$TEMPLATES_DIR" ]; then
        mkdir -p "$TEMPLATES_DIR"
    fi
    nuclei -update-templates -silent
    echo "Templates updated successfully."
}

# Function to run a Nuclei scan
function run_nuclei_scan {
    local target=$1
    local template_type=$2
    local template_option=""

    if [ "$template_type" != "default" ]; then
        template_option="-t $TEMPLATES_DIR/$template_type"
    fi

    echo "Running Nuclei scan on $target with template type: $template_type..."
    nuclei -u "$target" $template_option -o "$OUTPUT_FILE" -silent
    echo "Scan completed. Results saved to $OUTPUT_FILE"
}

# Main script execution
check_nuclei_installed
update_templates

# Prompt user for target URL and template type
read -p "Enter target URL or IP (e.g., https://example.com): " target
read -p "Enter template type (default, cves, misconfigurations, exposures): " template_choice

# Run the Nuclei scan based on user input
run_nuclei_scan "$target" "$template_choice"
