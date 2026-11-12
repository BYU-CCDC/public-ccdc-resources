#!/bin/bash

# Nmap Network Scan Automation Script
# This script automates Nmap scanning for open ports and vulnerabilities on a specified network range.

# Define Variables
NETWORK_RANGE="192.168.1.0/24"  # Set your network range here
OUTPUT_DIR="/tmp/nmap_scans"
PORT_SCAN_OUTPUT="$OUTPUT_DIR/nmap_port_scan_$(date +'%Y%m%d_%H%M%S').txt"
VULN_SCAN_OUTPUT="$OUTPUT_DIR/nmap_vuln_scan_$(date +'%Y%m%d_%H%M%S').txt"
VULN_SCRIPT="--script vuln"  # Nmap script for vulnerability scan

# Ensure Output Directory Exists
mkdir -p "$OUTPUT_DIR"

# Function to Check if Nmap is Installed
check_nmap() {
    if ! command -v nmap &> /dev/null; then
        echo "Nmap is not installed. Please install Nmap to continue."
        exit 1
    fi
}

# Function to Run Nmap Port Scan
run_port_scan() {
    echo "Running Nmap port scan on $NETWORK_RANGE..."
    nmap -p- -T4 -oN "$PORT_SCAN_OUTPUT" "$NETWORK_RANGE"
    echo "Port scan completed. Results saved to $PORT_SCAN_OUTPUT"
}

# Function to Run Nmap Vulnerability Scan
run_vuln_scan() {
    echo "Running Nmap vulnerability scan on $NETWORK_RANGE..."
    nmap $VULN_SCRIPT -T4 -oN "$VULN_SCAN_OUTPUT" "$NETWORK_RANGE"
    echo "Vulnerability scan completed. Results saved to $VULN_SCAN_OUTPUT"
}

# Main Execution
check_nmap

# Prompt User for Scan Type
echo "Select scan type:"
echo "1: Port Scan only"
echo "2: Vulnerability Scan only"
echo "3: Both Port and Vulnerability Scans"
read -p "Enter your choice (1, 2, or 3): " scan_type

case "$scan_type" in
    1)
        run_port_scan
        ;;
    2)
        run_vuln_scan
        ;;
    3)
        run_port_scan
        sleep 5  # Brief pause before running the next scan
        run_vuln_scan
        ;;
    *)
        echo "Invalid selection. Please enter 1, 2, or 3."
        exit 1
        ;;
esac

echo "Scan completed. Results can be found in $OUTPUT_DIR"
