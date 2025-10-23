#!/bin/bash

# Define directories and files
monitorDirectory="/path/to/monitor"       # Directory to monitor for sensitive data
secureDirectory="/path/to/secure"         # Directory to move sensitive files to
logFile="/var/log/dlp_log.txt"            # Log file for DLP actions
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Create the secure directory if it doesn’t exist
if [[ ! -d $secureDirectory ]]; then
    mkdir -p $secureDirectory
    echo "$currentDateTime - Secure directory created at $secureDirectory" | tee -a $logFile
fi

# Define regular expressions for detecting sensitive data
declare -A sensitivePatterns=(
    ["CreditCard"]="\b(?:\d[ -]*?){13,16}\b"                    # Basic credit card number pattern
    ["SSN"]="\b\d{3}-\d{2}-\d{4}\b"                             # Social Security Number pattern
    ["Email"]="\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Email address pattern
)

# Function to check for sensitive data in a file
check_sensitive_data() {
    local filePath="$1"
    local foundSensitiveData=false

    # Read through each pattern and check for matches in the file
    for patternName in "${!sensitivePatterns[@]}"; do
        pattern="${sensitivePatterns[$patternName]}"
        if grep -qE "$pattern" "$filePath"; then
            echo "$currentDateTime - Sensitive data detected ($patternName) in file: $filePath" | tee -a $logFile
            foundSensitiveData=true
        fi
    done

    echo "$foundSensitiveData"
}

# Function to move files containing sensitive data to the secure directory
secure_file() {
    local filePath="$1"
    local fileName=$(basename "$filePath")

    # Move the file to the secure directory
    mv "$filePath" "$secureDirectory/$fileName"
    echo "$currentDateTime - File moved to secure location: $secureDirectory/$fileName" | tee -a $logFile
}

# Function to monitor the directory for sensitive data
monitor_directory() {
    echo "$currentDateTime - Starting DLP scan on directory: $monitorDirectory" | tee -a $logFile

    # Find all files in the directory and scan each one for sensitive data
    find "$monitorDirectory" -type f | while read -r file; do
        if [[ $(check_sensitive_data "$file") == "true" ]]; then
            secure_file "$file"
        fi
    done

    echo "$currentDateTime - DLP scan completed." | tee -a $logFile
}

# Run the directory monitor
monitor_directory
