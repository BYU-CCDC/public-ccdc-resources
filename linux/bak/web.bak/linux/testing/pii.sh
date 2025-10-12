#!/bin/bash

# Define directories and log file
monitorDirectory="/path/to/scan"        # Directory to scan for PII
logFile="/var/log/pii_detection_log.txt" # Log file for findings
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Create log file if it doesn't exist
touch "$logFile"

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

log_event "Starting PII scan in $monitorDirectory."

# Define regex patterns for PII detection
declare -A patterns
patterns["Email"]="[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
patterns["SSN"]="\b\d{3}-\d{2}-\d{4}\b"
patterns["CreditCard"]="\b(?:\d[ -]*?){13,16}\b"
patterns["Phone"]="\b\d{3}[-.\s]??\d{3}[-.\s]??\d{4}\b"

# Scan each file in the directory
find "$monitorDirectory" -type f | while read -r file; do
    for patternName in "${!patterns[@]}"; do
        # Search for the pattern in the file
        matches=$(grep -Eon "${patterns[$patternName]}" "$file")
        
        # Log any matches found
        if [[ -n "$matches" ]]; then
            log_event "Detected $patternName in $file:"
            echo "$matches" | tee -a "$logFile"
        fi
    done
done

log_event "PII scan completed."
