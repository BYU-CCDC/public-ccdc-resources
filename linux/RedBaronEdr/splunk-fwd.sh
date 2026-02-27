#!/bin/bash

LOG_PATH="/var/log/redbaronedr/detections.log"

# Check if the file DOES NOT exist
if [ ! -f "$LOG_PATH" ]; then
    mkdir -p "$(dirname "$LOG_PATH")"
    touch "$LOG_PATH"
    echo "Created: $LOG_PATH"
else
    echo "File already exists at: $LOG_PATH"
fi

if [ ! -f /opt/splunkforwarder/bin/splunk ]; then
    echo "Splunk Forwarder not found. Please install it before running this script."
    exit 1
fi

sudo /opt/splunkforwarder/bin/splunk add monitor "$LOG_PATH" -index edr