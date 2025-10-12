
# Once we get to a comfortable position, use this to check for changes, and considering the hashes don't match, restore to the previous? 

# sudo apt update
# sudo apt install inotify-tools -y

#!/bin/bash

# Define variables
monitorDirectory="/path/to/monitor"            # Directory to monitor
backupDirectory="/path/to/backup"              # Directory to store backup files
hashFile="/path/to/hash_baseline.txt"          # File to store baseline hashes
logFile="/var/log/fim_log.txt"                 # Log file
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Ensure necessary directories and files exist
mkdir -p "$backupDirectory"
touch "$hashFile" "$logFile"

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Create Baseline Hashes
create_baseline_hashes() {
    log_event "Creating baseline hashes for files in $monitorDirectory."
    find "$monitorDirectory" -type f | while read -r file; do
        hash=$(sha256sum "$file")
        echo "$hash" >> "$hashFile"
        # Backup the original file
        rsync -a "$file" "$backupDirectory"
    done
    log_event "Baseline hashes created and files backed up."
}

# Step 2: Check and Restore Modified Files
check_and_restore_file() {
    local filePath="$1"
    local fileHash=$(sha256sum "$filePath" | awk '{print $1}')
    local baselineHash=$(grep "$filePath" "$hashFile" | awk '{print $1}')
    
    if [[ "$fileHash" != "$baselineHash" ]]; then
        # Log the modification and restore file from backup
        log_event "Modification detected in $filePath. Restoring from backup."
        rsync -a "$backupDirectory/$(basename "$filePath")" "$filePath"
    else
        log_event "No changes detected in $filePath."
    fi
}

# Step 3: Start Monitoring for Changes
log_event "Starting File Integrity Monitoring on directory: $monitorDirectory"

# Create baseline hashes if not already done
if [[ ! -s "$hashFile" ]]; then
    create_baseline_hashes
else
    log_event "Using existing baseline hashes."
fi

# Monitor directory for changes and trigger hash check and restore if needed
inotifywait -m -r -e modify -e create -e delete -e move "$monitorDirectory" --format '%w%f' | while read -r modifiedFile
do
    log_event "Change detected: $modifiedFile"
    check_and_restore_file "$modifiedFile"
done
