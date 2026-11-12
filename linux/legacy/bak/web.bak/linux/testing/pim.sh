#!/bin/bash

# Define directories and files
logFile="/var/log/pim_audit_log.txt"      # Log file for PIM actions
alertMode=false                           # Set to true to disable non-essential accounts
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# List of essential users (modify as needed)
essentialUsers=("root" "admin")

# Create log file if it doesn’t exist
touch "$logFile"

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Audit Privileged Users
log_event "Starting privileged user audit."

# Get users with sudo/root access
privilegedUsers=$(getent group sudo | awk -F: '{print $4}' | tr ',' '\n')

log_event "Privileged users with sudo/root access:"
echo "$privilegedUsers" | while read -r user; do
    if [[ -n "$user" ]]; then
        log_event " - $user"
    fi
done

# Step 2: Disable Non-Essential Accounts if Alert Mode is On
if [[ "$alertMode" == true ]]; then
    log_event "Alert mode enabled: Disabling non-essential accounts."

    echo "$privilegedUsers" | while read -r user; do
        # Check if the user is essential
        if [[ ! " ${essentialUsers[@]} " =~ " ${user} " ]]; then
            log_event "Disabling non-essential account: $user"
            sudo usermod -L "$user"  # Lock the user account
        fi
    done
else
    log_event "Alert mode is disabled. No accounts were locked."
fi

# Step 3: Re-enable Non-Essential Accounts (optional)
# Run this section if you want to unlock accounts after a certain time.
# To re-enable, set `alertMode=false` and run this section manually.

# echo "$privilegedUsers" | while read -r user; do
#     if [[ ! " ${essentialUsers[@]} " =~ " ${user} " ]]; then
#         log_event "Re-enabling account: $user"
#         sudo usermod -U "$user"  # Unlock the user account
#     fi
# done

log_event "Privileged user audit and account management completed."
