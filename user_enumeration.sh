#!/bin/bash


#Ethan Hulse 2024
#This script will enumerate all users on the system and check their permissions
#It will log the results to /var/log/user_permissions_audit.log

#++++++++++++++++++++++++++ GLOBAL VARS ++++++++++++++++++++++++#

log_file="/var/log/user_permissions_audit.log"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

####################### Support Functions #######################

function log {
    # Log $1 (string) into the script's log file
    local log_msg="$1"
    
    # Create log file if it does not exist
    [ ! -f "$log_file" ] && touch "$log_file" && chmod 600 "$log_file"

    # Log the message with a timestamp
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $log_msg" | tee -a "$log_file"
}

function check_user_permissions {
    # Check permissions for a given user
    local user="$1"
    local home_dir
    home_dir=$(getent passwd "$user" | cut -d: -f6)

    # Check if the user's home directory exists
    if [ ! -d "$home_dir" ]; then
        log "ERROR: Home directory for user $user does not exist."
        return
    fi

    # Check home directory permissions
    local home_permissions
    home_permissions=$(stat -c "%A" "$home_dir")

    if [[ "$home_permissions" != "drwx------" && "$home_permissions" != "drwxr-x---" ]]; then
        log "WARNING: Insecure permissions on $user's home directory ($home_dir): $home_permissions"
    else
        log "INFO: Home directory permissions for $user are secure ($home_permissions)"
    fi

    # Check for world-writable files in the user's home directory
    local world_writable_files
    world_writable_files=$(find "$home_dir" -xdev -type f -perm -0002 2>/dev/null)

    if [ -n "$world_writable_files" ]; then
        log "WARNING: World-writable files found in $user's home directory:"
        echo "$world_writable_files" | while read -r file; do
            log "  - $file"
        done
    else
        log "INFO: No world-writable files found in $user's home directory."
    fi

    # Check for .ssh directory and permissions
    local ssh_dir="$home_dir/.ssh"
    if [ -d "$ssh_dir" ]; then
        local ssh_permissions
        ssh_permissions=$(stat -c "%A" "$ssh_dir")
        if [[ "$ssh_permissions" != "drwx------" ]]; then
            log "WARNING: Insecure permissions on $user's .ssh directory: $ssh_permissions"
        else
            log "INFO: .ssh directory permissions for $user are secure."
        fi

        # Check authorized_keys file permissions if it exists
        local authorized_keys="$ssh_dir/authorized_keys"
        if [ -f "$authorized_keys" ]; then
            local auth_keys_permissions
            auth_keys_permissions=$(stat -c "%A" "$authorized_keys")
            if [[ "$auth_keys_permissions" != "-rw-------" ]]; then
                log "WARNING: Insecure permissions on $user's authorized_keys file: $auth_keys_permissions"
            else
                log "INFO: authorized_keys file permissions for $user are secure."
            fi
        fi
    fi
}

####################### Main Script #############################

log "Starting user permissions audit."

# Get all users with valid shells (excluding system accounts)
users=$(awk -F':' '/\/bin\/bash|\/bin\/sh/{print $1}' /etc/passwd)

# Iterate through each user and check their permissions
for user in $users; do
    log "Auditing user: $user"
    check_user_permissions "$user"
    log "----------------------------------------"
done

log "User permissions audit completed."
log "Logged to $log_file"
