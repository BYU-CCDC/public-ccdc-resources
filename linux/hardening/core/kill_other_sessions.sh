#!/usr/bin/env bash

function kill_other_sessions {
    # Get the current TTY device (e.g., /dev/pts/0)
    local current_tty=$(tty 2>/dev/null)
    
    # Check if TTY is valid; exit if not
    if [ -z "$current_tty" ]; then
        log_error "Error: Could not determine current TTY"
        return 1
    fi
    
    # Get the current user (should be root since script requires root privileges)
    local current_user=$(whoami)
    
    # Normalize TTY name by removing '/dev/' prefix to match 'who' output (e.g., pts/0)
    local current_tty_short=$(echo "$current_tty" | sed 's|^/dev/||')
    
    # Get list of other TTYs for the current user, excluding the current TTY
    local other_ttys=$(who | awk -v user="$current_user" -v tty="$current_tty_short" '$1 == user && $2 != tty {print $2}')
    
    # If no other sessions exist, inform and exit
    if [ -z "$other_ttys" ]; then
        log_info "No other sessions found for user $current_user"
        return 0
    fi
    
    # Iterate through other TTYs and terminate their processes
    for tty in $other_ttys; do
        log_info "Killing session on /dev/$tty"
        # Get PIDs of processes attached to this TTY
        local pids=$(ps -t "$tty" -o pid= 2>/dev/null)
        for pid in $pids; do
            # Kill each process, suppressing errors if PID no longer exists
            kill "$pid" 2>/dev/null
        done
    done
    
    return 0
}

