#!/usr/bin/env bash

function run_rkhunter {
    print_banner "Running Rootkit Hunter"

    local confirm
    if [ "$ANSIBLE" == "true" ]; then
        confirm="${RKHUNTER_SCAN:-n}"
    else
        confirm=$(get_input_string "Would you like to run rkhunter (Rootkit Hunter) scan? (y/N): ")
    fi

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Skipping rkhunter scan as per configuration."
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y rkhunter
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y rkhunter
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y rkhunter
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y rkhunter
    else
        log_error "Could not determine package manager to install rkhunter."
        return 1
    fi

    log_info "Running rkhunter scan. Please review the output for warnings."
    sudo rkhunter --update || true
    sudo rkhunter --check --sk
}

