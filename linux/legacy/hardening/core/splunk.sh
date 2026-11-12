#!/usr/bin/env bash

function setup_splunk {
    print_banner "Installing Splunk"

    if [ "$ANSIBLE" == "true" ]; then
        log_warning "Ansible mode: Skipping Splunk installation."
        return 0
    fi

    local indexer_ip
    indexer_ip=$(get_input_string "What is the Splunk forward server IP? ")
    local installer_url="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main/splunk/splunk.sh"
    local installer_path
    installer_path="$(mktemp /tmp/splunk-install.XXXXXX)"

    if ! wget --no-check-certificate "$installer_url" -O "$installer_path"; then
        log_error "Failed to download Splunk helper script from $installer_url"
        rm -f "$installer_path"
        return 1
    fi

    chmod +x "$installer_path"
    if ! "$installer_path" -f "$indexer_ip"; then
        log_error "Splunk installer script reported an error."
        rm -f "$installer_path"
        return 1
    fi

    rm -f "$installer_path"
    log_success "Splunk installation helper completed."
}
