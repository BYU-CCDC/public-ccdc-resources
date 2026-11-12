#!/usr/bin/env bash

function configure_login_banner {
    print_banner "Configuring Login Banner"

    # Unified pre-auth banner text (console + SSH)
    local default_banner="WARNING: UNAUTHORIZED ACCESS TO THIS NETWORK DEVICE IS PROHIBITED
You must have explicit, authorized permission to access or configure this device.
Unauthorized attempts to access and misuse of this system may result in prosecution.
All activities performed on this device are logged and monitored.

WARNING:
This computer system, including all related equipment, networks, and network devices, is for authorized users only.
All activity on this network is being monitored and logged for lawful purposes, including verifying authorized use.

Data collected including logs will be used to investigate and prosecute unauthorized or improper access.
By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.

All employees must take reasonable steps to prevent unauthorized access to the system, including protecting passwords and other login information.
Employees are required to notify their administrators immediately of any known or suspected breach of security and to do their best to stop such a breach."

    # Write banner to BOTH console (/etc/issue) and SSH (/etc/issue.net)
    for banner_file in /etc/issue /etc/issue.net; do
        echo "$default_banner" | sudo tee "$banner_file" >/dev/null
        sudo chown root:root "$banner_file" 2>/dev/null || true
        sudo chmod 0644 "$banner_file" 2>/dev/null || true
        log_info "Login banner written to $banner_file."
    done

    # Configure sshd to use /etc/issue.net as the pre-auth Banner
    local ssh_config="/etc/ssh/sshd_config"
    if [ -f "$ssh_config" ]; then
        # Remove any existing Banner directives (with or without leading spaces/comments)
        sudo sed -i -E '/^\s*#?\s*Banner\s+/d' "$ssh_config"
        echo "Banner /etc/issue.net" | sudo tee -a "$ssh_config" >/dev/null
        log_info "Updated $ssh_config to use the login banner."

        # Find correct SSH service name and restart safely
        local svc="sshd"
        if systemctl list-unit-files | grep -q '^ssh\.service'; then
            svc="ssh"
        fi

        if command -v sshd >/dev/null 2>&1; then
            # Validate config before restart
            if sudo sshd -t 2>/dev/null; then
                if command -v systemctl >/dev/null 2>&1; then
                    sudo systemctl restart "$svc"
                else
                    sudo service "$svc" restart
                fi
                log_info "SSH service ($svc) restarted."
            else
                log_error "sshd_config test failed; not restarting. Please review $ssh_config."
            fi
        else
            # Fallback restart if sshd binary name differs
            if command -v systemctl >/dev/null 2>&1; then
                sudo systemctl restart "$svc" || true
            else
                sudo service "$svc" restart || true
            fi
        fi
    else
        log_error "SSH configuration file not found at $ssh_config."
    fi
}

function secure_ssh {
    print_banner "Securing SSH"

    # Step 1: Check if SSH service is installed
    if command -v sshd &>/dev/null; then
        service_name="sshd"
    elif command -v ssh &>/dev/null; then
        service_name="ssh"
    else
        log_info "SSH service not found. Attempting to install..."

        # Attempt to install SSH based on the system's package manager
        if command -v apt-get &>/dev/null; then
            update_package_cache
            sudo apt-get install -y openssh-server
        elif command -v yum &>/dev/null; then
            sudo yum install -y openssh-server
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y openssh-server
        elif command -v zypper &>/dev/null; then
            sudo zypper install -y openssh
        else
            log_error "ERROR: Could not determine package manager to install SSH."
            return 1
        fi

        # Verify installation
        if command -v sshd &>/dev/null; then
            service_name="sshd"
        elif command -v ssh &>/dev/null; then
            service_name="ssh"
        else
            log_error "ERROR: Failed to install SSH service."
            return 1
        fi
    fi

    # Step 2: Check if SSH service is running
    if ! sudo systemctl is-active --quiet "$service_name"; then
        log_info "SSH service is not running. Attempting to start..."
        sudo systemctl start "$service_name"
        if ! sudo systemctl is-active --quiet "$service_name"; then
            log_error "ERROR: Failed to start SSH service."
            return 1
        fi
    fi

    # Step 3: Ensure SSH service is enabled to start on boot
    if ! sudo systemctl is-enabled --quiet "$service_name"; then
        log_info "Enabling SSH service to start on boot..."
        sudo systemctl enable "$service_name"
    fi

    # Step 4: Apply SSH hardening
    config_file="/etc/ssh/sshd_config"
    if [ ! -f "$config_file" ]; then
        log_error "ERROR: SSH configuration file not found: $config_file"
        return 1
    fi

    # Backup the original configuration file
    sudo cp "$config_file" "${config_file}.bak"
    log_info "Backed up $config_file to ${config_file}.bak"

    # Apply hardening configurations
    ## Disable root login
    sudo sed -i '/^PermitRootLogin/d' "$config_file"
    echo "PermitRootLogin no" | sudo tee -a "$config_file" >/dev/null

    ## Set login grace time to 1 minute
    sudo sed -i '/^LoginGraceTime/d' "$config_file"
    echo "LoginGraceTime 1m" | sudo tee -a "$config_file" >/dev/null

    ## Set idle timeout (10 minutes)
    sudo sed -i '/^ClientAliveInterval/d' "$config_file"
    sudo sed -i '/^ClientAliveCountMax/d' "$config_file"
    echo "ClientAliveInterval 600" | sudo tee -a "$config_file" >/dev/null
    echo "ClientAliveCountMax 0" | sudo tee -a "$config_file" >/dev/null

    ## Deny empty passwords
    sudo sed -i '/^PermitEmptyPasswords/d' "$config_file"
    echo "PermitEmptyPasswords no" | sudo tee -a "$config_file" >/dev/null

    ## Use IPv4 only
    sudo sed -i '/^AddressFamily/d' "$config_file"
    echo "AddressFamily inet" | sudo tee -a "$config_file" >/dev/null

    ## Disable DNS lookups
    sudo sed -i '/^UseDNS/d' "$config_file"
    echo "UseDNS no" | sudo tee -a "$config_file" >/dev/null

    # Step 5: Test and apply the new configuration
    if sudo sshd -t; then
        # Restart the SSH service
        sudo systemctl restart "$service_name"
        log_info "SSH hardening applied and $service_name restarted successfully."
    else
        log_error "ERROR: SSH configuration test failed. Restoring original configuration."
        sudo cp "${config_file}.bak" "$config_file"
        sudo systemctl restart "$service_name"
        return 1
    fi
}
