#!/usr/bin/env bash

function audit_running_services {
    print_banner "Auditing Running Services"
    log_info "Listing running services (TCP/UDP listening ports):"
    ss -tuln
}

function disable_other_firewalls {
    print_banner "Disabling existing firewalls"
    if sudo command -v firewalld &>/dev/null; then
        log_info "Disabling firewalld"
        sudo systemctl stop firewalld
        sudo systemctl disable firewalld
    fi
}

function disable_unnecessary_services {
    print_banner "Disabling Unnecessary Services"
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Skipping disabling services."
        return 0
    fi
    read -p "Disable SSHD? (WARNING: may lock you out if remote) (y/N): " disable_sshd
    if [[ "$disable_sshd" =~ ^[Yy]$ ]]; then
        if systemctl is-active sshd &> /dev/null; then
            sudo systemctl stop sshd
            sudo systemctl disable sshd
            log_info "SSHD service disabled."
        else
            log_info "SSHD service not active."
        fi
    fi
    read -p "Disable Cockpit? (y/N): " disable_cockpit
    if [[ "$disable_cockpit" =~ ^[Yy]$ ]]; then
        if systemctl is-active cockpit &> /dev/null; then
            sudo systemctl stop cockpit
            sudo systemctl disable cockpit
            log_info "Cockpit service disabled."
        else
            log_info "Cockpit service not active."
        fi
    fi
}

function check_service_integrity {
    print_banner "Checking Service Binary Integrity"
    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        # Ensure debsums is installed.
        if ! command -v debsums &>/dev/null; then
            log_info "Installing debsums..."
            sudo apt-get install -y debsums
        fi
        local packages=("apache2" "openssh-server" "mysql-server" "postfix" "nginx")
        for pkg in "${packages[@]}"; do
            if dpkg -s "$pkg" &>/dev/null; then
                log_info "Checking integrity for package: $pkg"
                # Run debsums and filter lines indicating failures.
                results=$(sudo debsums "$pkg" 2>/dev/null | grep "FAILED")
                if [ -n "$results" ]; then
                    log_warning "Integrity check FAILED for $pkg:"
                    echo "$results"
                else
                    log_info "$pkg passed integrity check."
                fi
            else
                log_info "Package $pkg is not installed; skipping."
            fi
        done
    elif grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        local packages=("httpd" "openssh" "mariadb-server" "postfix" "nginx")
        for pkg in "${packages[@]}"; do
            if rpm -q "$pkg" &>/dev/null; then
                log_info "Checking integrity for package: $pkg"
                results=$(rpm -V "$pkg")
                if [ -n "$results" ]; then
                    log_warning "Integrity check FAILED for $pkg:"
                    echo "$results"
                else
                    log_info "$pkg passed integrity check."
                fi
            else
                log_info "Package $pkg is not installed; skipping."
            fi
        done
    else
        log_error "Unsupported OS for native binary integrity checking."
    fi
}
