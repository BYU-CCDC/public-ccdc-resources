#!/usr/bin/env bash

function configure_security_modules {
    print_banner "Configuring Security Modules (SELinux & AppArmor)"

    # Detect OS/distribution
    local distro=""
    local release_file="/etc/os-release"
    if [ -f "$release_file" ]; then
        # shellcheck disable=SC1090
        . "$release_file"
        distro=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
    fi

    # Decide which module to attempt installing based on distro
    case "$distro" in
        # Red Hat, CentOS, Fedora, Rocky, Alma, etc.
        rhel|centos|fedora|rocky|almalinux)
            log_info "Detected a RHEL-like OS ($distro). Attempting SELinux setup..."
            setup_selinux_rhel
            ;;
        # Debian, Ubuntu (and possibly Linux Mint which also says 'ubuntu' in /etc/os-release)
        debian|ubuntu|linuxmint)
            log_info "Detected a Debian-like OS ($distro). Attempting AppArmor setup..."
            setup_apparmor_debian
            ;;
        # openSUSE or SLES often uses AppArmor by default
        opensuse*)
            log_info "Detected openSUSE ($distro). Attempting AppArmor setup..."
            setup_apparmor_debian  # same function works for openSUSE if it has zypper
            ;;
        # fallback
        *)
            log_warning "Unrecognized distro: $distro"
            log_warning "Attempting generic check for apt-get or zypper or yum to decide..."
            if command -v apt-get &>/dev/null; then
                # Usually means Debian/Ubuntu
                setup_apparmor_debian
            elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
                # Usually means RHEL-based
                setup_selinux_rhel
            elif command -v zypper &>/dev/null; then
                # Usually openSUSE-based
                setup_apparmor_debian
            else
                log_error "Could not determine how to install SELinux or AppArmor on this OS. Aborting."
                return 1
            fi
            ;;
    esac
}

function setup_selinux_rhel {
    # Optional prompt for user
    read -p "Would you like to install/configure SELinux in Enforcing mode? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Skipping SELinux setup."
        return 0
    fi

    log_info "Installing SELinux-related packages..."
    if command -v yum &>/dev/null; then
        sudo yum install -y selinux-policy selinux-policy-targeted policycoreutils
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y selinux-policy selinux-policy-targeted policycoreutils
    else
        log_error "No recognized package manager found for SELinux installation on a RHEL-like OS."
        return 1
    fi

    log_info "Ensuring SELinux is set to enforcing..."
    if [ -f /etc/selinux/config ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    fi

    # Attempt to set enforce at runtime
    if command -v setenforce &>/dev/null; then
        sudo setenforce 1 || log_warning "Could not setenforce 1. Check if SELinux is disabled at boot level."
    fi

    log_info "SELinux packages installed. SELinux is configured to enforcing in /etc/selinux/config."
    log_info "If the system was previously in 'disabled' mode, a reboot may be required for full SELinux enforcement."
}

function setup_apparmor_debian {
    # Optional prompt for user
    read -p "Would you like to install/configure AppArmor? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Skipping AppArmor setup."
        return 0
    fi

    log_info "Installing AppArmor-related packages..."

    # For Debian/Ubuntu
    if command -v apt-get &>/dev/null; then
        update_package_cache
        sudo apt-get install -y apparmor apparmor-profiles apparmor-utils

        # Ensure service is enabled
        if command -v systemctl &>/dev/null; then
            sudo systemctl enable apparmor
            sudo systemctl start apparmor
        fi

        # Enforce all profiles or do something more selective
        # By default, you can do: 
        #   sudo aa-enforce /etc/apparmor.d/*
        # or you can just let the system handle it if the profiles are installed

        log_info "AppArmor installed and started. Profiles are enforced if present."
    elif command -v zypper &>/dev/null; then
        # openSUSE approach
        sudo zypper refresh
        sudo zypper install -y apparmor-profiles apparmor-utils
        # In openSUSE, AppArmor might already be installed and enabled by default
        # etc.
        sudo systemctl enable apparmor
        sudo systemctl start apparmor
        log_info "AppArmor installed/enabled under openSUSE."
    else
        log_error "Could not find apt-get or zypper. Aborting AppArmor setup."
        return 1
    fi
}
