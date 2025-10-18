#!/usr/bin/env bash

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
                local results
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
                local results
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
