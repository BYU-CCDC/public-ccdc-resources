#!/usr/bin/env bash

function defend_against_forkbomb {
    print_banner "Defending Against Fork Bombing"

    # Create group 'fork' if it does not exist.
    if ! getent group fork >/dev/null; then
        sudo groupadd fork
        log_info "Group 'fork' created."
    else
        log_info "Group 'fork' already exists."
    fi

    # Get list of users with terminal access (shell in /bin/ or /usr/bin/)
    local user_list
    user_list=$(awk -F: '$1 != "root" && $7 ~ /^\/(bin|usr\/bin)\// { print $1 }' /etc/passwd)
    if [ -n "$user_list" ]; then
        for user in $user_list; do
            sudo usermod -a -G fork "$user"
            log_info "User $user added to group 'fork'."
        done
    else
        log_info "No applicable users found for fork protection."
    fi

    # Backup current limits.conf
    sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak

    # Add process limits if not already present.
    if ! grep -q "^root hard" /etc/security/limits.conf; then
        echo "root hard nproc 1000" | sudo tee -a /etc/security/limits.conf >/dev/null
        log_info "Added 'root hard nproc 1000' to limits.conf."
    else
        log_info "Root nproc limit already set."
    fi

    if ! grep -q "^@fork hard" /etc/security/limits.conf; then
        echo "@fork hard nproc 300" | sudo tee -a /etc/security/limits.conf >/dev/null
        log_info "Added '@fork hard nproc 300' to limits.conf."
    else
        log_info "Fork group nproc limit already set."
    fi
}
