#!/usr/bin/env bash

WAZUH_REPO_FILE="/etc/yum.repos.d/wazuh.repo"
WAZUH_APT_SOURCE="/etc/apt/sources.list.d/wazuh.list"
WAZUH_GPG_KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
WAZUH_REPO_BASE="https://packages.wazuh.com/4.x"

_add_wazuh_repository() {
    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            if [ ! -f "$WAZUH_APT_SOURCE" ]; then
                curl -fsSL "$WAZUH_GPG_KEY_URL" | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
                echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] ${WAZUH_REPO_BASE}/apt/ stable main" | sudo tee "$WAZUH_APT_SOURCE" >/dev/null
                sudo apt-get update
            fi
            ;;
        dnf|yum)
            if [ ! -f "$WAZUH_REPO_FILE" ]; then
                sudo rpm --import "$WAZUH_GPG_KEY_URL"
                cat <<REPO | sudo tee "$WAZUH_REPO_FILE" >/dev/null
[wazuh]
name=Wazuh repository
baseurl=${WAZUH_REPO_BASE}/yum/
gpgcheck=1
gpgkey=${WAZUH_GPG_KEY_URL}
enabled=1
protect=1
REPO
            fi
            ;;
        zypper)
            if ! sudo zypper lr | grep -q wazuh 2>/dev/null; then
                sudo rpm --import "$WAZUH_GPG_KEY_URL"
                sudo zypper addrepo "${WAZUH_REPO_BASE}/yum/" wazuh
            fi
            ;;
        *)
            log_warning "Unsupported package manager for Wazuh repository setup"
            return 1
            ;;
    esac
}

_install_wazuh_manager() {
    _add_wazuh_repository || return 1

    case "$pm" in
        apt-get)
            sudo apt-get install -y wazuh-manager filebeat || return 1
            ;;
        dnf)
            sudo dnf install -y wazuh-manager filebeat || return 1
            ;;
        yum)
            sudo yum install -y wazuh-manager filebeat || return 1
            ;;
        zypper)
            sudo zypper install -y wazuh-manager filebeat || return 1
            ;;
        *)
            log_warning "Unable to install Wazuh manager on this platform"
            return 1
            ;;
    esac

    sudo systemctl enable wazuh-manager --now || true
    sudo systemctl enable filebeat --now || true

    log_success "Wazuh manager installed and services enabled"
}

_configure_wazuh_agent_manager() {
    local manager_ip="$1"
    local config="/var/ossec/etc/ossec.conf"

    if [ ! -f "$config" ]; then
        log_warning "Wazuh agent configuration file $config not found"
        return 1
    fi

    sudo cp "$config" "${config}.bak" || true
    if sudo sed -i "0,/<address>.*<\/address>/s//<address>${manager_ip}<\/address>/" "$config"; then
        log_info "Updated Wazuh agent manager address to $manager_ip"
    fi
}

_install_wazuh_agent() {
    local manager_ip="$1"

    _add_wazuh_repository || return 1

    case "$pm" in
        apt-get)
            sudo apt-get install -y wazuh-agent || return 1
            ;;
        dnf)
            sudo dnf install -y wazuh-agent || return 1
            ;;
        yum)
            sudo yum install -y wazuh-agent || return 1
            ;;
        zypper)
            sudo zypper install -y wazuh-agent || return 1
            ;;
        *)
            log_warning "Unable to install Wazuh agent on this platform"
            return 1
            ;;
    esac

    if [ -n "$manager_ip" ]; then
        _configure_wazuh_agent_manager "$manager_ip"
    fi

    sudo systemctl enable wazuh-agent --now || true
    log_success "Wazuh agent installed and started"
}

run_wazuh_installation() {
    print_banner "Wazuh Deployment"

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    local choice manager_ip
    if [ "$ANSIBLE" == "true" ]; then
        choice="${WAZUH_ROLE:-skip}"
        manager_ip="${WAZUH_MANAGER_IP:-}"
    else
        echo "Select Wazuh role to install:"
        echo "  1) Manager"
        echo "  2) Agent"
        echo "  3) Skip"
        choice=$(get_input_string "Enter choice [3]: ")
        choice=${choice:-3}
        if [ "$choice" = "2" ]; then
            manager_ip=$(get_input_string "Enter Wazuh manager IP/hostname (leave blank to skip configuration): ")
        fi
    fi

    case "$choice" in
        1|manager|Manager)
            _install_wazuh_manager || log_warning "Wazuh manager installation failed"
            ;;
        2|agent|Agent)
            if [ "$ANSIBLE" == "true" ] && [ -z "$manager_ip" ]; then
                manager_ip="$WAZUH_MANAGER_IP"
            fi
            _install_wazuh_agent "$manager_ip" || log_warning "Wazuh agent installation failed"
            ;;
        *)
            log_info "Skipping Wazuh deployment"
            ;;
    esac
}

