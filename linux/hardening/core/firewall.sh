#!/usr/bin/env bash
set -o pipefail

# Persistence & PM
PACKAGE_CACHE_UPDATED="false"

function detect_system_info {
    print_banner "Detecting system info"
    log_info "Detecting package manager"

    if command -v apt-get &>/dev/null; then
        log_info "apt/apt-get detected (Debian-based OS)"
        if [ "${PACKAGE_CACHE_UPDATED:-false}" != "true" ]; then
            log_info "Updating package list"
            sudo apt-get update
            PACKAGE_CACHE_UPDATED="true"
        else
            log_info "Package list already refreshed during this session"
        fi
        pm="apt-get"
    elif command -v dnf &>/dev/null; then
        log_info "dnf detected (Fedora-based OS)"
        pm="dnf"
    elif command -v zypper &>/dev/null; then
        log_info "zypper detected (OpenSUSE-based OS)"
        pm="zypper"
    elif command -v yum &>/dev/null; then
        log_info "yum detected (RHEL-based OS)"
        pm="yum"
    else
        log_error "ERROR: Could not detect package manager"
        exit 1
    fi

    log_info "Detecting sudo group"
    local groups
    groups=$(compgen -g)
    if echo "$groups" | grep -q '^sudo$'; then
        log_info "sudo group detected"
        sudo_group='sudo'
    elif echo "$groups" | grep -q '^wheel$'; then
        log_info "wheel group detected"
        sudo_group='wheel'
    else
        log_error "ERROR: could not detect sudo group"
        exit 1
    fi
}

function remove_packages {
    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    if [ $# -eq 0 ]; then
        return 0
    fi

    case "$pm" in
        apt-get)
            sudo apt-get purge -y "$@" >/dev/null 2>&1 || true
            ;;
        yum|dnf)
            sudo "$pm" remove -y "$@" >/dev/null 2>&1 || true
            ;;
        zypper)
            sudo zypper remove -y "$@" >/dev/null 2>&1 || true
            ;;
        *)
            ;;
    esac
}

function install_prereqs {
    print_banner "Installing prerequisites"
    if [ -z "$pm" ]; then
        log_warning "Package manager not detected yet; running detect_system_info first."
        detect_system_info
    fi
    sudo $pm install -y zip unzip wget curl acl
}

function update_package_cache {
    if [ -z "$pm" ]; then
        detect_system_info
    fi
    if [ "${PACKAGE_CACHE_UPDATED:-false}" == "true" ]; then
        return 0
    fi
    case "$pm" in
        apt-get)
            log_info "Refreshing apt package cache"
            sudo apt-get update
            ;;
        yum|dnf)
            log_info "Refreshing $pm metadata"
            sudo "$pm" makecache -y
            ;;
        zypper)
            log_info "Refreshing zypper repositories"
            sudo zypper refresh
            ;;
        *)
            log_warning "Package cache refresh not implemented for package manager: $pm"
            return 1
            ;;
    esac
    PACKAGE_CACHE_UPDATED="true"
}

# iptables persistence
function ensure_iptables_persistence {
    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        if ! command -v netfilter-persistent >/dev/null 2>&1; then
            log_info "Installing iptables-persistent (provides netfilter-persistent)"
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent || {
                log_error "Failed to install iptables-persistent"; return 1; }
        fi
        sudo systemctl enable netfilter-persistent >/dev/null 2>&1 || true
        log_info "netfilter-persistent enabled for boot-time restore"
    elif grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        if ! systemctl list-unit-files | awk '{print $1}' | grep -qx "iptables.service"; then
            log_info "Installing iptables-services for boot-time restore"
            sudo dnf install -y iptables-services 2>/dev/null || sudo yum install -y iptables-services || {
                log_error "Failed to install iptables-services"; return 1; }
        fi
        sudo systemctl enable iptables >/dev/null 2>&1 || true
        log_info "iptables.service enabled for boot-time restore"
    elif grep -qi 'suse' /etc/os-release; then
        if ! command -v iptables-save >/dev/null 2>&1; then
            sudo zypper install -y iptables || true
        fi
        if systemctl list-unit-files | awk '{print $1}' | grep -qx "iptables.service"; then
            sudo systemctl enable iptables >/dev/null 2>&1 || true
            log_info "iptables.service enabled for boot-time restore (SUSE)"
        else
            log_warning "SUSE variant may lack iptables.service; prefer firewalld/nftables if available."
        fi
    else
        log_warning "Unknown distro for iptables persistence; please validate manually."
    fi
}

function restart_iptables_restore_service {
    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        if command -v netfilter-persistent >/dev/null 2>&1; then
            log_info "Restarting netfilter-persistent to restore saved rules"
            sudo systemctl restart netfilter-persistent || sudo netfilter-persistent reload || true
        fi
    elif grep -qi 'fedora\|centos\|rhel\|suse' /etc/os-release; then
        if systemctl list-units --type=service --all | grep -q '^iptables\.service'; then
            log_info "Restarting iptables.service to restore saved rules"
            sudo systemctl restart iptables || true
        fi
    fi
}

function verify_iptables_restored_sample {
    log_info "Verifying restored rules (sample):"
    sudo iptables -S | head -n 25 || sudo iptables -L -n -v | head -n 25
}

# Save helpers 
function backup_current_iptables_rules {
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
        log_info "Iptables rules saved to /etc/sysconfig/iptables"
    elif grep -qi 'suse' /etc/os-release; then
        sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
        log_info "Iptables rules saved to /etc/sysconfig/iptables (SUSE)"
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        sudo mkdir -p /etc/iptables
        sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
        log_info "Iptables rules saved to /etc/iptables/rules.v4"
    else
        log_info "Unknown OS. Please ensure iptables rules are saved manually if needed."
    fi
}

function save_iptables_rules_persistent {
    print_banner "Saving iptables rules & enabling persistence"
    backup_current_iptables_rules
    ensure_iptables_persistence
    restart_iptables_restore_service
    verify_iptables_restored_sample
    log_info "Saved and configured for boot-time restore."
}

# Firewall framework cleanup
function disable_existing_firewalls {
    print_banner "Disabling alternate firewall frameworks"

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    local action_taken="false"

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "firewalld.service"; then
            log_info "Stopping firewalld service"
            sudo systemctl stop firewalld 2>/dev/null || true
            sudo systemctl disable firewalld 2>/dev/null || true
            sudo systemctl mask firewalld 2>/dev/null || true
            action_taken="true"
        fi

        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "nftables.service"; then
            log_info "Stopping nftables service"
            sudo systemctl stop nftables 2>/dev/null || true
            sudo systemctl disable nftables 2>/dev/null || true
            sudo systemctl mask nftables 2>/dev/null || true
            action_taken="true"
        fi

        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "ufw.service"; then
            log_info "Disabling ufw.service"
            sudo systemctl stop ufw 2>/dev/null || true
            sudo systemctl disable ufw 2>/dev/null || true
            action_taken="true"
        fi
    fi

    if command -v firewall-cmd >/dev/null 2>&1; then
        log_info "Removing firewalld tooling"
        remove_packages firewalld
        action_taken="true"
    fi

    if command -v nft >/dev/null 2>&1; then
        log_info "Flushing nftables ruleset"
        sudo nft flush ruleset 2>/dev/null || true
        log_info "Removing nftables tooling"
        remove_packages nftables
        action_taken="true"
    fi

    if command -v ufw >/dev/null 2>&1; then
        log_info "Resetting and removing UFW"
        sudo ufw --force disable 2>/dev/null || true
        sudo ufw --force reset 2>/dev/null || true
        remove_packages ufw
        action_taken="true"
    fi

    if [ "$action_taken" = "true" ]; then
        log_info "Alternate firewall services have been disabled."
    else
        log_info "No alternate firewall services detected."
    fi
}

function prompt_read_line {
    local __resultvar="$1"
    local prompt="$2"
    local default_value="${3:-}"
    local input=""

    if [ "${ANSIBLE:-false}" == "true" ]; then
        printf -v "$__resultvar" '%s' "$default_value"
        return 0
    fi

    if [ -n "$prompt" ]; then
        read -e -r -p "$prompt" input
    else
        read -e -r input
    fi

    if [ -z "$input" ] && [ -n "$default_value" ]; then
        input="$default_value"
    fi

    printf -v "$__resultvar" '%s' "$input"
}

# FastFW Implementation
function yesno() {
    local default_choice="${1:-}"
    local prompt_text="${2:-}"
    local normalized_default=""

    if [ -n "$default_choice" ]; then
        normalized_default="$(tr '[:upper:]' '[:lower:]' <<<"$default_choice" | head -c1)"
    fi

    if [ "${ANSIBLE:-false}" == "true" ]; then
        [ "$normalized_default" == "y" ]
        return $?
    fi

    if [ -n "$prompt_text" ]; then
        case "$normalized_default" in
            y) prompt_text+=" (Y/n) " ;;
            n) prompt_text+=" (y/N) " ;;
            *) prompt_text+=" (y/n) " ;;
        esac
    fi

    local response=""
    prompt_read_line response "$prompt_text" ""

    if [ -z "$response" ] && [ -n "$normalized_default" ]; then
        response="$normalized_default"
    fi

    response="$(tr '[:upper:]' '[:lower:]' <<<"$response" | head -c1)"

    if [ "$response" == "y" ]; then
        return 0
    elif [ "$response" == "n" ]; then
        return 1
    fi

    [ "$normalized_default" == "y" ]
}

function genPortList() {
    local chain="$1"
    local proto="$2"
    local prompt_text="$3"
    shift 3
    local extra_args=("$@")

    if [ "${ANSIBLE:-false}" == "true" ]; then
        return 0
    fi

    local ports
    ports=$(prompt_space_separated_list "$prompt_text")

    for port in $ports; do
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            local cmd=(sudo iptables -A "$chain" -p "$proto" --dport "$port")
            if [ ${#extra_args[@]} -gt 0 ]; then
                cmd+=("${extra_args[@]}")
            fi
            cmd+=(-j ACCEPT)
            "${cmd[@]}"
            if [ ${#extra_args[@]} -gt 0 ]; then
                log_info "Allowing $chain $proto $port (${extra_args[*]})"
            else
                log_info "Allowing $chain $proto port $port"
            fi
        elif [ -n "$port" ]; then
            log_warning "Skipping invalid port entry '$port'"
        fi
    done
}

function iptables_base_policy_interactive {
    print_banner "Interactive IPtables Base Policy"

    if [ "$EUID" -ne 0 ]; then
        log_error "Please run with sudo/root"
        return 1
    fi

    disable_existing_firewalls

    local existing_rules
    existing_rules="$(sudo iptables --list-rules | wc -l | awk '{print $1}')"
    if (( existing_rules > 3 )); then
        if yesno n "Existing iptables rules detected. Flush them now?"; then
            log_info "Flushing current iptables rules"
            sudo iptables -F
            sudo iptables -X
            sudo iptables -Z
        else
            log_info "Keeping existing iptables rules and appending baseline allowances"
        fi
    else
        sudo iptables -F
        sudo iptables -X
        sudo iptables -Z
        log_info "Initialized clean iptables rule set"
    fi

    log_info "Applying baseline loopback and stateful allowances"
    sudo iptables -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT  -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT  -p icmp --icmp-type echo-request -j ACCEPT
    sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

    local splunk_ip=""
    prompt_read_line splunk_ip "Splunk indexer IP (leave blank to skip): "
    if [ -n "$splunk_ip" ]; then
        sudo iptables -A OUTPUT -d "$splunk_ip" -p tcp --dport 9997 -j ACCEPT
        log_info "Allowing Splunk indexer at $splunk_ip (tcp/9997)"
    fi

    if [ -n "${SSH_CLIENT:-}" ]; then
        local ssh_source
        ssh_source="$(cut -f1 -d' ' <<<"${SSH_CLIENT}")"
        if yesno y "SSH detected from $ssh_source. Whitelist client?"; then
            sudo iptables -A INPUT -s "$ssh_source" -p tcp --dport 22 -j ACCEPT
            log_info "Whitelisted SSH client $ssh_source"
        fi
    fi

    local dns_ips
    dns_ips=$(prompt_space_separated_list "DNS server IPs for outbound udp/53 (space-separated, blank to skip): ")
    for ip in $dns_ips; do
        sudo iptables -A OUTPUT -d "$ip" -p udp --dport 53 -j ACCEPT
        log_info "Allowing DNS queries to $ip"
    done

    for chain in INPUT OUTPUT; do
        for proto in tcp udp; do
            genPortList "$chain" "$proto" "Space-separated list of $chain $proto ports/services (leave blank for none): "
        done
    done

    if yesno n "Would you like to whitelist traffic to a specific IP or subnet?"; then
        local whitelist_target=""
        prompt_read_line whitelist_target "IP or subnet (CIDR): "
        if [ -n "$whitelist_target" ]; then
            for proto in tcp udp; do
                genPortList INPUT "$proto" "Allowed INPUT $proto ports from $whitelist_target (blank for none): " -s "$whitelist_target"
            done
            for proto in tcp udp; do
                genPortList OUTPUT "$proto" "Allowed OUTPUT $proto ports to $whitelist_target (blank for none): " -d "$whitelist_target"
            done
        fi
    fi

    log_info "Temporarily setting default policies to DROP for validation"
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP
    sudo iptables -P FORWARD DROP

    sleep 0.5
    log_info "Policies set to DROP. Press Ctrl+C within 5 seconds if connectivity is lost in order to revert changes to the base, default policy."
    sleep 5

    sudo iptables -P INPUT ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT

    log_info "Base policy applied (test complete)."
    if yesno y "Would you like to SAVE these rules and make them PERSISTENT across reboots?"; then
        save_iptables_rules_persistent
    fi
}

# Other iptables utilities
function apply_established_only_rules {
    print_banner "Applying Established/Related Only Rules"
    sudo iptables -F; sudo iptables -X; sudo iptables -Z
    sudo iptables -P INPUT DROP; sudo iptables -P OUTPUT DROP; sudo iptables -P FORWARD DROP
    sudo iptables -A INPUT  -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    log_info "Established/Related only rule-set loaded (not yet persisted)."
}

function iptables_disable_default_deny {
    print_banner "Temporarily Disabling iptables Default Deny Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P INPUT  ACCEPT
    log_info "Default policies now ACCEPT (backup saved)."
}

function iptables_enable_default_deny {
    print_banner "Re-enabling iptables Default Deny Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT DROP
    sudo iptables -P INPUT  DROP
    log_info "Default policies now DROP (current rules preserved)."
}

function custom_iptables_manual_rules {
    print_banner "Manual Inbound IPtables Rule Addition"
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Skipping manual inbound rule addition."
        return 0
    fi
    log_info "Enter port numbers (one per line); blank line to finish."
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A INPUT --protocol tcp --dport "$port" -j ACCEPT
        log_info "Inbound iptables rule added for port $port (TCP)"
    done
}

function custom_iptables_manual_outbound_rules {
    print_banner "Manual Outbound IPtables Rule Addition"
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Skipping manual outbound rule addition."
        return 0
    fi
    log_info "Enter port numbers (one per line); blank line to finish."
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j ACCEPT
        log_info "Outbound iptables rule added for port $port (TCP)"
    done
}

function reset_iptables {
    print_banner "Resetting IPtables Firewall"
    log_info "Flushing all iptables rules..."
    sudo iptables -F
    sudo iptables -X
    sudo iptables -Z
    log_info "Setting default policies to ACCEPT..."
    sudo iptables -P INPUT   ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT  ACCEPT
    log_info "IPtables firewall has been reset (not persisted yet)."
}

# Firewall menus
function firewall_configuration_menu {
    if declare -F initialize_environment >/dev/null; then
        initialize_environment
    fi
    if [ "$ANSIBLE" == "true" ]; then
         log_info "Ansible mode: Running interactive base policy (iptables)."
         iptables_base_policy_interactive
         return 0
    fi

    read -e -r -p "Press ENTER to continue to the firewall configuration menu..." dummy
    echo

    while true; do
        echo "===== IPtables Menu ====="
        echo "  1) Setup IPtables (guided base policy)"
        echo "  2) Create outbound allow rule"
        echo "  3) Create inbound allow rule"
        echo "  4) Create outbound deny rule"
        echo "  5) Create inbound deny rule"
        echo "  6) Show IPtables rules"
        echo "  7) Reset IPtables (flush & set ACCEPT)"
        echo "  8) Show Running Services"
        echo "  9) Disable default deny (temporarily allow outbound)"
        echo " 10) Enable default deny (restore outbound blocking)"
        echo " 11) Allow only Established/Related Traffic"
        echo " 12) Save & Persist iptables rules"
        echo " 13) Exit IPtables menu"
        read -e -r -p "Enter your choice [1-13]: " ipt_choice
        echo
        case $ipt_choice in
            1)  iptables_base_policy_interactive ;;
            2)  custom_iptables_manual_outbound_rules ;;
            3)  custom_iptables_manual_rules ;;
            4)
                read -e -r -p "Enter outbound port to deny: " port
                sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j DROP
                log_info "Outbound deny $port"
                ;;
            5)
                read -e -r -p "Enter inbound port to deny: " port
                sudo iptables -A INPUT  --protocol tcp --dport "$port" -j DROP
                log_info "Inbound deny $port"
                ;;
            6)  sudo iptables -L -n -v ;;
            7)  reset_iptables ;;
            8)  audit_running_services ;;
            9)  iptables_disable_default_deny ;;
            10) iptables_enable_default_deny ;;
            11) apply_established_only_rules ;;
            12) save_iptables_rules_persistent ;;
            13) break ;;
            *)
                log_error "Invalid option."
                ;;
        esac
        echo
    done
}
