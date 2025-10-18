#!/usr/bin/env bash
set -o pipefail

# =========================
# Helper: persistence & PM
# =========================
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

# =========================
# iptables persistence
# =========================
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

# =========================
# Save helpers (no auto-add)
# =========================
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

# =========================
# UFW helpers (unchanged)
# =========================
function ensure_ufw_persistence {
    if systemctl list-unit-files | awk '{print $1}' | grep -qx "ufw.service"; then
        sudo systemctl enable ufw >/dev/null 2>&1 || true
        log_info "ufw.service enabled for boot-time"
    fi
}

function backup_current_ufw_rules {
    log_info "Backing up current UFW rules to $UFW_BACKUP"
    if [ -f /etc/ufw/user.rules ]; then
        sudo cp /etc/ufw/user.rules "$UFW_BACKUP"
    else
        log_warning "/etc/ufw/user.rules not found; UFW may not be initialized yet."
    fi
}

function restore_ufw_rules {
    if [ -f "$UFW_BACKUP" ]; then
        log_info "Restoring UFW rules from $UFW_BACKUP"
        sudo ufw reset
        sudo cp "$UFW_BACKUP" /etc/ufw/user.rules
        sudo ufw reload
    else
        log_error "No UFW backup file found."
    fi
}

function setup_ufw {
    print_banner "Configuring ufw"
    sudo $pm install -y ufw
    sudo sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw
    sudo ufw --force disable
    sudo ufw --force reset
    sudo ufw default deny outgoing
    sudo ufw default deny incoming
    sudo ufw allow out on lo
    sudo ufw allow out to any port 53 proto tcp
    sudo ufw allow out to any port 53 proto udp
    log_info "UFW installed and configured with strict outbound deny (except DNS) successfully.\n"
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Skipping additional inbound port configuration."
    else
        log_info "Which additional ports should be opened for incoming traffic?"
        echo "      WARNING: Do NOT forget to add 22/SSH if needed - please don't accidentally lock yourself out!"
        ports=$(get_input_list)
        for port in $ports; do
            sudo ufw allow "$port"
            log_info "Rule added for port $port"
        done
    fi
    sudo ufw logging on
    sudo ufw --force enable
    ensure_ufw_persistence
    backup_current_ufw_rules
}

# =======================================
# Interactive base policy
# =======================================
function yesno() {
    read YESNO
    YESNO="$(tr '[:upper:]' '[:lower:]' <<<"$YESNO" | head -c1)"
    test "$YESNO" == "y" && return 0
    test "$YESNO" == "n" && return 1
    test "$1" == 'y'
    return $?
}

function genPortList() {
    read PORT_LIST
    for port in $PORT_LIST; do
        sudo iptables -A "$1" -p "$2" --dport "$port" $3 -j ACCEPT
    done
}

function iptables_base_policy_interactive {
    print_banner "Interactive IPtables Base Policy"
    if [ "$EUID" != 0 ]; then
        log_error "Please run with sudo/root"
        return 1
    fi

    # Optional flush if rules already exist
    if [ "$(sudo iptables --list-rules | wc -l)" -gt 3 ]; then
        echo 'It looks like there are already some firewall rules. Do you want to remove them? (y/N)'
        yesno n && sudo iptables -F
    fi

    # Core allow rules
    sudo iptables -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT  -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT  -p icmp --icmp-type echo-request -j ACCEPT
    sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply  -j ACCEPT

    # Splunk
    echo 'Splunk indexer IP: '
    read SPLUNK_IP
    if [[ -n "$SPLUNK_IP" ]]; then
        sudo iptables -A OUTPUT -d "$SPLUNK_IP" -p tcp --dport 9997 -j ACCEPT
        sudo iptables -A OUTPUT -d "$SPLUNK_IP" -p udp --dport 1514 -j ACCEPT
        sudo iptables -A OUTPUT -d "$SPLUNK_IP" -p udp --dport 1515 -j ACCEPT
    fi

    # SSH client detection
    if [ -n "$SSH_CLIENT" ]; then
        echo 'SSH Detected. Whitelist client? (Y/n)'
        yesno y && sudo iptables -A INPUT -s "$(cut -f1 -d' ' <<<"$SSH_CLIENT")" -p tcp --dport 22 -j ACCEPT
    fi

    # DNS servers (UDP 53 out)
    echo 'DNS Server IPs: (OUTPUT udp/53)'
    read DNS_IPS
    for ip in $DNS_IPS; do
        sudo iptables -A OUTPUT -d "$ip" -p udp --dport 53 -j ACCEPT
    done

    # Free-form port additions before policy change
    for CHAIN in INPUT OUTPUT; do
        for PROTO in tcp udp; do
            echo "Space-separated list of $CHAIN $PROTO ports/services (press Enter for none):"
            genPortList "$CHAIN" "$PROTO"
        done
    done

    # Optional whitelist block
    echo 'Would you like to whitelist traffic to a specific IP or subnet? (y/N)'
    yesno n && {
        echo 'IP or subnet: '
        read IP
        for PROTO in tcp udp; do
            echo "Space-separated list of INPUT $PROTO ports/services from whitelisted IP/subnet:"
            genPortList INPUT "$PROTO" "-s $IP"
        done
        for PROTO in tcp udp; do
            echo "Space-separated list of OUTPUT $PROTO ports/services to whitelisted IP/subnet:"
            genPortList OUTPUT "$PROTO" "-d $IP"
        done
    }

    # Change policies to DROP (test window), then revert
    echo 'Changing policy...'
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP
    sudo iptables -P FORWARD DROP

    sleep 0.5
    echo 'Policy changed.'
    echo 'If you can see this, press Ctrl+C'
    echo 'Reverting policies in 5s...'
    sleep 5

    sudo iptables -P INPUT ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT

    log_info "Base policy applied (test complete)."
    # Ask to save now
    echo "Would you like to SAVE these rules and make them PERSISTENT across reboots? (Y/n)"
    yesno y && save_iptables_rules_persistent
}

# =========================
# Other iptables utilities
# =========================
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

# =========================
# Firewall menus
# =========================
function firewall_configuration_menu {
    if declare -F initialize_environment >/dev/null; then
        initialize_environment
    fi
    if [ "$ANSIBLE" == "true" ]; then
         log_info "Ansible mode: Running interactive base policy (iptables)."
         iptables_base_policy_interactive
         return 0
    fi

    read -p "Press ENTER to continue to the firewall configuration menu..." dummy
    echo
    echo "Select firewall type:"
    echo "  1) UFW"
    echo "  2) IPtables"
    read -p "Enter your choice [1-2]: " fw_type_choice
    echo
    case $fw_type_choice in
        1)
            while true; do
                echo "===== UFW Menu ====="
                echo "  1) Setup UFW"
                echo "  2) Create inbound allow rule"
                echo "  3) Create outbound allow rule"
                echo "  4) Show UFW rules"
                echo "  5) Reset UFW"
                echo "  6) Show Running Services"
                echo "  7) Disable default deny (temporarily allow outbound)"
                echo "  8) Enable default deny (restore outbound blocking)"
                echo "  9) Exit UFW menu"
                read -p "Enter your choice [1-9]: " ufw_choice
                echo
                case $ufw_choice in
                    1) setup_ufw ;;
                    2)
                        log_info "Ports (one per line, blank to finish):"
                        ports=$(get_input_list)
                        for p in $ports; do
                            sudo ufw allow in "$p"
                            log_info "Inbound allow $p"
                        done
                        ;;
                    3)
                        log_info "Ports (one per line, blank to finish):"
                        ports=$(get_input_list)
                        for p in $ports; do
                            sudo ufw allow out "$p"
                            log_info "Outbound allow $p"
                        done
                        ;;
                    4) sudo ufw status numbered ;;
                    5)
                        log_info "Resetting UFW..."
                        sudo ufw --force reset
                        ;;
                    6) audit_running_services ;;
                    7) sudo ufw default allow outgoing; backup_current_ufw_rules ;;
                    8) sudo ufw default deny outgoing; sudo ufw allow out on lo; sudo ufw allow out to any port 53 proto tcp; sudo ufw allow out to any port 53 proto udp; backup_current_ufw_rules ;;
                    9) break ;;
                    *)
                        log_error "Invalid option."
                        ;;
                esac
                echo
            done
            ;;
        2)
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
                echo " 11) Open OSSEC Ports (UDP 1514 & 1515)"
                echo " 12) Allow only Established/Related Traffic"
                echo " 13) Save & Persist iptables rules  <-- NEW"
                echo " 14) Exit IPtables menu"
                read -p "Enter your choice [1-14]: " ipt_choice
                echo
                case $ipt_choice in
                    1)  iptables_base_policy_interactive ;;
                    2)  custom_iptables_manual_outbound_rules ;;
                    3)  custom_iptables_manual_rules ;;
                    4)
                        read -p "Enter outbound port to deny: " port
                        sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j DROP
                        log_info "Outbound deny $port"
                        ;;
                    5)
                        read -p "Enter inbound port to deny: " port
                        sudo iptables -A INPUT  --protocol tcp --dport "$port" -j DROP
                        log_info "Inbound deny $port"
                        ;;
                    6)  sudo iptables -L -n -v ;;
                    7)  reset_iptables ;;
                    8)  audit_running_services ;;
                    9)  iptables_disable_default_deny ;;
                    10) iptables_enable_default_deny ;;
                    11) open_ossec_ports ;;
                    12) apply_established_only_rules ;;
                    13) save_iptables_rules_persistent ;;   # <= dedicated save action
                    14) break ;;
                    *)
                        log_error "Invalid option."
                        ;;
                esac
                echo
            done
            ;;
        *)
            log_error "Invalid firewall type selection."
            ;;
    esac
}
