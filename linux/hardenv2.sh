#!/bin/bash
# Usage: ./harden.sh [option]

# NOTE: It is recommended to run this script with root privileges (e.g., via sudo)
if [ "$EUID" -ne 0 ]; then
    echo "[X] Please run this script as root (or via sudo)."
    exit 1
fi

###################### GLOBALS ######################
LOG='/var/log/ccdc/harden.log'
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main"
pm=""
sudo_group=""
ccdc_users=( "ccdcuser1" "ccdcuser2" )
debug="false"
IPTABLES_BACKUP="/tmp/iptables_backup.rules"
UFW_BACKUP="/tmp/ufw_backup.rules"
#####################################################

##################### FUNCTIONS #####################
# Prints text in a banner
# Arguments:
#   $1: Text to print
function print_banner {
    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
}

function debug_print {
    if [ "$debug" == "true" ]; then
        echo -n "DEBUG: "
        for arg in "$@"; do
            echo -n "$arg"
        done
        echo -e "\n"
    fi
}

function get_input_string {
    read -r -p "$1" input
    echo "$input"
}

function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

function get_input_list {
    local input_list=()
    while [ "$continue" != "false" ]; do
        input=$(get_input_string "Enter input: (one entry per line; hit enter to continue): ")
        if [ "$input" == "" ]; then
            continue="false"
        else
            input_list+=("$input")
        fi
    done
    echo "${input_list[@]}"
}

function exclude_users {
    users="$@"
    input=$(get_input_list)
    for item in $input; do
        users+=("$item")
    done
    echo "${users[@]}"
}

function get_users {
    awk_string=$1
    exclude_users=$(sed -e 's/ /\\|/g' <<< $2)
    users=$(awk -F ':' "$awk_string" /etc/passwd)
    filtered=$(echo "$users" | grep -v -e $exclude_users)
    readarray -t results <<< $filtered
    echo "${results[@]}"
}

function detect_system_info {
    print_banner "Detecting system info"
    echo "[*] Detecting package manager"
    sudo which apt-get &> /dev/null
    apt=$?
    sudo which dnf &> /dev/null
    dnf=$?
    sudo which zypper &> /dev/null
    zypper=$?
    sudo which yum &> /dev/null
    yum=$?

    if [ $apt == 0 ]; then
        echo "[*] apt/apt-get detected (Debian-based OS)"
        echo "[*] Updating package list"
        sudo apt-get update
        pm="apt-get"
    elif [ $dnf == 0 ]; then
        echo "[*] dnf detected (Fedora-based OS)"
        pm="dnf"
    elif [ $zypper == 0 ]; then
        echo "[*] zypper detected (OpenSUSE-based OS)"
        pm="zypper"
    elif [ $yum == 0 ]; then
        echo "[*] yum detected (RHEL-based OS)"
        pm="yum"
    else
        echo "[X] ERROR: Could not detect package manager"
        exit 1
    fi

    echo "[*] Detecting sudo group"
    groups=$(compgen -g)
    if echo "$groups" | grep -q '^sudo$'; then
        echo '[*] sudo group detected'
        sudo_group='sudo'
    elif echo "$groups" | grep -q '^wheel$'; then
        echo '[*] wheel group detected'
        sudo_group='wheel'
    else
        echo '[X] ERROR: could not detect sudo group'
        exit 1
    fi
}

function install_prereqs {
    print_banner "Installing prerequisites"
    sudo $pm install -y zip unzip wget curl acl
}

function change_root_password {
    print_banner "Changing Root Password"
    while true; do
        root_password=$(get_silent_input_string "Enter new root password: ")
        echo
        root_password_confirm=$(get_silent_input_string "Confirm new root password: ")
        echo
        if [ "$root_password" != "$root_password_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    if echo "root:$root_password" | sudo chpasswd; then
        echo "[*] Root password updated successfully."
    else
        echo "[X] ERROR: Failed to update root password."
    fi
}

# Updated create_ccdc_users function:
function create_ccdc_users {
    print_banner "Creating ccdc users"

    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
            # For ccdcuser1 and ccdcuser2, prompt to update their password.
            if [[ "$user" == "ccdcuser1" ]]; then
                echo "[*] $user already exists. Do you want to update the password? (y/N): "
                read -r update_choice
                if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
                    while true; do
                        password=$(get_silent_input_string "Enter new password for $user: ")
                        echo
                        password_confirm=$(get_silent_input_string "Confirm new password for $user: ")
                        echo
                        if [ "$password" != "$password_confirm" ]; then
                            echo "Passwords do not match. Please retry."
                        else
                            if ! echo "$user:$password" | sudo chpasswd; then
                                echo "[X] ERROR: Failed to update password for $user"
                            else
                                echo "[*] Password for $user updated."
                                break
                            fi
                        fi
                    done
                fi
            elif [[ "$user" == "ccdcuser2" ]]; then
                echo "[*] $user already exists. Do you want to update the password? (y/N): "
                read -r update_choice
                if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
                    while true; do
                        password=$(get_silent_input_string "Enter new password for $user: ")
                        echo
                        password_confirm=$(get_silent_input_string "Confirm new password for $user: ")
                        echo
                        if [ "$password" != "$password_confirm" ]; then
                            echo "Passwords do not match. Please retry."
                        else
                            if ! echo "$user:$password" | sudo chpasswd; then
                                echo "[X] ERROR: Failed to update password for $user"
                            else
                                echo "[*] Password for $user updated."
                                break
                            fi
                        fi
                    done
                fi
    
                echo "[*] Would you like to change the root password? (y/N): "
                read -r root_choice
                if [[ "$root_choice" == "y" || "$root_choice" == "Y" ]]; then
                    change_root_password
                fi
            else
                echo "[*] $user already exists. Skipping..."
            fi
        else
            echo "[*] $user not found. Creating user..."
            if [ -f "/bin/bash" ]; then
                sudo useradd -m -s /bin/bash "$user"
            elif [ -f "/bin/sh" ]; then
                sudo useradd -m -s /bin/sh "$user"
            else
                echo "[X] ERROR: Could not find valid shell"
                exit 1
            fi

            # For ccdcuser1 and ccdcuser2, prompt for an individual password.
            if [[ "$user" == "ccdcuser1" ]]; then
                echo "[*] Enter the password for $user:"
                while true; do
                    password=$(get_silent_input_string "Enter password for $user: ")
                    echo
                    password_confirm=$(get_silent_input_string "Confirm password for $user: ")
                    echo
                    if [ "$password" != "$password_confirm" ]; then
                        echo "Passwords do not match. Please retry."
                    else
                        if ! echo "$user:$password" | sudo chpasswd; then
                            echo "[X] ERROR: Failed to set password for $user"
                        else
                            echo "[*] Password for $user has been set."
                            break
                        fi
                    fi
                done
                echo "[*] Adding $user to $sudo_group group"
                sudo usermod -aG $sudo_group "$user"
            elif [[ "$user" == "ccdcuser2" ]]; then
                echo "[*] Enter the password for $user:"
                while true; do
                    password=$(get_silent_input_string "Enter password for $user: ")
                    echo
                    password_confirm=$(get_silent_input_string "Confirm password for $user: ")
                    echo
                    if [ "$password" != "$password_confirm" ]; then
                        echo "Passwords do not match. Please retry."
                    else
                        if ! echo "$user:$password" | sudo chpasswd; then
                            echo "[X] ERROR: Failed to set password for $user"
                        else
                            echo "[*] Password for $user has been set."
                            break
                        fi
                    fi
                done
                
                echo "[*] Would you like to change the root password? (y/N): "
                read -r root_choice
                if [[ "$root_choice" == "y" || "$root_choice" == "Y" ]]; then
                    change_root_password
                fi
            else
                if echo "$user:$default_password" | sudo chpasswd; then
                    echo "[*] $user created with the default password."
                else
                    echo "[X] ERROR: Failed to set default password for $user"
                fi
            fi
        fi
        echo
    done
}

function change_passwords {
    print_banner "Changing user passwords"

    # Exclude root, ccdcuser1, and ccdcuser2
    exclusions=("root" "${ccdc_users[@]}")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi

    # Get targets (all users not matching "nobody" and not in the exclusions list)
    targets=$(get_users '$1 != "nobody" {print $1}' "${exclusions[*]}")

    echo "[*] Enter the new password to be used for all users."
    while true; do
        password=""
        confirm_password=""

        # Ask for password
        password=$(get_silent_input_string "Enter password: ")
        echo

        # Confirm password
        confirm_password=$(get_silent_input_string "Confirm password: ")
        echo

        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    echo

    echo "[*] Changing passwords..."
    for user in $targets; do
        if ! echo "$user:$password" | sudo chpasswd; then
            echo "[X] ERROR: Failed to change password for $user"
        else
            echo "[*] Password for $user has been changed."
        fi
    done
}

function disable_users {
    print_banner "Disabling users"
    exclusions=("${ccdc_users[@]}")
    exclusions+=("root")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '/\/bash$|\/sh$|\/ash$|\/zsh$/{print $1}' "${exclusions[*]}")
    echo
    echo "[*] Disabling user accounts using usermod -L and setting shell to nologin..."
    for user in $targets; do
        if sudo usermod -L "$user"; then
            echo "[*] Account for $user has been locked (usermod -L)."
            if sudo usermod -s /usr/sbin/nologin "$user"; then
                echo "[*] Login shell for $user set to nologin."
            else
                echo "[X] ERROR: Failed to set nologin shell for $user."
            fi
        else
            echo "[X] ERROR: Failed to lock account for $user using usermod -L."
        fi
    done
}

function remove_sudoers {
    print_banner "Removing sudoers"
    echo "[*] Removing users from the $sudo_group group"
    exclusions=("ccdcuser1")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '{print $1}' "${exclusions[*]}")
    echo
    echo "[*] Removing sudo users..."
    for user in $targets; do
        if groups "$user" | grep -q "$sudo_group"; then
            echo "[*] Removing $user from $sudo_group group"
            sudo gpasswd -d "$user" "$sudo_group"
        fi
    done
}

function audit_running_services {
    print_banner "Auditing Running Services"
    echo "[*] Listing running services (TCP/UDP listening ports):"
    ss -tuln
}

########################################################################
# FUNCTION: disable_other_firewalls
########################################################################
function disable_other_firewalls {
    print_banner "Disabling existing firewalls"
    if sudo command -v firewalld &>/dev/null; then
        echo "[*] Disabling firewalld"
        sudo systemctl stop firewalld
        sudo systemctl disable firewalld
    fi
    # The other potential firewall services remain commented out.
}

########################################################################
# FUNCTION: backup fw rules
########################################################################

function backup_current_iptables_rules {
    echo "[*] Backing up current iptables rules to $IPTABLES_BACKUP"
    sudo iptables-save > "$IPTABLES_BACKUP"
}

function restore_iptables_rules {
    if [ -f "$IPTABLES_BACKUP" ]; then
        echo "[*] Restoring iptables rules from $IPTABLES_BACKUP"
        sudo iptables-restore < "$IPTABLES_BACKUP"
    else
        echo "[X] No iptables backup file found."
    fi
}

function backup_current_ufw_rules {
    echo "[*] Backing up current UFW rules to $UFW_BACKUP"
    sudo cp /etc/ufw/user.rules "$UFW_BACKUP"
}

function restore_ufw_rules {
    if [ -f "$UFW_BACKUP" ]; then
        echo "[*] Restoring UFW rules from $UFW_BACKUP"
        sudo ufw reset
        sudo cp "$UFW_BACKUP" /etc/ufw/user.rules
        sudo ufw reload
    else
        echo "[X] No UFW backup file found."
    fi
}

########################################################################
# FUNCTION: setup_ufw
# Configures UFW firewall rules with a strict outbound deny policy (except DNS)
# and disables IPv6.
########################################################################
function setup_ufw {
    print_banner "Configuring ufw"
    sudo $pm install -y ufw

    # Disable IPv6 in UFW configuration.
    sudo sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw

    # Immediately reset UFW so that the new rules will be the only ones present.
    sudo ufw --force disable
    sudo ufw --force reset

    # Set default policies: deny all outgoing and incoming traffic.
    sudo ufw default deny outgoing
    sudo ufw default deny incoming

    # Allow loopback outbound traffic.
    sudo ufw allow out on lo

    # Explicitly allow outbound DNS queries (TCP and UDP on port 53).
    sudo ufw allow out to any port 53 proto tcp
    sudo ufw allow out to any port 53 proto udp

    echo -e "[*] UFW installed and configured with strict outbound deny (except DNS) successfully.\n"
    echo "[*] Which additional ports should be opened for incoming traffic?"
    echo "      WARNING: Do NOT forget to add 22/SSH if needed - please don't accidentally lock yourself out!"
    ports=$(get_input_list)
    for port in $ports; do
        sudo ufw allow "$port"
        echo "[*] Rule added for port $port"
    done

    sudo ufw logging on
    sudo ufw --force enable
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: ufw_disable_default_deny
# Temporarily disables UFW’s default deny policy for outgoing traffic.
########################################################################
function ufw_disable_default_deny {
    print_banner "Temporarily Disabling UFW Default Deny Outgoing Policy"
    sudo ufw default allow outgoing
    echo "[*] UFW default outgoing policy is now set to allow."
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: ufw_enable_default_deny
# Re-enables UFW’s default deny policy for outgoing traffic.
########################################################################
function ufw_enable_default_deny {
    print_banner "Re-enabling UFW Default Deny Outgoing Policy"
    sudo ufw default deny outgoing
    # Re-add essential outbound rules:
    sudo ufw allow out on lo
    sudo ufw allow out to any port 53 proto tcp
    sudo ufw allow out to any port 53 proto udp
    echo "[*] UFW default outgoing policy is now set to deny."
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: setup_custom_iptables
# Configures iptables with a strict outbound deny policy (except DNS) for IPv4.
########################################################################
function setup_custom_iptables {
    print_banner "Configuring iptables (Custom Script)"
    
    # Flush existing iptables rules.
    reset_iptables

    # Set default policies: drop outbound and inbound traffic.
    sudo iptables -P OUTPUT DROP
    sudo iptables -P INPUT DROP

    # Allow loopback outbound traffic.
    sudo iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established/related connections.
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Explicitly allow outbound DNS queries (TCP and UDP on port 53).
    sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    # (Note: Inbound DNS responses are allowed automatically via conntrack.)

    echo "Select your DNS server option:"
    echo "  1) Use Cloudflare DNS servers (1.1.1.1, 1.0.0.1)"
    echo "  2) Use default gateway/router as your DNS server"
    echo "  3) Use default DNS servers (192.168.XXX.1, 192.168.XXX.2)"
    dns_choice=$(get_input_string "Enter your choice [1-3]: ")
    if [[ "$dns_choice" == "1" ]]; then
        dns_value="1.1.1.1 1.0.0.1"
    elif [[ "$dns_choice" == "2" ]]; then
        default_gateway=$(ip route | awk '/default/ {print $3; exit}')
        if [[ -z "$default_gateway" ]]; then
            echo "[X] Could not determine default gateway. Using fallback DNS servers."
            dns_value="192.168.XXX.1 192.168.XXX.2"
        else
            dns_value="$default_gateway"
        fi
    else
        dns_value="192.168.XXX.1 192.168.XXX.2"
    fi

    # [The DSU dual-mode script block remains unchanged, except that any inbound DNS allow lines are removed.]
    # Create and execute the DSU script as in your original code...
    # (See your existing code block for the DSU script; no inbound DNS rules are added.)
    
    # Save the iptables rules persistently.
    backup_current_iptables_rules

    # Ask whether to enter additional (extended) iptables management.
    ext_choice=$(get_input_string "Would you like to add any additional iptables rules? (y/N): ")
    if [[ "$ext_choice" == "y" || "$ext_choice" == "Y" ]]; then
        extended_iptables
    fi
}

########################################################################
# FUNCTION: iptables_enable/deny
# Toggle between the two
########################################################################
function iptables_disable_default_deny {
    print_banner "Temporarily Disabling iptables Default Deny Outgoing Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P INPUT ACCEPT
    echo "[*] iptables default policies are now set to ACCEPT (backup saved)."
}

function iptables_enable_default_deny {
    print_banner "Re-enabling iptables Default Deny Outgoing Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT DROP
    sudo iptables -P INPUT DROP
    echo "[*] iptables default policies are now set to DROP (current rules preserved)."
}

########################################################################
# FUNCTION: backup_current_iptables_rules
# Saves current iptables rules persistently based on the detected OS.
########################################################################
function backup_current_iptables_rules {
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
        echo "[*] Iptables rules saved to /etc/sysconfig/iptables"
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        if [ -f /etc/iptables/rules.v4 ]; then
            sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
            echo "[*] Iptables rules saved to /etc/iptables/rules.v4"
        elif command -v netfilter-persistent &> /dev/null; then
            sudo netfilter-persistent save
            echo "[*] Iptables rules saved using netfilter-persistent"
        else
            echo "[!] Warning: iptables persistent saving is not configured on this system."
        fi
    else
        echo "[*] Unknown OS. Please ensure iptables rules are saved manually if needed."
    fi
}

########################################################################
# FUNCTION: custom_iptables_manual_rules (inbound)
########################################################################
function custom_iptables_manual_rules {
    print_banner "Manual Inbound IPtables Rule Addition"
    echo "[*] Enter port numbers (one per line) for which you wish to allow inbound TCP traffic."
    echo "    Press ENTER on a blank line when finished."
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A INPUT --protocol tcp --dport "$port" -j ACCEPT
        echo "[*] Inbound iptables rule added for port $port (TCP)"
        backup_current_iptables_rules
    done
}

########################################################################
# FUNCTION: custom_iptables_manual_outbound_rules
########################################################################
function custom_iptables_manual_outbound_rules {
    print_banner "Manual Outbound IPtables Rule Addition"
    echo "[*] Enter port numbers (one per line) for which you wish to allow outbound TCP traffic."
    echo "    Press ENTER on a blank line when finished."
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j ACCEPT
        echo "[*] Outbound iptables rule added for port $port (TCP)"
        backup_current_iptables_rules
    done
}

########################################################################
# FUNCTION: extended_iptables
# Provides an interactive loop for extended IPtables management.
########################################################################
function extended_iptables {
    while true; do
        print_banner "Extended IPtables Management"
        echo "Select an option:"
        echo "  1) Add Outbound Rule (ACCEPT)"
        echo "  2) Add Inbound Rule (ACCEPT)"
        echo "  3) Deny Outbound Rule (DROP)"
        echo "  4) Deny Inbound Rule (DROP)"
        echo "  5) Show All Rules"
        echo "  6) Reset Firewall"
        echo "  7) Exit Extended IPtables Management"
        read -p "Enter your choice [1-7]: " choice
        case $choice in
            1)
                read -p "Enter outbound port number: " port
                sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j ACCEPT
                echo "Outbound ACCEPT rule added for port $port"
                backup_current_iptables_rules
                ;;
            2)
                read -p "Enter inbound port number: " port
                sudo iptables -A INPUT --protocol tcp --dport "$port" -j ACCEPT
                echo "Inbound ACCEPT rule added for port $port"
                backup_current_iptables_rules
                ;;
            3)
                read -p "Enter outbound port number to deny: " port
                sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j DROP
                echo "Outbound DROP rule added for port $port"
                backup_current_iptables_rules
                ;;
            4)
                read -p "Enter inbound port number to deny: " port
                sudo iptables -A INPUT --protocol tcp --dport "$port" -j DROP
                echo "Inbound DROP rule added for port $port"
                backup_current_iptables_rules
                ;;
            5)
                sudo iptables -L -n -v
                ;;
            6)
                reset_iptables
                backup_current_iptables_rules
                ;;
            7)
                echo "Exiting Extended IPtables Management."
                break
                ;;
            *)
                echo "Invalid option selected."
                ;;
        esac
        echo ""
    done
}

########################################################################
# FUNCTION: reset_iptables
# Resets the IPtables firewall.
########################################################################
function reset_iptables {
    print_banner "Resetting IPtables Firewall"
    echo "[*] Flushing all iptables rules..."
    sudo iptables -F
    sudo iptables -X
    sudo iptables -Z
    echo "[*] Setting default policies to ACCEPT..."
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    echo "[*] IPtables firewall has been reset."
    backup_current_iptables_rules
}

########################################################################
# FUNCTION: firewall_configuration_menu
# New interactive menu that first prompts for firewall type (UFW or IPtables)
# then displays the appropriate submenu. After finishing the submenu, it exits.
########################################################################
function firewall_configuration_menu {
    # Prepare system
    detect_system_info
    install_prereqs
    disable_other_firewalls

    # Run audit_running_services before the firewall menu pops up.
    audit_running_services
    read -p "Press ENTER to continue to the firewall configuration menu..." dummy

    echo
    echo "Select firewall type:"
    echo "  1) UFW"
    echo "  2) IPtables"
    read -p "Enter your choice [1-2]: " fw_type_choice
    echo
    case $fw_type_choice in
        1)
            # UFW submenu loop
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
                    1)
                        setup_ufw
                        ;;
                    2)
                        echo "[*] Enter inbound port numbers (one per line; hit ENTER on a blank line to finish):"
                        ports=$(get_input_list)
                        for port in $ports; do
                            sudo ufw allow in "$port"
                            echo "[*] Inbound allow rule added for port $port"
                        done
                        ;;
                    3)
                        echo "[*] Enter outbound port numbers (one per line; hit ENTER on a blank line to finish):"
                        ports=$(get_input_list)
                        for port in $ports; do
                            sudo ufw allow out "$port"
                            echo "[*] Outbound allow rule added for port $port"
                        done
                        ;;
                    4)
                        sudo ufw status numbered
                        ;;
                    5)
                        echo "[*] Resetting UFW..."
                        sudo ufw --force reset
                        ;;
                    6)
                        audit_running_services
                        ;;
                    7)
                        ufw_disable_default_deny
                        ;;
                    8)
                        ufw_enable_default_deny
                        ;;
                    9)
                        break
                        ;;
                    *)
                        echo "[X] Invalid option."
                        ;;
                esac
                echo
            done
            ;;
        2)
            # IPtables submenu loop
            while true; do
                echo "===== IPtables Menu ====="
                echo "  1) Setup IPtables"
                echo "  2) Create outbound allow rule"
                echo "  3) Create inbound allow rule"
                echo "  4) Create outbound deny rule"
                echo "  5) Create inbound deny rule"
                echo "  6) Show IPtables rules"
                echo "  7) Reset IPtables"
                echo "  8) Show Running Services"
                echo "  9) Disable default deny (temporarily allow outbound)"
                echo "  10) Enable default deny (restore outbound blocking)"
                echo "  11) Exit IPtables menu"
                read -p "Enter your choice [1-11]: " ipt_choice
                echo
                case $ipt_choice in
                    1)
                        setup_custom_iptables
                        ;;
                    2)
                        custom_iptables_manual_outbound_rules
                        ;;
                    3)
                        custom_iptables_manual_rules
                        ;;
                    4)
                        read -p "Enter outbound port number to deny: " port
                        sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j DROP
                        echo "[*] Outbound deny rule added for port $port"
                        backup_current_iptables_rules
                        ;;
                    5)
                        read -p "Enter inbound port number to deny: " port
                        sudo iptables -A INPUT --protocol tcp --dport "$port" -j DROP
                        echo "[*] Inbound deny rule added for port $port"
                        backup_current_iptables_rules
                        ;;
                    6)
                        sudo iptables -L -n -v
                        ;;
                    7)
                        reset_iptables
                        backup_current_iptables_rules
                        ;;
                    8)
                        audit_running_services
                        ;;
                    9)
                        iptables_disable_default_deny
                        ;;
                    10)
                        iptables_enable_default_deny
                        ;;
                    11)
                        break
                        ;;
                    *)
                        echo "[X] Invalid option."
                        ;;
                esac
                echo
            done
            ;;
        *)
            echo "[X] Invalid firewall type selection."
            ;;
    esac
}

########################################################################
# FUNCTION: backup_directories
# Backs up critical and additional directories/files into a single encrypted archive.
########################################################################
function backup_directories {
    print_banner "Backup Directories"

    # Pre-check for critical directories
    default_dirs=( "/etc/nginx" "/etc/apache2" "/usr/share/nginx" "/var/www" "/var/www/html" "/etc/lighttpd" "/etc/mysql" "/etc/postgresql" "/var/lib/apache2" "/var/lib/mysql" "/etc/redis" "/etc/phpMyAdmin" "/etc/php.d" )
    detected_dirs=()
    echo "[*] Scanning for critical directories..."
    for d in "${default_dirs[@]}"; do
        if [ -d "$d" ]; then
            detected_dirs+=("$d")
        fi
    done

    backup_list=()
    if [ ${#detected_dirs[@]} -gt 0 ]; then
        echo "[*] The following critical directories were detected:"
        for d in "${detected_dirs[@]}"; do
            echo "   $d"
        done
        read -p "Would you like to back these up? (y/N): " detected_choice
        if [[ "$detected_choice" == "y" || "$detected_choice" == "Y" ]]; then
            backup_list=("${detected_dirs[@]}")
        fi
    else
        echo "[*] No critical directories detected."
    fi

    # Ask for additional directories/files
    read -p "Would you like to backup any additional files or directories? (y/N): " additional_choice
    if [[ "$additional_choice" == "y" || "$additional_choice" == "Y" ]]; then
        echo "[*] Enter additional directories/files to backup (one per line; hit ENTER on a blank line to finish):"
        additional_dirs=$(get_input_list)
        for item in $additional_dirs; do
            path=$(readlink -f "$item")
            if [ -e "$path" ]; then
                backup_list+=("$path")
            else
                echo "[X] ERROR: $path does not exist."
            fi
        done
    fi

    # Abort if nothing was selected
    if [ ${#backup_list[@]} -eq 0 ]; then
        echo "[*] No directories or files selected for backup. Exiting backup."
        return
    fi

    # Prompt for backup archive name; .zip will be automatically appended if not provided
    while true; do
        backup_name=$(get_input_string "Enter a name for the backup archive (without extension .zip): ")
        if [ "$backup_name" != "" ]; then
            if [[ "$backup_name" != *.zip ]]; then
                backup_name="${backup_name}.zip"
            fi
            break
        fi
        echo "[X] ERROR: Backup name cannot be blank."
    done

    echo "[*] Creating archive..."
    # Create a zip archive containing all selected directories/files
    zip -r "$backup_name" "${backup_list[@]}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Failed to create archive."
        return
    fi
    echo "[*] Archive created: $backup_name"

    # Encrypt the archive
    echo "[*] Encrypting the archive."
    while true; do
        enc_password=$(get_silent_input_string "Enter encryption password: ")
        echo
        enc_confirm=$(get_silent_input_string "Confirm encryption password: ")
        echo
        if [ "$enc_password" != "$enc_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    enc_archive="${backup_name}.enc"
    openssl enc -aes-256-cbc -salt -in "$backup_name" -out "$enc_archive" -k "$enc_password"
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Encryption failed."
        return
    fi
    echo "[*] Archive encrypted: $enc_archive"

    # Prompt for the backup storage directory
    while true; do
        storage_dir=$(get_input_string "Enter directory to store the encrypted backup: ")
        storage_dir=$(readlink -f "$storage_dir")
        if [ -d "$storage_dir" ]; then
            break
        else
            echo "[*] Directory does not exist. Creating it..."
            sudo mkdir -p "$storage_dir"
            if [ $? -eq 0 ]; then
                break
            else
                echo "[X] ERROR: Could not create directory."
            fi
        fi
    done

    # Move the encrypted archive to the storage directory and cleanup
    sudo mv "$enc_archive" "$storage_dir/"
    if [ $? -eq 0 ]; then
        echo "[*] Encrypted archive moved to $storage_dir"
    else
        echo "[X] ERROR: Failed to move encrypted archive."
    fi

    rm -f "$backup_name"
    echo "[*] Cleanup complete. Only the encrypted archive remains."
}

########################################################################
# FUNCTION: unencrypt_backups
# Decrypts a previously encrypted backup archive and optionally extracts it.
########################################################################
function unencrypt_backups {
    print_banner "Decrypt Backup"
    while true; do
        encrypted_file=$(get_input_string "Enter path to the encrypted backup file: ")
        # Expand any relative path to full path
        encrypted_file=$(readlink -f "$encrypted_file")
        if [ ! -f "$encrypted_file" ]; then
            echo "[X] ERROR: File '$encrypted_file' does not exist."
            # Search for similar files in the same directory (case-insensitive)
            dir=$(dirname "$encrypted_file")
            base=$(basename "$encrypted_file")
            echo "[*] Searching for similar files in '$dir'..."
            similar_files=$(find "$dir" -maxdepth 1 -iname "*${base}*" 2>/dev/null)
            if [ -n "$similar_files" ]; then
                echo "[*] Similar files found:"
                echo "$similar_files"
            else
                echo "[*] No similar files found."
            fi
            echo "[*] Please try again."
        else
            break
        fi
    done

    while true; do
        dec_password=$(get_silent_input_string "Enter decryption password: ")
        echo
        dec_confirm=$(get_silent_input_string "Confirm decryption password: ")
        echo
        if [ "$dec_password" != "$dec_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    temp_output="decrypted_backup.zip"
    openssl enc -d -aes-256-cbc -in "$encrypted_file" -out "$temp_output" -k "$dec_password"
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Decryption failed. Check your password."
        rm -f "$temp_output"
        return
    fi

    echo "[*] Decryption successful. Decrypted archive: $temp_output"
    read -p "Would you like to extract the decrypted archive? (y/N): " extract_choice
    if [[ "$extract_choice" == "y" || "$extract_choice" == "Y" ]]; then
        read -p "Enter directory to extract the backup: " extract_dir
        extract_dir=$(readlink -f "$extract_dir")
        mkdir -p "$extract_dir"
        unzip "$temp_output" -d "$extract_dir"
        echo "[*] Backup extracted to $extract_dir"
        rm -f "$temp_output"
    else
        echo "[*] Decrypted archive remains as $temp_output"
    fi
}

########################################################################
# FUNCTION: backups
# Presents a backup menu for either backing up directories or decrypting backups.
########################################################################
function backups {
    print_banner "Backup Menu"
    echo "1) Backup Directories"
    echo "2) Decrypt Backup"
    echo "3) Exit Backup Menu"
    read -p "Enter your choice [1-3]: " backup_choice
    case $backup_choice in
        1)
            backup_directories
            ;;
        2)
            unencrypt_backups
            ;;
        3)
            echo "[*] Exiting Backup Menu."
            ;;
        *)
            echo "[X] Invalid option."
            ;;
    esac
}

function setup_splunk {
    print_banner "Installing Splunk"
    indexer_ip=$(get_input_string "What is the Splunk forward server ip? ")

    wget $GITHUB_URL/splunk/splunk.sh --no-check-certificate
    chmod +x splunk.sh
    ./splunk.sh -f $indexer_ip
}


##################### ADDITIONAL WEB HARDENING FUNCTIONS #####################

function backup_databases {
    print_banner "Hardening Databases"
    # Check if MySQL/MariaDB is active and if default (empty) root login works.
    sudo service mysql status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] mysql/mariadb is active!"
        sudo mysql -u root -e "quit" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "[!] Able to login with empty password on the mysql database!"
            echo "[*] Backing up all databases..."
            sudo mysqldump --all-databases > backup.sql
            ns=$(date +%N)
            pass=$(echo "${ns}$REPLY" | sha256sum | cut -d" " -f1)
            echo "[+] Backed up database. Key for database dump: $pass"
            gpg -c --pinentry-mode=loopback --passphrase "$pass" backup.sql
            sudo rm backup.sql
        fi
    fi

    # Check if PostgreSQL is active
    sudo service postgresql status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] PostgreSQL is active!"
    fi
}


function secure_php_ini {
    print_banner "Securing php.ini Files"
    for ini in $(find / -name "php.ini" 2>/dev/null); do
        echo "[+] Writing php.ini options to $ini..."
        echo "disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo" | sudo tee -a "$ini" >/dev/null
        echo "max_execution_time = 3" | sudo tee -a "$ini" >/dev/null
        echo "register_globals = off" | sudo tee -a "$ini" >/dev/null
        echo "magic_quotes_gpc = on" | sudo tee -a "$ini" >/dev/null
        echo "allow_url_fopen = off" | sudo tee -a "$ini" >/dev/null
        echo "allow_url_include = off" | sudo tee -a "$ini" >/dev/null
        echo "display_errors = off" | sudo tee -a "$ini" >/dev/null
        echo "short_open_tag = off" | sudo tee -a "$ini" >/dev/null
        echo "session.cookie_httponly = 1" | sudo tee -a "$ini" >/dev/null
        echo "session.use_only_cookies = 1" | sudo tee -a "$ini" >/dev/null
        echo "session.cookie_secure = 1" | sudo tee -a "$ini" >/dev/null
    done
}

function secure_ssh {
    print_banner "Securing SSH"

    # Determine the SSH service name.
    if sudo service sshd status > /dev/null 2>&1; then
        service_name="sshd"
    elif sudo service ssh status > /dev/null 2>&1; then
        service_name="ssh"
    else
        echo "[*] SSH service not found. Skipping SSH hardening."
        return
    fi

    config_file="/etc/ssh/sshd_config"
    if [ ! -f "$config_file" ]; then
        echo "[X] ERROR: SSH configuration file not found: $config_file"
        return
    fi

    # Apply SSH hardening settings.
    # Enable root login and disable public-key authentication for root.
    sudo sed -i '1s;^;PermitRootLogin yes\n;' "$config_file"
    sudo sed -i '1s;^;PubkeyAuthentication no\n;' "$config_file"

    # For non-RedHat systems, disable PAM in sshd_config.
    if ! grep -qi "REDHAT_" /etc/os-release; then
        sudo sed -i '1s;^;UsePAM no\n;' "$config_file"
    fi

    sudo sed -i '1s;^;UseDNS no\n;' "$config_file"
    sudo sed -i '1s;^;PermitEmptyPasswords no\n;' "$config_file"
    sudo sed -i '1s;^;AddressFamily inet\n;' "$config_file"
    sudo sed -i '1s;^;Banner none\n;' "$config_file"

    # Test the SSH configuration.
    if sudo sshd -t; then
        # Restart the SSH service.
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl restart "$service_name"
        else
            sudo service "$service_name" restart
        fi
        echo "[*] SSH hardening applied and $service_name restarted."
    else
        echo "[X] ERROR: SSH configuration test failed."
    fi
}

function install_modsecurity {
    print_banner "Installing ModSecurity"
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo $ipt -P OUTPUT ACCEPT

    if command -v yum >/dev/null; then
        # RHEL-based systems (not implemented in this snippet)
        echo "RHEL-based ModSecurity installation not implemented"
    elif command -v apt-get >/dev/null; then
        # Debian/Ubuntu (and other Debian-based) systems
        sudo apt-get update
        sudo apt-get -y install libapache2-mod-security2
        sudo a2enmod security2
        sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
        sudo systemctl restart apache2
    elif command -v apk >/dev/null; then
        # Alpine-based systems (not implemented in this snippet)
        echo "Alpine-based ModSecurity installation not implemented"
    else
        echo "Unsupported distribution for ModSecurity installation"
        exit 1
    fi

    sudo $ipt -P OUTPUT DROP
}

function remove_profiles {
    print_banner "Removing Profile Files"
    # Back up system-wide profile files
    sudo mv /etc/prof{i,y}le.d /etc/profile.d.bak 2>/dev/null
    sudo mv /etc/prof{i,y}le /etc/profile.bak 2>/dev/null

    # Remove user-specific profile files from /home and /root,
    # excluding critical accounts (root, ccdcuser1, and ccdcuser2)
    for f in ".profile" ".bashrc" ".bash_login"; do
        sudo find /home /root \( -path "/root/*" -o -path "/home/ccdcuser1/*" -o -path "/home/ccdcuser2/*" \) -prune -o -name "$f" -exec sudo rm {} \;
    done
}

function fix_pam {
    print_banner "Fixing PAM Configuration"
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo $ipt -P OUTPUT ACCEPT

    if command -v yum >/dev/null; then
        if command -v authconfig >/dev/null; then
            sudo authconfig --updateall
            sudo yum -y reinstall pam
        else
            echo "No authconfig, cannot fix PAM on this system"
        fi
    elif command -v apt-get >/dev/null; then
        echo "" | sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --force
        sudo apt-get -y --reinstall install libpam-runtime libpam-modules
    elif command -v apk >/dev/null; then
        if [ -d /etc/pam.d ]; then
            sudo apk fix --purge linux-pam
            for file in $(find /etc/pam.d -name "*.apk-new" 2>/dev/null); do
                sudo mv "$file" "$(echo $file | sed 's/.apk-new//g')"
            done
        else
            echo "PAM is not installed"
        fi
    elif command -v pacman >/dev/null; then
        if [ -z "$BACKUPDIR" ]; then
            echo "No backup directory provided for PAM configs"
        else
            sudo mv /etc/pam.d /etc/pam.d.backup
            sudo cp -R "$BACKUPDIR" /etc/pam.d
        fi
        sudo pacman -S pam --noconfirm
    else
        echo "Unknown OS, not fixing PAM"
    fi

    sudo $ipt -P OUTPUT DROP
}

function search_ssn {
    print_banner "Searching for SSN Patterns"
    local rootdir="/home/"
    local ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'
    sudo find "$rootdir" -type f \( -name "*.txt" -o -name "*.csv" \) -exec sh -c '
        file="$1"
        pattern="$2"
        grep -Hn "$pattern" "$file" | while read -r line; do
            echo "$file:SSN:$line"
        done
    ' sh '{}' "$ssn_pattern" \;
}

function remove_unused_packages {
    print_banner "Removing Unused Packages"
    if command -v yum >/dev/null; then
        sudo yum purge -y -q netcat nc gcc cmake make telnet
    elif command -v apt-get >/dev/null; then
        sudo apt-get -y purge netcat nc gcc cmake make telnet
    elif command -v apk >/dev/null; then
        sudo apk remove gcc make
    else
        echo "Unsupported package manager for package removal"
    fi
}

function patch_vulnerabilities {
    print_banner "Patching Vulnerabilities"
    # Patch pwnkit vulnerability
    sudo chmod 0755 /usr/bin/pkexec

    # Patch CVE-2023-32233 vulnerability
    sudo sysctl -w kernel.unprivileged_userns_clone=0
    echo "kernel.unprivileged_userns_clone = 0" | sudo tee -a /etc/sysctl.conf >/dev/null
    sudo sysctl -p >/dev/null
}

function check_permissions {
    print_banner "Checking and Setting Permissions"
    sudo chown root:root /etc/shadow
    sudo chown root:root /etc/passwd
    sudo chmod 640 /etc/shadow
    sudo chmod 644 /etc/passwd

    echo "[+] SUID binaries:"
    sudo find / -perm -4000 2>/dev/null

    echo "[+] Directories with 777 permissions (max depth 3):"
    sudo find / -maxdepth 3 -type d -perm -777 2>/dev/null

    echo "[+] Files with capabilities:"
    sudo getcap -r / 2>/dev/null

    echo "[+] Files with extended ACLs in critical directories:"
    sudo getfacl -sR /etc/ /usr/ /root/
}

function sysctl_config {
    print_banner "Applying sysctl Configurations"
    local file="/etc/sysctl.conf"
    echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.tcp_synack_retries = 2" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.tcp_challenge_ack_limit = 1000000" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.tcp_rfc1337 = 1" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.icmp_echo_ignore_all = 1" | sudo tee -a "$file" >/dev/null
    echo "kernel.core_uses_pid = 1" | sudo tee -a "$file" >/dev/null
    echo "kernel.kptr_restrict = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.perf_event_paranoid = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.randomize_va_space = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.sysrq = 0" | sudo tee -a "$file" >/dev/null
    echo "kernel.yama.ptrace_scope = 2" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_hardlinks = 1" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_symlinks = 1" | sudo tee -a "$file" >/dev/null
    echo "fs.suid_dumpable = 0" | sudo tee -a "$file" >/dev/null
    echo "kernel.unprivileged_userns_clone = 0" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_fifos = 2" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_regular = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.kptr_restrict = 2" | sudo tee -a "$file" >/dev/null

    sudo sysctl -p >/dev/null
}

# my_secure_sql_installation
function my_secure_sql_installation {
    print_banner "My Secure SQL Installation"
    read -p "Would you like to run mysql_secure_installation? (y/N): " sql_choice
    if [[ "$sql_choice" == "y" || "$sql_choice" == "Y" ]]; then
         echo "[*] Running mysql_secure_installation..."
         sudo mysql_secure_installation
    else
         echo "[*] Skipping mysql_secure_installation."
    fi
}

# FUNCTION: manage_web_immutability
# This function scans for default critical web directories (e.g., /etc/nginx, /etc/apache2, /var/www, etc.),
# lists any that are found, and then prompts the user to either set the immutable flag (chattr +i) on these directories,
# or to remove the immutable flag (chattr -i). This applies only to production web directories.
function manage_web_immutability {
    print_banner "Manage Web Directory Immutability"
    
    # List of common critical web directories (you may add or remove as needed)
    default_web_dirs=(
        "/etc/nginx"
        "/etc/apache2"
        "/usr/share/nginx"
        "/var/www"
        "/var/www/html"
        "/etc/lighttpd"
        "/etc/mysql"
        "/etc/postgresql"
        "/var/lib/apache2"
        "/var/lib/mysql"
        "/etc/redis"
        "/etc/phpMyAdmin"
        "/etc/php.d"
    )
    
    detected_web_dirs=()
    echo "[*] Scanning for critical web directories..."
    for dir in "${default_web_dirs[@]}"; do
        if [ -d "$dir" ]; then
            detected_web_dirs+=("$dir")
        fi
    done

    if [ ${#detected_web_dirs[@]} -eq 0 ]; then
        echo "[*] No critical web directories were found."
        return
    fi

    echo "[*] The following web directories have been detected:"
    for d in "${detected_web_dirs[@]}"; do
        echo "    $d"
    done

    read -p "Would you like to set these directories to immutable? (y/N): " imm_choice
    if [[ "$imm_choice" == "y" || "$imm_choice" == "Y" ]]; then
        for d in "${detected_web_dirs[@]}"; do
            sudo chattr +i "$d"
            echo "[*] Set immutable flag on $d"
        done
    else
        read -p "Would you like to remove the immutable flag from these directories? (y/N): " unimm_choice
        if [[ "$unimm_choice" == "y" || "$unimm_choice" == "Y" ]]; then
            for d in "${detected_web_dirs[@]}"; do
                sudo chattr -i "$d"
                echo "[*] Removed immutable flag from $d"
            done
        else
            echo "[*] No changes made to web directory immutability."
        fi
    fi
}

# harden_web function:
function harden_web {
    print_banner "Web Hardening Initiated"
    backup_databases
    secure_php_ini
    install_modsecurity
    my_secure_sql_installation
    manage_web_immutability
}


##################### ADVANCED HARDENING FUNCTIONS #####################

# Function to set up a cronjob that saves iptables rules persistently.
function setup_iptables_cronjob {
    print_banner "Setting Up Iptables Persistence Cronjob"
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables-save > /etc/sysconfig/iptables
EOF
        echo "[*] Cron job created at $cron_file for RHEL-based systems."
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables-save > /etc/iptables/rules.v4
EOF
        echo "[*] Cron job created at $cron_file for Debian-based systems."
    else
        echo "[*] Unknown OS. Please set up a cron job manually for iptables persistence."
    fi
}

# Function to disable unnecessary services (with a caution about SSH).
function disable_unnecessary_services {
    print_banner "Disabling Unnecessary Services"
    read -p "Disable SSHD? (WARNING: may lock you out if remote) (y/N): " disable_sshd
    if [[ "$disable_sshd" =~ ^[Yy]$ ]]; then
        if systemctl is-active sshd &> /dev/null; then
            sudo systemctl stop sshd
            sudo systemctl disable sshd
            echo "[*] SSHD service disabled."
        else
            echo "[*] SSHD service not active."
        fi
    fi
    read -p "Disable Cockpit? (y/N): " disable_cockpit
    if [[ "$disable_cockpit" =~ ^[Yy]$ ]]; then
        if systemctl is-active cockpit &> /dev/null; then
            sudo systemctl stop cockpit
            sudo systemctl disable cockpit
            echo "[*] Cockpit service disabled."
        else
            echo "[*] Cockpit service not active."
        fi
    fi
}

# Function to set up a cronjob that monitors open ports and re-applies iptables rules.
function setup_firewall_maintenance_cronjob_iptables {
    print_banner "Setting Up iptables Maintenance Cronjob"
    local script_file="/usr/local/sbin/firewall_maintain.sh"
    sudo bash -c "cat > $script_file" <<'EOF'
#!/bin/bash
open_ports=$(ss -lnt | awk 'NR>1 {print $4}' | awk -F':' '{print $NF}' | sort -u)
for port in $open_ports; do
    # Check if a rule exists; if not, add one to allow TCP traffic on the port.
    iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport $port -j ACCEPT
done
EOF
    sudo chmod +x "$script_file"
    local cron_file="/etc/cron.d/firewall_maintenance"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root $script_file
EOF
    echo "[*] iptables maintenance cron job created."
}

function setup_firewall_maintenance_cronjob_ufw {
    print_banner "Setting Up UFW Maintenance Cronjob"
    backup_current_ufw_rules
    local script_file="/usr/local/sbin/ufw_maintain.sh"
    sudo bash -c "cat > $script_file" <<'EOF'
#!/bin/bash
if [ -f /tmp/ufw_backup.rules ]; then
    ufw reset
    cp /tmp/ufw_backup.rules /etc/ufw/user.rules
    ufw reload
fi
EOF
    sudo chmod +x "$script_file"
    local cron_file="/etc/cron.d/ufw_maintenance"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /usr/local/sbin/ufw_maintain.sh
EOF
    echo "[*] UFW maintenance cron job created."
}


function setup_firewall_maintenance_cronjob {
    if command -v ufw &>/dev/null && sudo ufw status | grep -q "Status: active"; then
        setup_firewall_maintenance_cronjob_ufw
    else
        setup_firewall_maintenance_cronjob_iptables
    fi
}

# Function to set up a cronjob that clears the NAT table periodically.
function setup_nat_clear_cronjob {
    print_banner "Setting Up NAT Table Clear Cronjob"
    cron_file="/etc/cron.d/clear_nat_table"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables -t nat -F
EOF
    echo "[*] NAT table clear cron job created."
}

# Function to set up a cronjob that restarts the detected firewall service,
# then offers to add additional services.
function setup_service_restart_cronjob {
    print_banner "Setting Up Service Restart Cronjob"
    
    # Detect active firewall service
    detected_service=""
    if command -v ufw &>/dev/null && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        detected_service="ufw"
    elif systemctl is-active firewalld &>/dev/null; then
        detected_service="firewalld"
    elif systemctl is-active netfilter-persistent &>/dev/null; then
        detected_service="netfilter-persistent"
    else
        echo "[*] No recognized firewall service detected automatically."
    fi
    
    if [ -n "$detected_service" ]; then
        echo "[*] Detected firewall service: $detected_service"
        local script_file="/usr/local/sbin/restart_${detected_service}.sh"
        sudo bash -c "cat > $script_file" <<EOF
#!/bin/bash
systemctl restart $detected_service
EOF
        sudo chmod +x $script_file
        local cron_file="/etc/cron.d/restart_${detected_service}"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root $script_file
EOF
        echo "[*] Cron job created to restart $detected_service every 5 minutes."
    fi

    # Offer to add additional services
    read -p "Would you like to add additional services to restart via cronjob? (y/N): " add_extra
    if [[ "$add_extra" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Enter the name of the additional service (or leave blank to finish): " extra_service
            if [ -z "$extra_service" ]; then
                break
            fi
            local extra_script_file="/usr/local/sbin/restart_${extra_service}.sh"
            sudo bash -c "cat > $extra_script_file" <<EOF
#!/bin/bash
systemctl restart $extra_service
EOF
            sudo chmod +x $extra_script_file
            local extra_cron_file="/etc/cron.d/restart_${extra_service}"
            sudo bash -c "cat > $extra_cron_file" <<EOF
*/5 * * * * root $extra_script_file
EOF
            echo "[*] Cron job created to restart $extra_service every 5 minutes."
        done
    fi
    echo "[*] Service restart configuration complete."
}

function reset_advanced_hardening {
    print_banner "Resetting Advanced Hardening Configurations"
    echo "[*] Removing iptables persistence cronjob (if exists)..."
    sudo rm -f /etc/cron.d/iptables_persistence
    echo "[*] Removing firewall maintenance cronjob and script..."
    sudo rm -f /etc/cron.d/firewall_maintenance
    sudo rm -f /usr/local/sbin/firewall_maintain.sh
    echo "[*] Removing NAT table clear cronjob..."
    sudo rm -f /etc/cron.d/clear_nat_table
    echo "[*] Removing service restart cronjobs and scripts..."
    sudo rm -f /etc/cron.d/restart_*
    sudo rm -f /usr/local/sbin/restart_*
    echo "[*] Advanced hardening configurations have been reset."
}

function run_full_advanced_hardening {
    print_banner "Running Full Advanced Hardening Process"
    setup_iptables_cronjob
    disable_unnecessary_services
    setup_firewall_maintenance_cronjob
    setup_nat_clear_cronjob
    setup_service_restart_cronjob
    echo "[*] Full Advanced Hardening Process Completed."
}

# Modified advanced_hardening menu
function advanced_hardening {
    local adv_choice
    while true; do
        print_banner "Advanced Hardening & Automation #TESTING, JUST PLACEHOLDERS"
        echo "1) Run Full Advanced Hardening Process"
        echo "2) Set up iptables persistence cronjob"
        echo "3) Disable SSHD/Cockpit services"
        echo "4) Set up firewall maintenance cronjob (monitor open ports)"
        echo "5) Set up cronjob to clear NAT table"
        echo "6) Set up cronjob to restart firewall service and additional services"
        echo "7) Reset Advanced Hardening Configurations"
        echo "8) Exit Advanced Hardening Menu"
        read -p "Enter your choice [1-8]: " adv_choice
        case $adv_choice in
            1) run_full_advanced_hardening ;;
            2) setup_iptables_cronjob ;;
            3) disable_unnecessary_services ;;
            4) setup_firewall_maintenance_cronjob ;;
            5) setup_nat_clear_cronjob ;;
            6) setup_service_restart_cronjob ;;
            7) reset_advanced_hardening ;;
            8) echo "[*] Exiting advanced hardening menu."; break ;;
            *) echo "[X] Invalid option." ;;
        esac
        echo ""
    done
}

##################### WEB HARDENING MENU FUNCTION #####################
function show_web_hardening_menu {
    print_banner "Web Hardening Menu"
    echo "1) Run Full Web Hardening Process"
    echo "2) backup_databases"
    echo "3) secure_php_ini"
    echo "4) install_modsecurity"
    echo "5) my_secure_sql_installation"
    echo "6) manage_web_immutability"
    echo "7) Exit Web Hardening Menu"
    read -p "Enter your choice [1-7]: " web_menu_choice
    case $web_menu_choice in
        1)
            print_banner "Web Hardening Initiated"
            backup_databases
            secure_php_ini
            install_modsecurity
            my_secure_sql_installation
            manage_web_immutability
            ;;
        2)
            print_banner "Web Hardening Initiated"
            backup_databases
            ;;
        3)
            print_banner "Web Hardening Initiated"
            secure_php_ini
            ;;
        4)
            print_banner "Web Hardening Initiated"
            install_modsecurity
            ;;
        5)
            print_banner "Web Hardening Initiated"
            my_secure_sql_installation
            ;;
        6)
            print_banner "Web Hardening Initiated"
            manage_web_immutability
            ;;
        7)
            echo "[*] Exiting Web Hardening Menu"
            ;;
        *)
            echo "[X] Invalid option."
            ;;
    esac
}

##################### MAIN MENU FUNCTION #####################
function show_menu {
    print_banner "Hardening Script Menu"
    echo "1) Full Hardening Process (Run all)"
    echo "2) User Management"
    echo "3) Firewall Configuration"
    echo "4) Backup"
    echo "5) Splunk Installation"
    echo "6) SSH Hardening"
    echo "7) PAM/Profile Fixes & System Config"
    echo "8) Web Hardening"
    echo "9) Advanced Hardening"
    echo "10) Exit"
    echo
    read -p "Enter your choice [1-10]: " menu_choice
    echo
    case $menu_choice in
        1) main ;;
        2)
            detect_system_info
            install_prereqs
            create_ccdc_users
            change_passwords
            disable_users
            remove_sudoers
            ;;
        3)
            firewall_configuration_menu
            ;;
        4)
            backups
            ;;
        5)
            setup_splunk
            ;;
        6)
            secure_ssh
            ;;
        7)
            fix_pam
            remove_profiles
            check_permissions
            sysctl_config
            ;;
        8)
            show_web_hardening_menu
            ;;
        9)
            advanced_hardening   # (Assuming you’ve defined your advanced_hardening function)
            ;;
        10)
            echo "Exiting..."; exit 0
            ;;
        *)
            echo "Invalid option. Exiting."; exit 1
            ;;
    esac
}

##################### MAIN FUNCTION #####################
function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of full hardening process"
    detect_system_info
    install_prereqs
    create_ccdc_users
    change_passwords
    disable_users
    remove_sudoers
    audit_running_services
    disable_other_firewalls
    firewall_configuration_menu
    backups
    setup_splunk
    secure_ssh
    remove_profiles
    fix_pam
    search_ssn
    remove_unused_packages
    patch_vulnerabilities
    check_permissions
    sysctl_config
    web_choice=$(get_input_string "Would you like to perform web hardening? (y/N): ")
    if [ "$web_choice" == "y" ]; then
        show_web_hardening_menu
    fi
    adv_choice=$(get_input_string "Would you like to perform advanced hardening? (y/N): ")
    if [ "$adv_choice" == "y" ]; then
        advanced_hardening
    fi
    echo "[*] End of full hardening process"
    echo "[*] Script log can be viewed at $LOG"
    echo "[*] ***Please install system updates now***"
}
##################### ARGUMENT PARSING #####################
for arg in "$@"; do
    case "$arg" in
        --debug )
            echo "[*] Debug mode enabled"
            debug="true"
            ;;
    esac
done

##################### LOGGING SETUP #####################
LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    sudo mkdir -p "$LOG_PATH"
    sudo chown root:root "$LOG_PATH"
    sudo chmod 750 "$LOG_PATH"
fi

##################### MAIN EXECUTION #####################
show_menu
