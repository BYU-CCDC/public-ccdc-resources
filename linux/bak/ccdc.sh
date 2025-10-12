#!/bin/bash
# Usage: ./harden.sh [option]
#    e.g.: ./harden.sh -ansible
#
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
ANSIBLE="false"      # When set to "true", interactive prompts will be skipped.
IPTABLES_BACKUP="/tmp/iptables_backup.rules"
UFW_BACKUP="/tmp/ufw_backup.rules"
#####################################################

##################### FUNCTIONS #####################

# Prints text in a banner
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
    if [ "$ANSIBLE" == "true" ]; then
        echo ""
    else
        read -r -p "$1" input
        echo "$input"
    fi
}

function get_silent_input_string {
    if [ "$ANSIBLE" == "true" ]; then
        echo "DefaultPass123!"
    else
        read -r -s -p "$1" input
        echo "$input"
    fi
}

function get_input_list {
    if [ "$ANSIBLE" == "true" ]; then
        echo ""
    else
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
    fi
}

function exclude_users {
    if [ "$ANSIBLE" == "true" ]; then
        echo "$@"
    else
        users="$@"
        input=$(get_input_list)
        for item in $input; do
            users+=("$item")
        done
        echo "${users[@]}"
    fi
}

function get_users {
    awk_string=$1
    exclude_users=$(sed -e 's/ /\\|/g' <<< $2)
    users=$(awk -F ':' "$awk_string" /etc/passwd)
    filtered=$(echo "$users" | grep -v -e $exclude_users)
    readarray -t results <<< "$filtered"
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
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping root password change."
        return 0
    fi
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

function create_ccdc_users {
    if [ "$ANSIBLE" == "true" ]; then
        print_banner "Creating ccdc users (Ansible mode: Non-interactive)"
        default_password="ChangeMe123!"
        for user in "${ccdc_users[@]}"; do
            if ! id "$user" &>/dev/null; then
                if [ -f "/bin/bash" ]; then
                    sudo useradd -m -s /bin/bash "$user"
                else
                    sudo useradd -m -s /bin/sh "$user"
                fi
                echo "[*] Creating $user with default password."
                echo "$user:$default_password" | sudo chpasswd
                sudo usermod -aG $sudo_group "$user"
            else
                echo "[*] $user exists. Skipping interactive password update."
            fi
        done
        return 0
    fi
    print_banner "Creating ccdc users"
    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
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
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping bulk password change."
        return 0
    fi
    print_banner "Changing user passwords"
    exclusions=("root" "${ccdc_users[@]}")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '$1 != "nobody" {print $1}' "${exclusions[*]}")
    echo "[*] Enter the new password to be used for all users."
    while true; do
        password=""
        confirm_password=""
        password=$(get_silent_input_string "Enter password: ")
        echo
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
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping user disabling."
        return 0
    fi
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

function disable_other_firewalls {
    print_banner "Disabling existing firewalls"
    if sudo command -v firewalld &>/dev/null; then
        echo "[*] Disabling firewalld"
        sudo systemctl stop firewalld
        sudo systemctl disable firewalld
    fi
}

########################################################################
# FUNCTION: backup_current_iptables_rules
########################################################################
function backup_current_iptables_rules {
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
        echo "[*] Iptables rules saved to /etc/sysconfig/iptables"
    elif grep -qi 'suse' /etc/os-release; then
        sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
        echo "[*] Iptables rules saved to /etc/sysconfig/iptables (SUSE)"
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
########################################################################
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
    echo -e "[*] UFW installed and configured with strict outbound deny (except DNS) successfully.\n"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping additional inbound port configuration."
    else
        echo "[*] Which additional ports should be opened for incoming traffic?"
        echo "      WARNING: Do NOT forget to add 22/SSH if needed - please don't accidentally lock yourself out!"
        ports=$(get_input_list)
        for port in $ports; do
            sudo ufw allow "$port"
            echo "[*] Rule added for port $port"
        done
    fi
    sudo ufw logging on
    sudo ufw --force enable
    backup_current_ufw_rules
}


########################################################################
# FUNCTION: configure_security_modules
# Detects OS, then installs and configures SELinux (on RHEL-based) or
# AppArmor (on Debian/Ubuntu/OpenSUSE). Removes references to disabling
# or opening firewall policies here, relying instead on your existing
# firewall rules for outbound 80/443/53.
########################################################################
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
            echo "[*] Detected a RHEL-like OS ($distro). Attempting SELinux setup..."
            setup_selinux_rhel
            ;;
        # Debian, Ubuntu (and possibly Linux Mint which also says 'ubuntu' in /etc/os-release)
        debian|ubuntu|linuxmint)
            echo "[*] Detected a Debian-like OS ($distro). Attempting AppArmor setup..."
            setup_apparmor_debian
            ;;
        # openSUSE or SLES often uses AppArmor by default
        opensuse*)
            echo "[*] Detected openSUSE ($distro). Attempting AppArmor setup..."
            setup_apparmor_debian  # same function works for openSUSE if it has zypper
            ;;
        # fallback
        *)
            echo "[!] Unrecognized distro: $distro"
            echo "[!] Attempting generic check for apt-get or zypper or yum to decide..."
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
                echo "[X] Could not determine how to install SELinux or AppArmor on this OS. Aborting."
                return 1
            fi
            ;;
    esac
}


########################################################################
# FUNCTION: setup_selinux_rhel
# Installs and enables SELinux on RHEL-like distros (RHEL, CentOS, Fedora, etc.)
########################################################################
function setup_selinux_rhel {
    # Optional prompt for user
    read -p "Would you like to install/configure SELinux in Enforcing mode? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "[*] Skipping SELinux setup."
        return 0
    fi

    echo "[*] Installing SELinux-related packages..."
    if command -v yum &>/dev/null; then
        sudo yum install -y selinux-policy selinux-policy-targeted policycoreutils
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y selinux-policy selinux-policy-targeted policycoreutils
    else
        echo "[X] No recognized package manager found for SELinux installation on a RHEL-like OS."
        return 1
    fi

    echo "[*] Ensuring SELinux is set to enforcing..."
    if [ -f /etc/selinux/config ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    fi

    # Attempt to set enforce at runtime
    if command -v setenforce &>/dev/null; then
        sudo setenforce 1 || echo "[!] Could not setenforce 1. Check if SELinux is disabled at boot level."
    fi

    echo "[*] SELinux packages installed. SELinux is configured to enforcing in /etc/selinux/config."
    echo "[*] If the system was previously in 'disabled' mode, a reboot may be required for full SELinux enforcement."
}


########################################################################
# FUNCTION: setup_apparmor_debian
# Installs AppArmor on Debian/Ubuntu-based distros (and possibly openSUSE).
########################################################################
function setup_apparmor_debian {
    # Optional prompt for user
    read -p "Would you like to install/configure AppArmor? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "[*] Skipping AppArmor setup."
        return 0
    fi

    echo "[*] Installing AppArmor-related packages..."

    # For Debian/Ubuntu
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -y
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

        echo "[*] AppArmor installed and started. Profiles are enforced if present."
    elif command -v zypper &>/dev/null; then
        # openSUSE approach
        sudo zypper refresh
        sudo zypper install -y apparmor-profiles apparmor-utils
        # In openSUSE, AppArmor might already be installed and enabled by default
        # etc.
        sudo systemctl enable apparmor
        sudo systemctl start apparmor
        echo "[*] AppArmor installed/enabled under openSUSE."
    else
        echo "[X] Could not find apt-get or zypper. Aborting AppArmor setup."
        return 1
    fi
}





# ============================================================
# FUNCTION: setup_proxy_certificates_and_config
# ============================================================
# This function prompts the user to input the required proxy
# and certificate download URLs, and then configures the system's
# trusted certificates and proxy settings. It supports the major
# Linux distributions (RHEL/CentOS, Debian/Ubuntu, Alpine, and
# Slackware [stub]). You can adjust the default prompts and file
# paths if your environment differs.
# ============================================================
function setup_proxy_certificates_and_config {
    print_banner "Proxy and Certificate Configuration Setup"

    # Prompt the user for required URLs
    read -p "Enter the Proxy URL (e.g., http://192.168.1.107:8000): " user_proxy
    if [ -z "$user_proxy" ]; then
        echo "[X] No proxy URL provided. Aborting configuration."
        return 1
    fi
    PROXY="$user_proxy"

    read -p "Enter the Certificate CRT URL (e.g., http://192.168.1.107:9000/mitmproxy-ca-cert.crt): " user_patch_url
    if [ -z "$user_patch_url" ]; then
        echo "[X] No certificate CRT URL provided. Aborting configuration."
        return 1
    fi
    PATCH_URL="$user_patch_url"

    read -p "Enter the Certificate PEM URL (e.g., http://192.168.1.107:9000/mitmproxy-ca-cert.pem): " user_pem_url
    if [ -z "$user_pem_url" ]; then
        echo "[X] No certificate PEM URL provided. Aborting configuration."
        return 1
    fi
    PEM_URL="$user_pem_url"

    echo "[*] Proxy is set to: $PROXY"
    echo "[*] CRT will be downloaded from: $PATCH_URL"
    echo "[*] PEM will be downloaded from: $PEM_URL"

    # Now, detect which OS we’re running and call the corresponding helper.
    if command -v yum &>/dev/null ; then
        RHEL_proxy_setup
    elif command -v apt-get &>/dev/null ; then
        if grep -qi Ubuntu /etc/os-release; then
            UBUNTU_proxy_setup
        else
            DEBIAN_proxy_setup
        fi
    elif command -v apk &>/dev/null ; then
        ALPINE_proxy_setup
    elif command -v slapt-get &>/dev/null || grep -qi Slackware /etc/os-release ; then
        SLACK_proxy_setup
    else
        echo "[X] Unsupported or unknown OS for proxy/certificate configuration."
        return 1
    fi

    echo "[*] Proxy and certificate configuration completed."
}

# ============================================================
# Helper Functions for OS-Specific Proxy & Certificate Setup
# ============================================================

# --- RHEL/CentOS-based Systems ---
function RHEL_proxy_setup {
    echo "[*] Setting up proxy and installing certificate for RHEL-based systems..."
    yum install -y ca-certificates curl
    # Download the certificate files via the proxy
    curl -o cert.crt --proxy "$PROXY" "$PATCH_URL"
    curl -o cert.pem --proxy "$PROXY" "$PEM_URL"
    # Copy certificates to the system's anchor directory
    cp cert.crt /etc/pki/ca-trust/source/anchors/
    cp cert.pem /etc/pki/ca-trust/source/anchors/
    # Set permissions (644 is typical for certificates)
    chmod 644 /etc/pki/ca-trust/source/anchors/cert.crt
    chmod 644 /etc/pki/ca-trust/source/anchors/cert.pem
    # Update the certificate store
    update-ca-trust
    # Configure yum proxy settings
    echo "proxy=$PROXY" | tee -a /etc/yum.conf >/dev/null
    # Optionally, add proxy environment variables to ~/.bashrc
    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc
    source ~/.bashrc
    echo "[*] RHEL-based proxy and certificate configuration completed."
}

# --- Debian-Based Systems (also used for Ubuntu) ---
function DEBIAN_proxy_setup {
    echo "[*] Setting up proxy and installing certificate for Debian-based systems..."
    apt update
    apt install -y ca-certificates curl
    # Download certificate files via the proxy
    curl -o cert.crt --proxy "$PROXY" "$PATCH_URL"
    curl -o certPem.pem --proxy "$PROXY" "$PEM_URL"
    # Convert PEM file to CRT format (or simply rename)
    mv certPem.pem certPem.crt
    # Create extra directory if it does not exist
    mkdir -p /usr/share/ca-certificates/extra
    cp cert.crt /usr/share/ca-certificates/extra/cert.crt
    cp certPem.crt /usr/share/ca-certificates/extra/certPem.crt
    # Update certificates using dpkg and update-ca-certificates
    dpkg-reconfigure ca-certificates
    update-ca-certificates
    # Configure apt to use the proxy
    echo "Acquire::http::Proxy \"$PROXY\";" | tee /etc/apt/apt.conf.d/proxy.conf >/dev/null
    echo "Acquire::https::Proxy \"$PROXY\";" | tee -a /etc/apt/apt.conf.d/proxy.conf >/dev/null
    # Set proxy environment variables for current session
    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc
    source ~/.bashrc
    echo "[*] Debian-based proxy and certificate configuration completed."
}

function UBUNTU_proxy_setup {
    echo "[*] Detected Ubuntu. Using Debian configuration..."
    DEBIAN_proxy_setup
}

# --- Alpine Linux ---
function ALPINE_proxy_setup {
    echo "[*] Setting up proxy and installing certificate for Alpine Linux..."
    apk add --no-cache ca-certificates curl
    # Download the certificate file (using the CRT URL)
    curl -o cert.pem --proxy "$PROXY" "$PATCH_URL"
    cp cert.pem /usr/local/share/ca-certificates/
    update-ca-certificates
    # Configure repository proxy settings (if desired)
    # Here, you might add proxy URLs to /etc/apk/repositories if required.
    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc
    source ~/.bashrc
    echo "[*] Alpine Linux proxy and certificate configuration completed."
}


########################################################################
# FUNCTION: ufw_disable_default_deny
########################################################################
function ufw_disable_default_deny {
    print_banner "Temporarily Disabling UFW Default Deny Outgoing Policy"
    sudo ufw default allow outgoing
    echo "[*] UFW default outgoing policy is now set to allow."
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: ufw_enable_default_deny
########################################################################
function ufw_enable_default_deny {
    print_banner "Re-enabling UFW Default Deny Outgoing Policy"
    sudo ufw default deny outgoing
    sudo ufw allow out on lo
    sudo ufw allow out to any port 53 proto tcp
    sudo ufw allow out to any port 53 proto udp
    echo "[*] UFW default outgoing policy is now set to deny."
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: setup_custom_iptables
########################################################################
function setup_custom_iptables {
    print_banner "Configuring iptables (Custom Script)"
    reset_iptables

    # Set default policies: DROP for INPUT and OUTPUT
    sudo iptables -P OUTPUT DROP
    sudo iptables -P INPUT DROP

    # Allow loopback traffic by default.
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT

    # (Optional) Drop FORWARD chain (if this box is not a router)
    sudo iptables -P FORWARD DROP
    echo "[WARNING] FORWARD chain is set to DROP. If this box is a router or network device, please run 'sudo iptables -P FORWARD ALLOW'."

    # Allow established/related connections.
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow outbound DNS queries.
    sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    # Allow inbound DNS traffic.
    sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT

    # Allow ICMP traffic (for pings).
    sudo iptables -A INPUT -p icmp -j ACCEPT
    sudo iptables -A OUTPUT -p icmp -j ACCEPT

    # Allow outbound HTTPS (443) and HTTP (80) by default.
    sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

    # Read current running TCP listening ports and allow inbound traffic (except port 53).
    running_ports=$(ss -lnt | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -nu)
    for port in $running_ports; do
        if [ "$port" != "53" ]; then
            sudo iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        fi
    done

    echo "Select your DNS server option:"
    echo "  1) Use Cloudflare DNS servers (1.1.1.1, 1.0.0.1)"
    echo "  2) Use default gateway/router as your DNS server"
    echo "  3) Use default DNS servers (192.168.XXX.1, 192.168.XXX.2)"
    if [ "$ANSIBLE" == "true" ]; then
        dns_choice="1"
        echo "[*] Ansible mode: Defaulting DNS server option to 1."
    else
        dns_choice=$(get_input_string "Enter your choice [1-3]: ")
    fi
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
    backup_current_iptables_rules
    if [ "$ANSIBLE" == "false" ]; then
        ext_choice=$(get_input_string "Would you like to add any additional iptables rules? (y/N): ")
        if [[ "$ext_choice" == "y" || "$ext_choice" == "Y" ]]; then
            extended_iptables
        fi
    else
        echo "[*] Ansible mode: Skipping additional iptables rule prompts."
    fi
}

########################################################################
# FUNCTION: open_ossec_ports
########################################################################
function open_ossec_ports {
    print_banner "Opening OSSEC Ports"
    sudo iptables -A OUTPUT -p udp --dport 1514 -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 1515 -j ACCEPT
    echo "[*] OSSEC outbound ports 1514 and 1515 (UDP) have been opened."
    backup_current_iptables_rules
}

########################################################################
# FUNCTION: apply_established_only_rules
########################################################################
function apply_established_only_rules {
    print_banner "Applying Established/Related Only Rules"
    reset_iptables
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    backup_current_iptables_rules
}

########################################################################
# FUNCTION: iptables_disable_default_deny
########################################################################
function iptables_disable_default_deny {
    print_banner "Temporarily Disabling iptables Default Deny Outgoing Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P INPUT ACCEPT
    echo "[*] iptables default policies are now set to ACCEPT (backup saved)."
}

########################################################################
# FUNCTION: iptables_enable_default_deny
########################################################################
function iptables_enable_default_deny {
    print_banner "Re-enabling iptables Default Deny Outgoing Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT DROP
    sudo iptables -P INPUT DROP
    echo "[*] iptables default policies are now set to DROP (current rules preserved)."
}

########################################################################
# FUNCTION: custom_iptables_manual_rules (inbound)
########################################################################
function custom_iptables_manual_rules {
    print_banner "Manual Inbound IPtables Rule Addition"
    echo "[*] Enter port numbers (one per line) for which you wish to allow inbound TCP traffic."
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping manual inbound rule addition."
        return 0
    fi
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
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping manual outbound rule addition."
        return 0
    fi
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
########################################################################
function extended_iptables {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping extended iptables management."
        return 0
    fi
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
########################################################################
function firewall_configuration_menu {
    detect_system_info
    install_prereqs
    disable_other_firewalls
    audit_running_services
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Running default firewall configuration (iptables)."
         setup_custom_iptables
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
                echo "  11) Open OSSEC Ports (UDP 1514 & 1515)"
                echo "  12) Allow only Established/Related Traffic"
                echo "  13) Exit IPtables menu"
                read -p "Enter your choice [1-13]: " ipt_choice
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
                        open_ossec_ports
                        ;;
                    12)
                        apply_established_only_rules
                        ;;
                    13)
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


function toggle_permissions {
    local mode="${1:-apply}"
    
    if [ "$mode" == "revert" ]; then
        echo -e "\033[34m[i] Reverting Permissions\033[0m"
        setfacl -x u:www-data "$(which bash)" 2>/dev/null
        setfacl -x u:www-data "$(which dash)" 2>/dev/null
        setfacl -x u:www-data "$(which sh)" 2>/dev/null
        setfacl -x u:www-data "$(which setfacl)" 2>/dev/null
        setfacl -x u:apache "$(which bash)" 2>/dev/null
        setfacl -x u:apache "$(which dash)" 2>/dev/null
        setfacl -x u:apache "$(which sh)" 2>/dev/null
        setfacl -x u:apache "$(which setfacl)" 2>/dev/null
    else
        echo -e "\033[34m[i] Setting Permissions\033[0m"
        setfacl -m u:www-data:--- "$(which bash)" 2>/dev/null
        setfacl -m u:www-data:--- "$(which dash)" 2>/dev/null
        setfacl -m u:www-data:--- "$(which sh)" 2>/dev/null
        setfacl -m u:www-data:--- "$(which setfacl)" 2>/dev/null
        setfacl -m u:apache:--- "$(which bash)" 2>/dev/null
        setfacl -m u:apache:--- "$(which dash)" 2>/dev/null
        setfacl -m u:apache:--- "$(which sh)" 2>/dev/null
        setfacl -m u:apache:--- "$(which setfacl)" 2>/dev/null
    fi
}


########################################################################
# FUNCTION: backup_directories
########################################################################
function backup_directories {
    print_banner "Backup Directories"

    # Adjust this list so that /var/www/html is used instead of both /var/www & /var/www/html
    default_dirs=( "/var/www/html" "/etc/apache2" "/etc/mysql" "/var/lib/apache2" "/var/lib/mysql" )

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

    echo
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

    if [ ${#backup_list[@]} -eq 0 ]; then
        echo "[*] No directories or files selected for backup. Exiting backup."
        return
    fi

    # Prompt for a name for the backup archive.
    local backup_name=""
    while true; do
        backup_name=$(get_input_string "Enter a name for the backup archive (without extension .zip): ")
        if [ -n "$backup_name" ]; then
            # Ensure it has a .zip extension
            if [[ "$backup_name" != *.zip ]]; then
                backup_name="${backup_name}.zip"
            fi
            break
        else
            echo "[X] ERROR: Backup name cannot be blank."
        fi
    done

    echo "[*] Creating archive..."
    zip -r "$backup_name" "${backup_list[@]}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Failed to create archive."
        return
    fi
    echo "[*] Archive created: $backup_name"

    # Now encrypt the .zip file
    echo "[*] Encrypting the archive."
    local enc_password=""
    while true; do
        enc_password=$(get_silent_input_string "Enter encryption password: ")
        echo
        local enc_confirm=$(get_silent_input_string "Confirm encryption password: ")
        echo
        if [ "$enc_password" != "$enc_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    local enc_archive="${backup_name}.enc"
    openssl enc -aes-256-cbc -salt -in "$backup_name" -out "$enc_archive" -k "$enc_password"
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Encryption failed."
        return
    fi
    echo "[*] Archive encrypted: $enc_archive"

    # Ask user for multiple directories in which to copy the .enc file
    echo
    echo "[*] Provide directories where you'd like to COPY the encrypted backup."
    echo "[*] Enter one directory path per line. Press ENTER on a blank line to finish."
    while true; do
        local user_dir
        user_dir=$(get_input_string "Directory to store the encrypted backup (blank to finish): ")
        if [ -z "$user_dir" ]; then
            echo "[*] Done storing the encrypted backup in specified directories."
            break
        fi

        user_dir=$(readlink -f "$user_dir")
        if [ ! -d "$user_dir" ]; then
            echo "[*] Directory '$user_dir' does not exist. Creating it..."
            sudo mkdir -p "$user_dir"
            if [ $? -ne 0 ]; then
                echo "[X] ERROR: Could not create directory '$user_dir'. Skipping..."
                continue
            fi
        fi

        # Copy the .enc file into that directory
        cp "$enc_archive" "$user_dir/"
        if [ $? -eq 0 ]; then
            echo "[*] Encrypted archive copied to $user_dir/"
        else
            echo "[X] ERROR: Failed to copy encrypted archive to $user_dir/"
        fi
    done

    # (Optional) If you do NOT want to keep the .enc file in the current dir,
    # you could uncomment below:
    # rm -f "$enc_archive"

    # Finally, remove the unencrypted .zip file
    rm -f "$backup_name"
    echo "[*] Cleanup complete. Only the encrypted archive remains (in the current directory unless removed)."
}


function unencrypt_backups {
    print_banner "Decrypt Backup"

    # Step 1: Ask for the base name of the encrypted archive
    # e.g., if the actual file is /etc/mybackup.zip.enc, the user just enters: /etc/mybackup
    echo "Enter the base name of the encrypted backup (do NOT include '.zip.enc'):"
    read -r enc_base_name
    if [ -z "$enc_base_name" ]; then
        echo "[X] No backup name provided. Aborting."
        return
    fi

    local enc_file="${enc_base_name}.zip.enc"
    if [ ! -f "$enc_file" ]; then
        echo "[X] ERROR: File '$enc_file' does not exist."
        return
    fi

    # Step 2: Decrypt the file into a temporary .zip
    local dec_zip="${enc_base_name}.zip"
    local max_attempts=3
    local attempt=1
    local success=0

    while [ $attempt -le $max_attempts ]; do
        echo
        read -r -s -p "Enter decryption password (Attempt $attempt of $max_attempts): " dec_password
        echo
        # Attempt the decryption
        openssl enc -d -aes-256-cbc -in "$enc_file" -out "$dec_zip" -k "$dec_password" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[X] ERROR: Decryption failed. Check your password."
            attempt=$((attempt+1))
        else
            success=1
            break
        fi
    done

    if [ $success -eq 0 ]; then
        echo "[X] Too many failed attempts. Aborting decryption."
        rm -f "$dec_zip" 2>/dev/null
        return
    fi

    echo "[*] Decrypted archive saved as '$dec_zip'."

    # Step 3: Prompt for a folder name to hold the extracted files (default: "wazuh")
    local folder_name
    read -r -p "Enter the folder name to place the entire extracted backup (default: wazuh): " folder_name
    if [ -z "$folder_name" ]; then
        folder_name="wazuh"
    fi

    # Step 4: Unzip quietly to a temporary extraction folder
    local temp_extraction_dir="$(mktemp -d)"
    unzip -q "$dec_zip" -d "$temp_extraction_dir"
    echo "[*] Decrypted archive extracted to temporary location: $temp_extraction_dir"

    # Step 5: Prompt for multiple directories to place the extracted data
    echo
    echo "[*] Provide directories where you'd like to store the fully extracted backup."
    echo "[*] Enter one directory path per line. Press ENTER on a blank line to finish."
    while true; do
        local user_dir
        user_dir=$(get_input_string "Directory to store extracted backup (blank to finish): ")
        if [ -z "$user_dir" ]; then
            echo "[*] Done placing the extracted backup."
            break
        fi

        user_dir=$(readlink -f "$user_dir")
        if [ ! -d "$user_dir" ]; then
            echo "[*] Directory '$user_dir' does not exist. Creating it..."
            sudo mkdir -p "$user_dir"
            if [ $? -ne 0 ]; then
                echo "[X] ERROR: Could not create directory '$user_dir'. Skipping..."
                continue
            fi
        fi

        # Make a subfolder named "$folder_name" in $user_dir
        local final_path="$user_dir/$folder_name"
        sudo mkdir -p "$final_path"
        if [ $? -ne 0 ]; then
            echo "[X] ERROR: Could not create subdirectory '$final_path'. Skipping..."
            continue
        fi

        # Copy the entire extracted contents into that directory
        sudo cp -R "$temp_extraction_dir/"* "$final_path/"
        echo "[*] Extracted backup copied into '$final_path/'"
    done

    # Step 6: Clean up temporary .zip and extraction folder
    rm -f "$dec_zip"
    rm -rf "$temp_extraction_dir"

    echo "[*] Decryption process completed."
}




# In Ansible mode, skip the backup section entirely.
function backups {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping backup section."
        return 0
    fi
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
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping Splunk installation."
        return 0
    fi
    indexer_ip=$(get_input_string "What is the Splunk forward server ip? ")
    wget $GITHUB_URL/splunk/splunk.sh --no-check-certificate
    chmod +x splunk.sh
    ./splunk.sh -f $indexer_ip
}

##################### ADDITIONAL WEB HARDENING FUNCTIONS #####################
function backup_databases {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping database backup."
        return 0
    fi
    print_banner "Hardening Databases"
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
    sudo service postgresql status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] PostgreSQL is active!"
    fi
}


#function secure_php_ini {
#    print_banner "Securing php.ini Files"
#    for ini in $(find / -name "php.ini" 2>/dev/null); do
#        echo "[+] Writing php.ini options to $ini..."
#        echo "disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo" >> "$ini"
#        echo "max_execution_time = 3" >> "$ini"
#        echo "register_globals = off" >> "$ini"
#        echo "magic_quotes_gpc = on" >> "$ini"
#        echo "allow_url_fopen = off" >> "$ini"
#        echo "allow_url_include = off" >> "$ini"
#        echo "display_errors = off" >> "$ini"
#        echo "short_open_tag = off" >> "$ini"
#        echo "session.cookie_httponly = 1" >> "$ini"
#        echo "session.use_only_cookies = 1" >> "$ini"
#        echo "session.cookie_secure = 1" >> "$ini"
#    done
#}

function secure_php_ini {
    print_banner "Securing php.ini Files"
    for ini in $(find / -name "php.ini" 2>/dev/null); do
        echo "[+] Writing php.ini options to $ini..."
        echo "disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo" >> "$ini"
        echo "max_execution_time = 3" >> "$ini"
        echo "register_globals = off" >> "$ini"

        # Only add magic_quotes_gpc if PHP still supports it
        if php --ri magic_quotes_gpc &>/dev/null; then
            echo "magic_quotes_gpc = on" >> "$ini"
        else
            echo "[*] Skipping magic_quotes_gpc: not supported by this PHP version"
        fi

        echo "allow_url_fopen = off" >> "$ini"
        echo "allow_url_include = off" >> "$ini"
        echo "display_errors = off" >> "$ini"
        echo "short_open_tag = off" >> "$ini"
        echo "session.cookie_httponly = 1" >> "$ini"
        echo "session.use_only_cookies = 1" >> "$ini"
        echo "session.cookie_secure = 1" >> "$ini"
    done
}



function configure_login_banner {
    print_banner "Configuring Login Banner"

    # Define the banner file and default banner text.
    local banner_file="/etc/issue.net"
    local default_banner="WARNING: UNAUTHORIZED ACCESS TO THIS NETWORK DEVICE IS PROHIBITED
You must have explicit, authorized permission to access or configure this device.
Unauthorized attempts to access and misuse of this system may result in prosecution.
All activities performed on this device are logged and monitored.

WARNING: This computer system is the property of Team ##.
This computer system, including all related equipment, networks, and network devices, is for authorized users only.
All activity on this network is being monitored and logged for lawful purposes, including verifying authorized use.

Data collected including logs will be used to investigate and prosecute unauthorized or improper access.
By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.

All employees must take reasonable steps to prevent unauthorized access to the system, including protecting passwords and other login information.
Employees are required to notify their administrators immediately of any known or suspected breach of security and to do their best to stop such a breach."

    # Write the banner text to /etc/issue.net.
    echo "$default_banner" | sudo tee "$banner_file" >/dev/null
    echo "[*] Login banner written to $banner_file."

    # Update SSH configuration to use the banner.
    local ssh_config="/etc/ssh/sshd_config"
    if [ -f "$ssh_config" ]; then
        # Remove any pre-existing Banner directives.
        sudo sed -i '/^Banner/d' "$ssh_config"
        # Append the new Banner line.
        echo "Banner $banner_file" | sudo tee -a "$ssh_config" >/dev/null
        echo "[*] Updated $ssh_config to use the login banner."
        # Restart the SSH service.
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl restart sshd
        else
            sudo service ssh restart
        fi
        echo "[*] SSH service restarted."
    else
        echo "[X] SSH configuration file not found at $ssh_config."
    fi
}


function secure_ssh {
    echo "################"
    echo "Securing SSH"
    echo "################"

    # Step 1: Check if SSH service is installed
    if command -v sshd &>/dev/null; then
        service_name="sshd"
    elif command -v ssh &>/dev/null; then
        service_name="ssh"
    else
        echo "[*] SSH service not found. Attempting to install..."

        # Attempt to install SSH based on the system's package manager
        if command -v apt-get &>/dev/null; then
            sudo apt-get update
            sudo apt-get install -y openssh-server
        elif command -v yum &>/dev/null; then
            sudo yum install -y openssh-server
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y openssh-server
        elif command -v zypper &>/dev/null; then
            sudo zypper install -y openssh
        else
            echo "[X] ERROR: Could not determine package manager to install SSH."
            return 1
        fi

        # Verify installation
        if command -v sshd &>/dev/null; then
            service_name="sshd"
        elif command -v ssh &>/dev/null; then
            service_name="ssh"
        else
            echo "[X] ERROR: Failed to install SSH service."
            return 1
        fi
    fi

    # Step 2: Check if SSH service is running
    if ! sudo systemctl is-active --quiet "$service_name"; then
        echo "[*] SSH service is not running. Attempting to start..."
        sudo systemctl start "$service_name"
        if ! sudo systemctl is-active --quiet "$service_name"; then
            echo "[X] ERROR: Failed to start SSH service."
            return 1
        fi
    fi

    # Step 3: Ensure SSH service is enabled to start on boot
    if ! sudo systemctl is-enabled --quiet "$service_name"; then
        echo "[*] Enabling SSH service to start on boot..."
        sudo systemctl enable "$service_name"
    fi

    # Step 4: Apply SSH hardening
    config_file="/etc/ssh/sshd_config"
    if [ ! -f "$config_file" ]; then
        echo "[X] ERROR: SSH configuration file not found: $config_file"
        return 1
    fi

    # Backup the original configuration file
    sudo cp "$config_file" "${config_file}.bak"
    echo "[*] Backed up $config_file to ${config_file}.bak"

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
        echo "[*] SSH hardening applied and $service_name restarted successfully."
    else
        echo "[X] ERROR: SSH configuration test failed. Restoring original configuration."
        sudo cp "${config_file}.bak" "$config_file"
        sudo systemctl restart "$service_name"
        return 1
    fi
}





#########################################################
# MODSECURITY SECTION !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#########################################################

# Determine the recommended ModSecurity Docker image tag based on the OS.
# The mappings support Ubuntu (14,16,18,20,22), CentOS (6,7,8,9), Debian (7–12),
# Fedora (25–35), and OpenSUSE (Leap/Tumbleweed). If no explicit mapping exists, it falls back to 'latest'.
function get_modsecurity_image {
    # Source OS info if available
    if [ -f /etc/os-release ]; then
        . /etc/os-release
    fi
    distro=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
    version_major=$(echo "$VERSION_ID" | cut -d. -f1)

    # Define mappings for each supported distro.
    declare -A modsec_map_ubuntu=( ["14"]="modsecurity/modsecurity:ubuntu14.04" ["16"]="modsecurity/modsecurity:ubuntu16.04" ["18"]="modsecurity/modsecurity:ubuntu18.04" ["20"]="modsecurity/modsecurity:ubuntu20.04" ["22"]="modsecurity/modsecurity:ubuntu22.04" )
    declare -A modsec_map_centos=( ["6"]="modsecurity/modsecurity:centos6" ["7"]="modsecurity/modsecurity:centos7" ["8"]="modsecurity/modsecurity:centos8" ["9"]="modsecurity/modsecurity:centos-stream9" )
    declare -A modsec_map_debian=( ["7"]="modsecurity/modsecurity:debian7" ["8"]="modsecurity/modsecurity:debian8" ["9"]="modsecurity/modsecurity:debian9" ["10"]="modsecurity/modsecurity:debian10" ["11"]="modsecurity/modsecurity:debian11" ["12"]="modsecurity/modsecurity:debian12" )
    declare -A modsec_map_fedora=( ["25"]="modsecurity/modsecurity:fedora25" ["26"]="modsecurity/modsecurity:fedora26" ["27"]="modsecurity/modsecurity:fedora27" ["28"]="modsecurity/modsecurity:fedora28" ["29"]="modsecurity/modsecurity:fedora29" ["30"]="modsecurity/modsecurity:fedora30" ["31"]="modsecurity/modsecurity:fedora31" ["35"]="modsecurity/modsecurity:fedora35" )

    # Check for OpenSUSE using PRETTY_NAME keywords.
    if [[ "$PRETTY_NAME" =~ Tumbleweed ]]; then
         echo "modsecurity/modsecurity:opensuse-tumbleweed"
         return 0
    elif [[ "$PRETTY_NAME" =~ Leap ]]; then
         echo "modsecurity/modsecurity:opensuse-leap"
         return 0
    fi

    local image=""
    case "$distro" in
      ubuntu)
         image=${modsec_map_ubuntu[$version_major]:-"modsecurity/modsecurity:latest"}
         ;;
      centos)
         image=${modsec_map_centos[$version_major]:-"modsecurity/modsecurity:latest"}
         ;;
      debian)
         image=${modsec_map_debian[$version_major]:-"modsecurity/modsecurity:latest"}
         ;;
      fedora)
         image=${modsec_map_fedora[$version_major]:-"modsecurity/modsecurity:latest"}
         ;;
      *)
         image="modsecurity/modsecurity:latest"
         ;;
    esac
    echo "$image"
}

# Generate a strict (maximum security) ModSecurity configuration file.
function generate_strict_modsec_conf {
    local conf_file="/tmp/modsecurity_strict.conf"
    print_banner "Generating Strict ModSecurity Configuration"
    sudo bash -c "cat > $conf_file" <<'EOF'
# Strict ModSecurity Configuration for Maximum Protection

SecRuleEngine On
SecDefaultAction "phase:1,deny,log,status:403"
SecRequestBodyAccess On
SecResponseBodyAccess Off

# Block file uploads by denying requests with file parameters.
SecRule ARGS_NAMES "@rx .*" "id:1000,phase:2,deny,status:403,msg:'File upload detected; blocking.'"

# Set temporary directories (ensure OS-level security on these paths)
SecTmpDir /tmp/modsec_tmp
SecDataDir /tmp/modsec_data

# Enable detailed audit logging.
SecAuditEngine On
SecAuditLogParts ABIJDEFHZ
SecAuditLog /var/log/modsecurity_audit.log

# Limit PCRE usage to mitigate complex regex attacks.
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000

# Restrict request and response body sizes.
SecResponseBodyLimit 524288
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
EOF
    echo "[*] Strict ModSecurity config generated at $conf_file"
    echo "$conf_file"
}

# Dockerized ModSecurity installation function.
# This function is run by default in both regular and Ansible executions.
# Dockerized ModSecurity installation function.
function install_modsecurity_docker {
    print_banner "Dockerized ModSecurity Installation (Strict Mode)"
    
    # Ensure Docker is installed (auto-install if necessary)
    if ! ensure_docker_installed; then
        echo "[X] Could not install Docker automatically. Aborting."
        return 1
    fi

    # Determine the recommended ModSecurity Docker image tag based on the OS.
    local default_image
    default_image=$(get_modsecurity_image)
    
    # In Ansible mode, use the recommended image automatically; otherwise allow user override.
    local image
    if [ "$ANSIBLE" == "true" ]; then
        image="$default_image"
        echo "[*] Ansible mode: Using recommended ModSecurity Docker image: $image"
    else
        read -p "Enter ModSecurity Docker image to use [default: $default_image]: " user_image
        if [ -n "$user_image" ]; then
            image="$user_image"
        else
            image="$default_image"
        fi
    fi

    # Generate the strict configuration file for ModSecurity.
    local modsec_conf
    modsec_conf=$(generate_strict_modsec_conf)

    echo "[INFO] Pulling Docker image: $image"
    sudo docker pull "$image"

    echo "[INFO] Running Dockerized ModSecurity container with strict configuration..."
    # Run the container with port mapping (adjust if needed) and mount the strict config file as read-only.
    sudo docker run -d --name dockerized_modsec -p 80:80 \
         -v "$modsec_conf":/etc/modsecurity/modsecurity.conf:ro \
         "$image"

    if sudo docker ps | grep -q dockerized_modsec; then
        echo "[*] Dockerized ModSecurity container 'dockerized_modsec' is running with strict settings."
        return 0
    else
        echo "[X] Dockerized ModSecurity container failed to start."
        return 1
    fi
}


###############################################################################
# Web Hardening Functions (Separate Options)
###############################################################################

# Disable directory browsing for Apache or Nginx.
# Disable directory browsing for Apache (idempotent, targets /var/www/html by default)
function disable_directory_browsing() {
    local webroot="${1:-/var/www/html}"
    local apache_conf="/etc/apache2/apache2.conf"

    if [ ! -f "$apache_conf" ]; then
        echo "[X] Apache config not found at $apache_conf"
        return 1
    fi

    echo "[*] Disabling directory browsing for Apache on $webroot..."

    # 1) Ensure AllowOverride All so .htaccess can work if you need it later
    sudo sed -i "/<Directory ${webroot//\//\\/}>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/" "$apache_conf"

    # 2) Add "-Indexes" only if it isn't already there
    sudo sed -i "/<Directory ${webroot//\//\\/}>/,/<\/Directory>/ {
        /Options/ {
            /-Indexes/! s/Options[[:space:]]\+/Options -Indexes /
        }
    }" "$apache_conf"

    # 3) Reload systemd manager configuration (in case a2enmod was run elsewhere)
    sudo systemctl daemon-reload

    # 4) Restart Apache once
    if ! sudo systemctl restart apache2; then
        echo "[X] Failed to restart Apache."
        return 1
    fi

    echo "[*] Directory browsing disabled (Options -Indexes) in $apache_conf"
}

# Set essential security headers in the .htaccess file (idempotent, wrapped in IfModule)
function set_security_headers() {
    local webroot="${1:-/var/www/html}"
    local htaccess="$webroot/.htaccess"

    echo "[*] Setting security headers in $htaccess..."

    # 1) Enable mod_headers if needed
    if ! apachectl -M 2>/dev/null | grep -q headers_module; then
        echo "[*] Enabling mod_headers..."
        sudo a2enmod headers
    fi

    # 2) Create .htaccess if it doesn't exist
    if [ ! -f "$htaccess" ]; then
        sudo touch "$htaccess"
        sudo chown root:www-data "$htaccess"
        sudo chmod 0644 "$htaccess"
    fi

    # 3) Append headers only once, wrapped in <IfModule>
    if ! grep -q "Header always set X-Frame-Options" "$htaccess"; then
        sudo bash -c "cat >> '$htaccess' << 'EOF'

<IfModule mod_headers.c>
    Header always set X-Frame-Options \"DENY\"
    Header always set X-Content-Type-Options \"nosniff\"
    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';\"
    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"
    Header always set Referrer-Policy \"no-referrer\"
</IfModule>
EOF"
        echo "[*] Security headers appended to $htaccess"
    else
        echo "[*] Security headers already present in $htaccess"
    fi

    # 4) Reload systemd manager configuration and restart Apache
    sudo systemctl daemon-reload
    sudo systemctl restart apache2
}

# Hide web server version information (for Apache or Nginx)
function hide_server_version() {
    local apache_conf="/etc/apache2/apache2.conf"
    local nginx_conf="/etc/nginx/nginx.conf"
    if [ -f "$apache_conf" ]; then
        echo "[*] Hiding Apache server version information..."
        sudo sed -i '/ServerTokens/d' "$apache_conf"
        sudo sed -i '/ServerSignature/d' "$apache_conf"
        echo "ServerTokens Prod" | sudo tee -a "$apache_conf" >/dev/null
        echo "ServerSignature Off" | sudo tee -a "$apache_conf" >/dev/null
        sudo systemctl restart apache2 2>/dev/null || echo "[X] Failed to restart Apache."
    elif [ -f "$nginx_conf" ]; then
        echo "[*] Hiding Nginx server version information..."
        sudo sed -i '/server_tokens/d' "$nginx_conf"
        echo "server_tokens off;" | sudo tee -a "$nginx_conf" >/dev/null
        sudo systemctl restart nginx 2>/dev/null || echo "[X] Failed to restart Nginx."
    else
        echo "[X] No supported web server configuration found."
    fi
}

# Restrict file access by allowing .htaccess overrides in Apache configuration.
function restrict_file_access() {
    local webroot="${1:-/var/www/html}"
    local apache_conf="/etc/apache2/apache2.conf"
    if [ -f "$apache_conf" ]; then
        echo "[*] Restricting file access for Apache (enabling .htaccess overrides)..."
        sudo sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' "$apache_conf"
        sudo systemctl restart apache2 2>/dev/null || echo "[X] Failed to restart Apache."
    else
        echo "[*] Apache configuration not found. Ensure .htaccess is used for file restrictions."
    fi
}

###############################################################################
# Web Hardening Menu
###############################################################################
function display_web_hardening_menu() {
    echo "-------------------------------------------------"
    echo "           Web Hardening Menu"
    echo "-------------------------------------------------"
    echo "1) Disable Directory Browsing"
    echo "2) Set Security Headers"
    echo "3) Hide Server Version Information"
    echo "4) Restrict File Access"
    echo "5) Apply ALL Web Hardening Measures"
    echo "q) Quit"
    echo "-------------------------------------------------"
}

function web_hardening_menu() {
    local choice
    while true; do
        display_web_hardening_menu
        read -p "Choose an option: " choice
        case "$choice" in
            1)
                disable_directory_browsing
                echo "[*] Directory browsing disabled (if applicable)."
                ;;
            2)
                set_security_headers
                echo "[*] Security headers set."
                ;;
            3)
                hide_server_version
                echo "[*] Server version info hidden."
                ;;
            4)
                restrict_file_access
                echo "[*] File access restrictions applied."
                ;;
            5)
                # Apply all measures one after the other.
                disable_directory_browsing
                set_security_headers
                hide_server_version
                restrict_file_access
                echo "[*] ALL web hardening measures applied."
                ;;
            q|Q)
                echo "[*] Exiting Web Hardening Menu."
                break
                ;;
            *)
                echo "[X] Invalid option. Please choose a valid option."
                ;;
        esac
        echo ""
    done
}


###############################################################################
# Function: configure_modsecurityd
###############################################################################
function configure_modsecurity {
    print_banner "Configuring ModSecurity (Block Mode) with a Single CRS Setup File"

    # 1) Ensure /etc/modsecurity directory exists
    if [ ! -d "/etc/modsecurity" ]; then
        sudo mkdir -p /etc/modsecurity
    fi

    # 2) Copy modsecurity.conf-recommended -> modsecurity.conf (set SecRuleEngine On)
    local recommended_conf="/etc/modsecurity/modsecurity.conf-recommended"
    local main_conf="/etc/modsecurity/modsecurity.conf"
    if [ -f "$recommended_conf" ]; then
        sudo cp "$recommended_conf" "$main_conf"
        sudo sed -i 's/^SecRuleEngine\s\+DetectionOnly/SecRuleEngine On/i' "$main_conf"
    else
        echo "[X] ERROR: $recommended_conf not found! Cannot configure ModSecurity."
        return 1
    fi

    # Fix ownership/permissions
    sudo chown root:root "$main_conf"
    sudo chmod 644 "$main_conf"

    # 3) Ensure the audit log file is in place
    if [ ! -d "/var/log/apache2" ]; then
        sudo mkdir -p /var/log/apache2
    fi
    local audit_log="/var/log/apache2/modsec_audit.log"
    if [ ! -f "$audit_log" ]; then
        sudo touch "$audit_log"
    fi
    sudo chown www-data:www-data "$audit_log"
    sudo chmod 640 "$audit_log"

    # 4) Download or confirm OWASP CRS
    #    (Adjust path if you prefer to store it in /etc/modsecurity/crs manually.)
    if [ ! -d "/usr/share/owasp-modsecurity-crs" ]; then
        echo "[*] OWASP CRS not found; cloning from GitHub..."
        if command -v git &>/dev/null; then
            sudo git clone https://github.com/coreruleset/coreruleset.git /usr/share/owasp-modsecurity-crs
            if [ $? -ne 0 ]; then
                echo "[X] ERROR: Failed to clone OWASP CRS."
                return 1
            fi
        else
            echo "[X] ERROR: git is not installed. Install git and try again."
            return 1
        fi
    else
        echo "[*] OWASP CRS found; you may pull updates if needed."
    fi

    # 5) If you keep your crs-setup.conf in /etc/modsecurity/crs/, ensure it’s there:
    if [ ! -d "/etc/modsecurity/crs" ]; then
        sudo mkdir -p /etc/modsecurity/crs
    fi
    # If you want to copy crs-setup.conf.example -> /etc/modsecurity/crs/crs-setup.conf
    if [ -f "/usr/share/owasp-modsecurity-crs/crs-setup.conf.example" ] && [ ! -f "/etc/modsecurity/crs/crs-setup.conf" ]; then
        sudo cp /usr/share/owasp-modsecurity-crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
    fi

    # 6) Reconfigure Apache’s security2.conf
    local sec_conf="/etc/apache2/mods-enabled/security2.conf"
    local backup_sec_conf="/etc/apache2/mods-enabled/security2.conf.bak"

    if [ -f "$sec_conf" ]; then
        # Backup first
        sudo cp "$sec_conf" "$backup_sec_conf"

        # Comment out any line referencing /usr/share/modsecurity-crs
        sudo sed -i 's|^\([ \t]*Include.*usr/share/modsecurity-crs.*\)|#\1|' "$sec_conf"

        # Optionally comment out "IncludeOptional" lines referencing modsecurity-crs:
        sudo sed -i 's|^\([ \t]*IncludeOptional.*usr/share/modsecurity-crs.*\)|#\1|' "$sec_conf"

        # Ensure our correct lines are appended:
        # (1) "Include /etc/modsecurity/crs/crs-setup.conf"
        grep -q "Include /etc/modsecurity/crs/crs-setup.conf" "$sec_conf" || \
            echo "Include /etc/modsecurity/crs/crs-setup.conf" | sudo tee -a "$sec_conf" >/dev/null

        # (2) "Include /usr/share/modsecurity-crs/rules/*.conf" (assuming you place rules here)
        grep -q "Include /usr/share/modsecurity-crs/rules/*.conf" "$sec_conf" || \
            echo "Include /usr/share/modsecurity-crs/rules/*.conf" | sudo tee -a "$sec_conf" >/dev/null
    else
        echo "[X] ERROR: $sec_conf not found. ModSecurity might not be enabled with 'a2enmod security2'."
        return 1
    fi

    # 7) Test config before restarting
    echo "[*] Testing Apache config..."
    if ! sudo apachectl -t; then
        echo "[X] ERROR: Apache config test failed. Reverting changes..."
        [ -f "$backup_sec_conf" ] && sudo mv "$backup_sec_conf" "$sec_conf"
        return 1
    fi

    # 8) If all good, restart
    echo "[*] Config OK. Restarting Apache..."
    if ! sudo systemctl restart apache2; then
        echo "[X] ERROR: Apache restart failed. Reverting security2.conf..."
        [ -f "$backup_sec_conf" ] && sudo mv "$backup_sec_conf" "$sec_conf"
        return 1
    fi

    echo "[*] ModSecurity configured in blocking mode; /etc/modsecurity/crs/crs-setup.conf is used."
    echo "[*] Any old /usr/share/... references have been commented out in security2.conf."

    # 9) Append 'SecRuleEngine On' in the Apache default site configuration file
    local default_site="/etc/apache2/sites-enabled/000-default.conf"
    if [ -f "$default_site" ]; then
        sudo sed -i '/CustomLog ${APACHE_LOG_DIR}\/access.log combined/ a \
        SecRuleEngine On
' "$default_site"
        echo "[*] Inserted 'SecRuleEngine On' into $default_site"
    else
        echo "[X] ERROR: $default_site not found!"
        return 1
    fi

    return 0
}







# Optionally, a function to fix the ModSecurity audit log file permissions.
function fix_modsecurity_audit_log() {
    local log_dir="/var/log/apache2"
    local audit_log="${log_dir}/modsec_audit.log"
    echo "[*] Fixing ModSecurity audit log file..."
    if [ ! -d "$log_dir" ]; then
        echo "[*] Creating log directory $log_dir..."
        sudo mkdir -p "$log_dir"
    fi
    if [ ! -f "$audit_log" ]; then
        echo "[*] Creating audit log file $audit_log..."
        sudo touch "$audit_log"
    fi
    sudo chown www-data:www-data "$audit_log"
    sudo chmod 640 "$audit_log"
    echo "[*] ModSecurity audit log file fixed: $audit_log"
}



########################################################################
# FUNCTION: install_modsecurity_manual
# ---------------------------------------------------------------------
# This function installs the "libapache2-mod-security2" package for
# Debian-based systems and then deploys a strict configuration for
# ModSecurity. It attempts to locate the recommended configuration file
# from common locations on Debian/Ubuntu systems. If the file cannot be
# found, it notifies the user to manually specify the path.
#
# It then modifies the configuration to set SecRuleEngine to "On" and
# finally restarts the Apache web server (checking for both “apache2”
# and “httpd” as service names) to load the changes.
#
# Note: For RHEL/CentOS or Alpine systems, this function is currently
# not implemented.
########################################################################
function install_modsecurity_manual {
    # Only for Debian/Ubuntu systems
    if ! command -v apt-get &>/dev/null; then
        echo "[X] Manual ModSecurity installation is only implemented for Debian-based systems."
        return 1
    fi

    echo "[*] Updating package list..."
    sudo apt-get update -qq
    echo "[*] Installing libapache2-mod-security2 and modsecurity-crs..."
    sudo apt-get install -y libapache2-mod-security2 modsecurity-crs

    # Locate the recommended configuration file
    local recommended_conf=""
    for candidate in /etc/modsecurity/modsecurity.conf-recommended \
                      /usr/share/doc/libapache2-mod-security2/examples/modsecurity.conf-recommended \
                      /usr/share/modsecurity-crs/modsecurity.conf-recommended; do
        if [ -f "$candidate" ]; then
            recommended_conf="$candidate"
            break
        fi
    done

    if [ -z "$recommended_conf" ]; then
        echo "[X] ERROR: Could not locate modsecurity.conf-recommended."
        echo "    Please locate it manually and copy it to /etc/modsecurity/modsecurity.conf"
        return 1
    fi

    echo "[*] Found recommended config at: $recommended_conf"
    sudo mkdir -p /etc/modsecurity
    echo "[*] Copying configuration to /etc/modsecurity/modsecurity.conf"
    sudo cp "$recommended_conf" /etc/modsecurity/modsecurity.conf
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Failed to copy the configuration file."
        return 1
    fi

    echo "[*] Enabling ModSecurity (setting SecRuleEngine to On)..."
    sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Failed to modify modsecurity configuration."
        return 1
    fi

    # Set proper ownership and permissions
    sudo chown root:root /etc/modsecurity/modsecurity.conf
    sudo chmod 644 /etc/modsecurity/modsecurity.conf

    # Ensure audit log exists with correct permissions
    local audit_log="/var/log/apache2/modsec_audit.log"
    sudo mkdir -p /var/log/apache2
    if [ ! -f "$audit_log" ]; then
        sudo touch "$audit_log"
    fi
    sudo chown www-data:www-data "$audit_log"
    sudo chmod 640 "$audit_log"

    # Enable the security2 module
    if command -v a2enmod &>/dev/null; then
        echo "[*] Enabling security2 module..."
        sudo a2enmod security2
    fi

    # Restart Apache (check for apache2 or httpd)
    if systemctl is-active apache2 &>/dev/null; then
        echo "[*] Restarting apache2..."
        sudo systemctl restart apache2
    elif systemctl is-active httpd &>/dev/null; then
        echo "[*] Restarting httpd..."
        sudo systemctl restart httpd
    else
        echo "[!] WARNING: Apache service not detected as active. Please restart manually."
    fi

    echo "[*] Manual ModSecurity installation completed successfully."
}





function remove_profiles {
    print_banner "Removing Profile Files"
    sudo mv /etc/prof{i,y}le.d /etc/profile.d.bak 2>/dev/null
    sudo mv /etc/prof{i,y}le /etc/profile.bak 2>/dev/null
    for f in ".profile" ".bashrc" ".bash_login"; do
        sudo find /home /root \( -path "/root/*" -o -path "/home/ccdcuser1/*" -o -path "/home/ccdcuser2/*" \) -prune -o -name "$f" -exec sudo rm {} \;
    done
}

function fix_pam {
    print_banner "Fixing PAM Configuration and Enforcing Password Policies"

    # Temporarily set iptables OUTPUT policy to ACCEPT.
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo $ipt -P OUTPUT ACCEPT

    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        echo "[*] Detected Debian/Ubuntu system; configuring PAM password policies."

        # Install libpam-pwquality if not already installed.
        sudo apt-get install -y libpam-pwquality

        # Update /etc/pam.d/common-password.
        local common_pass="/etc/pam.d/common-password"
        if [ -f "$common_pass" ]; then
            # Remove any existing password policy options.
            sudo sed -i 's/ minlen=[0-9]\+//g' "$common_pass"
            sudo sed -i 's/ retry=[0-9]\+//g' "$common_pass"
            sudo sed -i 's/ dcredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ ucredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ lcredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ ocredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ remember=[0-9]\+//g' "$common_pass"
            # Append the desired settings.
            sudo sed -i '/^password.*pam_unix\.so/ s/$/ minlen=12 retry=5 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 remember=5 sha512/' "$common_pass"
            echo "[*] Updated $common_pass with policy settings."
        else
            echo "[X] $common_pass not found."
        fi

        # Update /etc/login.defs for password aging.
        local login_defs="/etc/login.defs"
        if [ -f "$login_defs" ]; then
            sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' "$login_defs"
            sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   2/' "$login_defs"
            sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   10/' "$login_defs"
            echo "[*] Updated $login_defs with login definitions."
        else
            echo "[X] $login_defs not found."
        fi

    elif command -v yum >/dev/null; then
        if command -v authconfig >/dev/null; then
            sudo authconfig --updateall
            sudo yum -y reinstall pam
        else
            echo "[X] No authconfig found; cannot fix PAM on this system."
        fi
    elif command -v apk >/dev/null; then
        if [ -d /etc/pam.d ]; then
            sudo apk fix --purge linux-pam
            for file in $(find /etc/pam.d -name "*.apk-new" 2>/dev/null); do
                sudo mv "$file" "$(echo $file | sed 's/.apk-new//g')"
            done
        else
            echo "[X] PAM is not installed."
        fi
    elif command -v pacman >/dev/null; then
        if [ -n "$BACKUPDIR" ]; then
            sudo mv /etc/pam.d /etc/pam.d.backup
            sudo cp -R "$BACKUPDIR" /etc/pam.d
        else
            echo "[X] No backup directory provided for PAM configs."
        fi
        sudo pacman -S pam --noconfirm
    else
        echo "[X] Unknown OS; PAM configuration not fixed."
    fi

    # Restore iptables OUTPUT policy to DROP.
    sudo $ipt -P OUTPUT DROP
}


function search_ssn {
    print_banner "Searching for SSN Patterns"
    local rootdir="/home/"
    local ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'
    
    echo "[*] Scanning $rootdir for files containing SSN patterns..."
    local found_match=0

    # Iterate over files ending in .txt or .csv under the rootdir
    while IFS= read -r file; do
        if grep -E -q "$ssn_pattern" "$file"; then
            echo "[WARNING] SSN pattern found in file: $file"
            grep -E -Hn "$ssn_pattern" "$file"
            found_match=1
            # Pause to let the user review the match before continuing.
            read -p "Press ENTER to continue scanning..."
        fi
    done < <(find "$rootdir" -type f \( -iname "*.txt" -o -iname "*.csv" \) 2>/dev/null)
    
    if [ $found_match -eq 0 ]; then
        echo "[*] No SSN patterns found in $rootdir."
    else
        echo "[*] Finished scanning. Please review the above matches."
    fi
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
    sudo chmod 0755 /usr/bin/pkexec
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

function my_secure_sql_installation {
    print_banner "My Secure SQL Installation"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping mysql_secure_installation."
        return 0
    fi
    read -p "Would you like to run mysql_secure_installation? (y/N): " sql_choice
    if [[ "$sql_choice" =~ ^[Yy]$ ]]; then
         echo "[*] Running mysql_secure_installation..."
         sudo mysql_secure_installation
         # Continue onward regardless of the exit status
    else
         echo "[*] Skipping mysql_secure_installation."
    fi
    echo "[*] Continuing with web hardening..."
}



function manage_web_immutability_menu {
    # A list of “candidate” directories that you believe should normally be immutable.
    # Adjust this list to suit your environment. 
    # Typically these are config directories or static content directories.
    local default_web_dirs=(
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

    # An array to store discovered directories from default_web_dirs.
    local discovered_dirs=()

    # 1) Populate discovered_dirs if they actually exist on the system.
    for dir in "${default_web_dirs[@]}"; do
        if [ -d "$dir" ]; then
            discovered_dirs+=("$dir")
        fi
    done

    # -------------------------
    # Helper function to set +i
    function set_immutable {
        local path="$1"
        sudo chattr -R +i "$path" 2>/dev/null && \
            echo "[*] Immutable set recursively on: $path" || \
            echo "[!] Failed to set immutable on: $path"
    }

    # Helper function to set -i
    function remove_immutable {
        local path="$1"
        sudo chattr -R -i "$path" 2>/dev/null && \
            echo "[*] Immutable removed (recursively) from: $path" || \
            echo "[!] Failed to remove immutable on: $path"
    }
    # -------------------------

    # Sub-functions for each menu option

    # Option 1: Detect & set discovered directories immutable
    function detect_and_set_immutable {
        # Show what we found
        echo "[*] The following directories have been detected:"
        for d in "${discovered_dirs[@]}"; do
            echo "    $d"
        done

        if [ ${#discovered_dirs[@]} -eq 0 ]; then
            echo "[!] No default directories detected."
            return
        fi

        read -p "Would you like to set ALL of these directories to immutable (recursively)? (y/N): " imm_choice
        if [[ "$imm_choice" =~ ^[Yy]$ ]]; then
            # Set each discovered directory to +i
            for d in "${discovered_dirs[@]}"; do
                set_immutable "$d"
            done
        else
            # If user says No, let them specify manually
            echo "[*] Enter the directories you'd like to set as immutable (one per line)."
            echo "    Press ENTER on a blank line to finish."
            while true; do
                local custom_dir
                read -r -p "Directory (blank to finish): " custom_dir
                if [ -z "$custom_dir" ]; then
                    break
                fi
                if [ -d "$custom_dir" ]; then
                    set_immutable "$custom_dir"
                else
                    echo "[X] Directory '$custom_dir' not found or invalid."
                fi
            done
        fi
    }

    # Option 2: Reverse discovered immutability
    function reverse_discovered_immutable {
        if [ ${#discovered_dirs[@]} -eq 0 ]; then
            echo "[!] No discovered directories found to un-set."
            return
        fi
        echo "[*] Removing immutability for discovered directories..."
        for d in "${discovered_dirs[@]}"; do
            remove_immutable "$d"
        done
    }

    # Option 3: Specify custom dirs to set +i
    function custom_set_immutable {
        echo "[*] Enter the directories you'd like to set as immutable (one per line)."
        echo "    Press ENTER on a blank line to finish."
        while true; do
            local custom_dir
            read -r -p "Directory to set immutable (blank to finish): " custom_dir
            if [ -z "$custom_dir" ]; then
                break
            fi
            if [ -d "$custom_dir" ]; then
                set_immutable "$custom_dir"
            else
                echo "[X] '$custom_dir' not found or not a directory."
            fi
        done
    }

    # Option 4: Specify custom dirs to remove immutability
    function custom_remove_immutable {
        echo "[*] Enter the directories you'd like to remove immutability from (one per line)."
        echo "    Press ENTER on a blank line to finish."
        while true; do
            local custom_dir
            read -r -p "Directory to remove immutability (blank to finish): " custom_dir
            if [ -z "$custom_dir" ]; then
                break
            fi
            if [ -d "$custom_dir" ]; then
                remove_immutable "$custom_dir"
            else
                echo "[X] '$custom_dir' not found or not a directory."
            fi
        done
    }

    # The actual sub-menu loop
    while true; do
        echo
        echo "========== WEB DIRECTORY IMMUTABILITY MENU =========="
        echo "1) Detect & Set Discovered Directories Immutable"
        echo "2) Reverse Immutability for Discovered Directories"
        echo "3) Specify Custom Directories to Set Immutable"
        echo "4) Specify Custom Directories to Remove Immutability"
        echo "5) Return to Web Hardening Menu"
        read -p "Enter your choice [1-5]: " sub_choice
        echo

        case "$sub_choice" in
            1) detect_and_set_immutable ;;
            2) reverse_discovered_immutable ;;
            3) custom_set_immutable ;;
            4) custom_remove_immutable ;;
            5) echo "[*] Returning to the previous menu..."; break ;;
            *) echo "[X] Invalid option. Please choose 1-5." ;;
        esac
    done
}

###########################
# FUNCTION: handle_non_immutable_dirs
#
# Creates a small sub-menu to either:
#   1) Backup (rename) directories that cannot be made immutable -> .bak
#   2) Restore (rename) them back to original
#
# You can call this function as a separate menu item, for example:
#
#   handle_non_immutable_dirs
#
###########################
function handle_non_immutable_dirs {
    # These are the paths that failed or are known to fail with chattr
    # or for which "Operation not supported/permitted" was reported.
    # Adjust as needed for your environment.
    local non_immutable_paths=(
        "/etc/apache2/conf-enabled"
        "/etc/apache2/sites-enabled"
        "/etc/apache2/mods-enabled"
        "/etc/mysql"
        "/var/www/html/prestashop/vendor/smarty/smarty/libs/sysplugins"
        "/var/www/html/prestashop/vendor/symfony/symfony/src/Symfony/Component/Intl/Resources/data/currencies"
        "/var/www/html/prestashop/vendor/tecnickcom/tcpdf/fonts"
        "/var/www/html/prestashop/vendor/ezyang/htmlpurifier/library/HTMLPurifier/ConfigSchema/schema"
        "/var/www/html/prestashop/modules/klaviyoopsautomation/vendor/giggsey/libphonenumber-for-php/src/data"
        "/var/www/html/prestashop/modules/klaviyoopsautomation/vendor/giggsey/locale/data"
        "/var/www/html/prestashop/modules/ps_shoppingcart/vendor/svix/go-internal/openapi"
        "/var/www/html/prestashop/modules/ps_facebook/vendor/facebook/php-business-sdk/examples"
        "/var/www/html/prestashop/modules/ps_facebook/vendor/facebook/php-business-sdk/src/FacebookAds/Object"
        "/var/www/html/prestashop/modules/ps_checkout/vendor/giggsey/libphonenumber-for-php/src/data"
        "/var/www/html/prestashop/modules/ps_checkout/vendor/giggsey/locale/data"
        "/var/www/html/prestashop/modules/ps_gamification/views/img/badges"
        "/var/www/html/prestashop/modules/ps_xmarketintegration/vendor/giggsey/libphonenumber-for-php/src/data"
        "/var/www/html/prestashop/modules/ps_xmarketintegration/vendor/giggsey/locale/data"
        "/var/www/html/prestashop/var/cache/prod/ContainerDuzmaSE"
        "/var/www/html/prestashop/var/cache/prod/ContainerBSdrPE"
        "/var/www/html/prestashop/translations/default"
        "/var/www/html/prestashop/translations/en-US"
        "/var/www/html/prestashop/themes/classic/assets/fonts"
        "/var/www/html/prestashop/themes/new-theme/public"
        "/var/www/html/prestashop/img/su"
        "/var/www/html/prestashop/img/l"
        "/var/www/html/prestashop/img/c"
        "/var/www/html/prestashop/img/p"
        "/var/www/html/prestashop/localization/CLDR/core/common/main"
    )

    print_banner "Manage Non-Immutable Directories"

    # Simple sub-menu
    while true; do
        echo "These directories/files cannot be made immutable."
        echo "1) Backup (rename) them with a .bak extension"
        echo "2) Restore them from .bak to original"
        echo "3) Return to previous menu"
        read -rp "Enter your choice [1-3]: " sub_choice
        echo

        case "$sub_choice" in
            1)
                # Backup step: rename each path -> path.bak
                echo "[*] Backing up directories/files (renaming -> .bak)..."
                for path in "${non_immutable_paths[@]}"; do
                    if [ -e "$path" ] && [ ! -e "${path}.bak" ]; then
                        sudo mv "$path" "${path}.bak"
                        echo "  Renamed: $path -> ${path}.bak"
                    else
                        # Either $path doesn't exist or $path.bak already exists
                        echo "  Skipped: $path"
                    fi
                done
                echo "[*] Backup (rename) complete."
                ;;
            2)
                # Restore step: rename each .bak -> original
                echo "[*] Restoring directories/files from .bak -> original..."
                for path in "${non_immutable_paths[@]}"; do
                    if [ -e "${path}.bak" ] && [ ! -e "$path" ]; then
                        sudo mv "${path}.bak" "$path"
                        echo "  Restored: ${path}.bak -> $path"
                    else
                        # Either ${path}.bak doesn't exist or original already exists
                        echo "  Skipped: $path"
                    fi
                done
                echo "[*] Restore complete."
                ;;
            3)
                echo "[*] Returning to previous menu."
                break
                ;;
            *)
                echo "[X] Invalid option."
                ;;
        esac

        echo
    done
}


function kill_other_sessions {
    # Get the current TTY device (e.g., /dev/pts/0)
    local current_tty=$(tty 2>/dev/null)
    
    # Check if TTY is valid; exit if not
    if [ -z "$current_tty" ]; then
        echo "[X] Error: Could not determine current TTY" >&2
        return 1
    fi
    
    # Get the current user (should be root since script requires root privileges)
    local current_user=$(whoami)
    
    # Normalize TTY name by removing '/dev/' prefix to match 'who' output (e.g., pts/0)
    local current_tty_short=$(echo "$current_tty" | sed 's|^/dev/||')
    
    # Get list of other TTYs for the current user, excluding the current TTY
    local other_ttys=$(who | awk -v user="$current_user" -v tty="$current_tty_short" '$1 == user && $2 != tty {print $2}')
    
    # If no other sessions exist, inform and exit
    if [ -z "$other_ttys" ]; then
        echo "[*] No other sessions found for user $current_user"
        return 0
    fi
    
    # Iterate through other TTYs and terminate their processes
    for tty in $other_ttys; do
        echo "[*] Killing session on /dev/$tty"
        # Get PIDs of processes attached to this TTY
        local pids=$(ps -t "$tty" -o pid= 2>/dev/null)
        for pid in $pids; do
            # Kill each process, suppressing errors if PID no longer exists
            kill "$pid" 2>/dev/null
        done
    done
    
    return 0
}





function defend_against_forkbomb {
    print_banner "Defending Against Fork Bombing"
    # Create group 'fork' if it does not exist.
    if ! getent group fork >/dev/null; then
        sudo groupadd fork
        echo "[*] Group 'fork' created."
    else
        echo "[*] Group 'fork' already exists."
    fi

    # Get list of users with terminal access (shell in /bin/ or /usr/bin/)
    user_list=$(awk -F: '$1 != "root" && $7 ~ /^\/(bin|usr\/bin)\// { print $1 }' /etc/passwd)
    if [ -n "$user_list" ]; then
        for user in $user_list; do
            sudo usermod -a -G fork "$user"
            echo "[*] User $user added to group 'fork'."
        done
    else
        echo "[*] No applicable users found for fork protection."
    fi

    # Backup current limits.conf
    sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak

    # Add process limits if not already present.
    if ! grep -q "^root hard" /etc/security/limits.conf; then
        echo "root hard nproc 1000" | sudo tee -a /etc/security/limits.conf >/dev/null
        echo "[*] Added 'root hard nproc 1000' to limits.conf."
    else
        echo "[*] Root nproc limit already set."
    fi

    if ! grep -q "^@fork hard" /etc/security/limits.conf; then
        echo "@fork hard nproc 300" | sudo tee -a /etc/security/limits.conf >/dev/null
        echo "[*] Added '@fork hard nproc 300' to limits.conf."
    else
        echo "[*] Fork group nproc limit already set."
    fi
}

function check_service_integrity {
    print_banner "Checking Service Binary Integrity"
    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        # Ensure debsums is installed.
        if ! command -v debsums &>/dev/null; then
            echo "[*] Installing debsums..."
            sudo apt-get install -y debsums
        fi
        local packages=("apache2" "openssh-server" "mysql-server" "postfix" "nginx")
        for pkg in "${packages[@]}"; do
            if dpkg -s "$pkg" &>/dev/null; then
                echo "[*] Checking integrity for package: $pkg"
                # Run debsums and filter lines indicating failures.
                results=$(sudo debsums "$pkg" 2>/dev/null | grep "FAILED")
                if [ -n "$results" ]; then
                    echo "[WARNING] Integrity check FAILED for $pkg:"
                    echo "$results"
                else
                    echo "[*] $pkg passed integrity check."
                fi
            else
                echo "[*] Package $pkg is not installed; skipping."
            fi
        done
    elif grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        local packages=("httpd" "openssh" "mariadb-server" "postfix" "nginx")
        for pkg in "${packages[@]}"; do
            if rpm -q "$pkg" &>/dev/null; then
                echo "[*] Checking integrity for package: $pkg"
                results=$(rpm -V "$pkg")
                if [ -n "$results" ]; then
                    echo "[WARNING] Integrity check FAILED for $pkg:"
                    echo "$results"
                else
                    echo "[*] $pkg passed integrity check."
                fi
            else
                echo "[*] Package $pkg is not installed; skipping."
            fi
        done
    else
        echo "[X] Unsupported OS for native binary integrity checking."
    fi
}

function disable_phpmyadmin {
    print_banner "Disabling phpMyAdmin"

    # List of common phpMyAdmin directories
    local phpmyadmin_dirs=( "/etc/phpmyadmin" "/usr/share/phpmyadmin" "/var/www/phpmyadmin" "/var/www/html/phpmyadmin" "/usr/local/phpmyadmin" )
    for loc in "${phpmyadmin_dirs[@]}"; do
        if [ -d "$loc" ]; then
            sudo mv "$loc" "${loc}_disabled"
            echo "[*] Renamed directory $loc to ${loc}_disabled"
        fi
    done

    # List of common phpMyAdmin configuration files
    local phpmyadmin_configs=( "/etc/httpd/conf.d/phpMyAdmin.conf" "/etc/apache2/conf-enabled/phpmyadmin.conf" )
    for file in "${phpmyadmin_configs[@]}"; do
        if [ -f "$file" ]; then
            sudo mv "$file" "${file}.disabled"
            echo "[*] Renamed configuration file $file to ${file}.disabled"
        fi
    done
}

function fix_web_browser() {
    # Use provided directory (if any); default to Firefox's config directory
    local browser_dir="${1:-$HOME/.mozilla}"

    echo "=== Fixing Home Directory Permissions ==="
    # Reset home directory ownership and secure permissions.
    sudo chown -R "$(whoami):$(id -gn)" "$HOME"
    sudo chmod 700 "$HOME"
    echo "Home directory attributes:"
    lsattr -d "$HOME"

    if [ -d "$browser_dir" ]; then
        echo "=== Fixing Browser Configuration Directory: $browser_dir ==="
        echo "Current attributes for $browser_dir:"
        lsattr -d "$browser_dir"
        
        echo "Removing immutable flag from home directory..."
        sudo chattr -i "$HOME"
        echo "Removing immutable flag recursively from $browser_dir..."
        sudo chattr -R -i "$browser_dir"

        # Back up the existing browser configuration directory with a timestamp.
        local backup_dir="${browser_dir}_backup_$(date +%s)"
        echo "Backing up $browser_dir to $backup_dir..."
        mv "$browser_dir" "$backup_dir"

        echo "Creating new configuration directory at $browser_dir..."
        mkdir -p "$browser_dir"
    else
        echo "Browser configuration directory ($browser_dir) not found. Skipping browser-specific fixes."
    fi

    echo "=== Done ==="
}


function configure_apache_htaccess {
    print_banner "Configuring Apache .htaccess"

    # 1) Figure out where your actual web‑app lives
    if [ -d "/var/www/html/web" ]; then
        webroot="/var/www/html/web"
    elif [ -d "/var/www/html" ]; then
        webroot="/var/www/html"
    elif [ -d "/var/www" ]; then
        webroot="/var/www"
    else
        echo "[X] No Apache web root found."
        return 1
    fi

    htfile="${webroot}/.htaccess"
    echo "[*] Ensuring $htfile exists…"
    sudo touch "$htfile"
    sudo chown root:www-data "$htfile"
    sudo chmod 0644 "$htfile"

    # 2) Only inject our security defaults if we haven't already
    if sudo grep -q "### CCDC HARDENING START" "$htfile"; then
        echo "[*] $htfile already contains hardening markers; skipping."
        return 0
    fi

    # 3) Make sure mod_rewrite is enabled
    if command -v a2enmod &>/dev/null; then
        sudo a2enmod rewrite
    fi

    # 4) Prepend our defaults
    sudo bash -c "cat <<'EOF' | cat - $htfile > /tmp/ht.$$ && mv /tmp/ht.$$ $htfile
### CCDC HARDENING START
# Disable directory listings
# (only valid if AllowOverride includes 'Options')
Options -Indexes

# Simple bad‑bot blocking
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP_USER_AGENT} (dirbuster|nikto|sqlmap|nessus|openvas|jbrofuzz|w3af\.sourceforge\.net|libwhisker|webshag|fimap) [NC]
  RewriteRule .* - [F,L]
</IfModule>
### CCDC HARDENING END

EOF"

    echo "[*] Wrote hardened .htaccess to $htfile"
    echo "[*] You may need to set 'AllowOverride All' in your <Directory> block for $webroot in your Apache vhost."
}

function run_rkhunter {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping Rootkit Hunter scan."
        return 0
    fi
    read -p "Would you like to run rkhunter (Rootkit Hunter) scan? (y/N): " run_rkh
    if [[ "$run_rkh" == "y" || "$run_rkh" == "Y" ]]; then
        print_banner "Running Rootkit Hunter"
        # Update package list and install rkhunter.
        sudo apt update
        sudo apt install -y rkhunter
        echo "[*] Running rkhunter scan. Please review the output for warnings."
        sudo rkhunter --check
    else
        echo "[*] Skipping rkhunter scan as per user decision."
    fi
}


function harden_web {
    print_banner "Web Hardening Initiated"
    
    # 1. Install ModSecurity manually by default.
    install_modsecurity_manual

    # 2. Backup databases
    backup_databases

    # 3. Secure php.ini files (using your original directive appending)
    secure_php_ini

    # 4. Configure Apache .htaccess for basic web protection.
    configure_apache_htaccess

    # 5. Run MySQL secure installation and manage web directory immutability
    #    only in interactive mode (non-Ansible) so that if the user chooses not
    #    to run mysql_secure_installation, the process still continues.
    if [ "$ANSIBLE" != "true" ]; then
         my_secure_sql_installation
         manage_web_immutability_menu
    else
         echo "[*] Ansible mode: Skipping mysql_secure_installation and web directory immutability."
    fi

    echo "[*] Web hardening process completed."
}







##################### ADVANCED HARDENING FUNCTIONS #####################
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

function disable_unnecessary_services {
    print_banner "Disabling Unnecessary Services"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping disabling services."
        return 0
    fi
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

function setup_firewall_maintenance_cronjob_iptables {
    print_banner "Setting Up iptables Maintenance Cronjob"
    local script_file="/usr/local/sbin/firewall_maintain.sh"
    sudo bash -c "cat > $script_file" <<'EOF'
#!/bin/bash
open_ports=$(ss -lnt | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -nu)
for port in $open_ports; do
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

function setup_nat_clear_cronjob {
    print_banner "Setting Up NAT Table Clear Cronjob"
    cron_file="/etc/cron.d/clear_nat_table"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables -t nat -F
EOF
    echo "[*] NAT table clear cron job created."
}



function setup_service_restart_cronjob {
    print_banner "Setting Up Service Restart Cronjob"
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
    if [ "$ANSIBLE" != "true" ]; then
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
    else
        echo "[*] Ansible mode: Skipping additional service restart configuration."
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

#==============================================================================
# FUNCTION: advanced_hardening
# DESCRIPTION:
#   Presents a menu of advanced hardening & automation tasks, now including
#   our new toggle_permissions option.
#==============================================================================
function advanced_hardening {
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping advanced hardening prompts."
         return 0
    fi

    local adv_choice
    while true; do
        print_banner "Advanced Hardening & Automation"
        echo " 1) Run Full Advanced Hardening Process"
        echo " 2) Run rkhunter scan"
        echo " 3) Check Service Integrity"
        echo " 4) Fix Web Browser Permissions"
        echo " 5) Configure SELinux or AppArmor"
        echo " 6) Disable SSHD/Cockpit services"
        echo " 7) Set up iptables persistence cronjob (dev)"
        echo " 8) Set up firewall maintenance cronjob (dev)"
        echo " 9) Set up NAT table clear cronjob (dev)"
        echo "10) Set up service restart cronjob (dev)"
        echo "11) Reset Advanced Hardening Configurations (dev)"
        echo "12) Restrict shell interpreter permissions (apply ACLs)"
        echo "13) Revert shell interpreter permissions (remove ACLs)"
        echo "14) Kill other sessions"
        echo "15) Exit Advanced Hardening Menu"
        read -p "Enter your choice [1-15]: " adv_choice
        echo

        case $adv_choice in
            1)  run_full_advanced_hardening    ;;
            2)  run_rkhunter                   ;;
            3)  check_service_integrity        ;;
            4)  fix_web_browser                ;;
            5)  configure_security_modules     ;;
            6)  disable_unnecessary_services   ;;
            7)  setup_iptables_cronjob         ;;
            8)  setup_firewall_maintenance_cronjob ;;
            9)  setup_nat_clear_cronjob        ;;
           10)  setup_service_restart_cronjob ;;
           11)  reset_advanced_hardening       ;;
           12)  toggle_permissions apply       ;;
           13)  toggle_permissions revert      ;;
           14)  kill_other_sessions            ;;
           15)  echo "[*] Exiting advanced hardening menu."; break ;;
            *)  echo "[X] Invalid option."       ;;
        esac
        echo
    done
}



##################### WEB HARDENING MENU FUNCTION #####################
function show_web_hardening_menu {
    print_banner "Web Hardening Menu"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Running full web hardening non-interactively."
        harden_web
        disable_phpmyadmin
        return 0
    fi

    echo "1) Run Full Web Hardening Process"
    echo "2) Install ModSecurity (Manual)"
    echo "3) Install ModSecurity (Dockerized)"
    echo "4) Backup Databases"
    echo "5) Secure php.ini Files"
    echo "6) Configure Apache .htaccess"
    echo "7) Run MySQL Secure Installation"
    echo "8) Manage Web Directory Immutability"
    echo "9) Disable phpMyAdmin"
    echo "10) Configure ModSecurity (block mode with OWASP CRS)"
    echo "11) Advanced Web Hardening Menu"
    echo "12) Exit Web Hardening Menu"
    read -p "Enter your choice [1-12]: " web_menu_choice
    echo

    case $web_menu_choice in
        1)
            print_banner "Web Hardening Initiated"
            install_modsecurity_manual
            backup_databases
            secure_php_ini
            kill_other_sessions
            configure_apache_htaccess
            my_secure_sql_installation
            disable_phpmyadmin
            kill_other_sessions
            configure_modsecurity
            web_hardening_menu
            manage_web_immutability_menu
            kill_other_sessions
            ;;
        2)
            print_banner "Installing Manual ModSecurity"
            install_modsecurity_manual
            ;;
        3)
            print_banner "Installing Dockerized ModSecurity"
            install_modsecurity_docker
            ;;
        4)
            print_banner "Backing Up Databases"
            backup_databases
            ;;
        5)
            print_banner "Securing php.ini Files"
            secure_php_ini
            ;;
        6)
            print_banner "Configuring Apache .htaccess"
            configure_apache_htaccess
            ;;
        7)
            print_banner "Running MySQL Secure Installation"
            my_secure_sql_installation
            ;;
        8)
            print_banner "Managing Web Directory Immutability"
            manage_web_immutability_menu
            ;;
        9)
            print_banner "Disabling phpMyAdmin"
            disable_phpmyadmin
            ;;
        10)
            print_banner "Configuring ModSecurity (Block Mode + OWASP CRS)"
            configure_modsecurity
            ;;
        11)
            print_banner "Advanced Web Hardening Configurations"
            web_hardening_menu
            ;;
        12)
            echo "[*] Exiting Web Hardening Menu"
            ;;
        *)
            echo "[X] Invalid option."
            ;;
    esac
}







# --------------------------------------------------------------------
# FUNCTION: show_menu
# --------------------------------------------------------------------
function show_menu {
    print_banner "Hardening Script Menu"
    echo "1) Full Hardening Process (Run all)"
    echo "2) User Management"
    echo "3) Firewall Configuration"
    echo "4) Backup"
    echo "5) Splunk Installation"
    echo "6) SSH Hardening"
    echo "7) PAM/Profile Fixes & System Config"
    echo "8) Setup Proxy & Install CA Certs"
    echo "9) Web Hardening"
    echo "10) Advanced Hardening"
    echo "11) Exit"
    echo
    read -p "Enter your choice [1-11]: " menu_choice
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
            # New menu item for Proxy & CA Certs setup.
            # You may place the proxy/CA certificate functions here. For example, if you have
            # a function called setup_proxy_and_ca, it would be called like:
            setup_proxy_and_ca
            ;;
        9)
            show_web_hardening_menu
            ;;
        10)
            advanced_hardening
            ;;
        11)
            echo "Exiting..."; exit 0
            ;;
        *)
            echo "Invalid option. Exiting."; exit 1
            ;;
    esac
}


##################### MAIN FUNCTION #####################
function main {
    kill_other_sessions
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of full hardening process"
    detect_system_info
    install_prereqs
    kill_other_sessions
    create_ccdc_users
    change_passwords
    kill_other_sessions
    disable_users
    remove_sudoers
    audit_running_services
    kill_other_sessions
    disable_other_firewalls
    firewall_configuration_menu
    kill_other_sessions
    if [ "$ANSIBLE" != "true" ]; then
         backups
    else
         echo "[*] Ansible mode: Skipping backup section."
    fi
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping Splunk installation."
    else
         setup_splunk
    fi
    secure_ssh
    remove_profiles
    fix_pam
    kill_other_sessions
    search_ssn
    remove_unused_packages
    patch_vulnerabilities
    kill_other_sessions
    check_permissions
    sysctl_config
    configure_login_banner
    kill_other_sessions
    defend_against_forkbomb

    # Disable phpMyAdmin by default for both Ansible and non-interactive execution.
    disable_phpmyadmin

    if [ "$ANSIBLE" != "true" ]; then
         web_choice=$(get_input_string "Would you like to perform web hardening? (y/N): ")
         if [ "$web_choice" == "y" ]; then
             show_web_hardening_menu
         fi
         adv_choice=$(get_input_string "Would you like to perform advanced hardening? (y/N): ")
         if [ "$adv_choice" == "y" ]; then
             advanced_hardening
         fi
    else
         echo "[*] Ansible mode: Running web hardening non-interactively."
         harden_web
         echo "[*] Ansible mode: Skipping advanced hardening prompts."
    fi
    run_rkhunter
    check_service_integrity
    kill_other_sessions
    echo "[*] End of full hardening process"
    echo "[*] Script log can be viewed at $LOG"
    echo "[*][WARNING] FORWARD chain is set to DROP. If this box is a router or network device, please run 'sudo iptables -P FORWARD ALLOW'."
    echo "[*] ***Please install system updates now***"
}





##################### ARGUMENT PARSING + LOGGING SETUP #####################
for arg in "$@"; do
    case "$arg" in
        --debug )
            echo "[*] Debug mode enabled"
            debug="true"
            ;;
        -ansible )
            echo "[*] Ansible mode enabled: Skipping interactive prompts."
            ANSIBLE="true"
            ;;
    esac
done

LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    sudo mkdir -p "$LOG_PATH"
    sudo chown root:root "$LOG_PATH"
    sudo chmod 750 "$LOG_PATH"
fi

##################### MAIN EXECUTION #####################
if [ "$ANSIBLE" == "true" ]; then
    main
else
    show_menu
fi
