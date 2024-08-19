#!/bin/bash
# Usage: ./harden.sh [option]

###################### GLOBALS ######################
DEBUG_LOG='/var/log/ccdc/setup/firewall.log'
GITHUB_URL='https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main'
pm=""
sudo_group=""
ccdc_users=( "ccdcuser1" "ccdcuser2" )
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

function get_user_input {
    local input_list=()

    while [ "$continue" != "false" ]; do
        read -r -p "Enter input: (one entry per line; hit enter to continue): " userInput
        if [[ "$userInput" == "" ]]; then
            continue="false"
        else
            input_list+=("$userInput")
        fi
    done

    # Return the list by printing it
    # Note: Bash functions can't return arrays directly, but we can print them
    echo "${input_list[@]}"
}

function detect_system_info {
    print_banner "Detecting system info"

    echo "[*] Detecting package manager"
    if command -v apt &>/dev/null; then
        echo "[*] apt detected (Debian-based OS)"
        pm="apt"
        return
    fi

    if command -v dnf &>/dev/null; then
        echo "[*] dnf detected (Fedora-based OS)"
        pm="dnf"
        return
    fi

    if command -v yum &>/dev/null; then
        echo "[*] yum detected (RHEL-based OS)"
        pm="yum"
        return
    fi

    if command -v zypper &>/dev/null; then
        echo "[*] zypper detected (OpenSUSE-based OS)"
        pm="zypper"
        return
    fi

    echo "[*] Detecting sudo (admin) group"

    groups=$(compgen -g)
    if echo "$groups" | grep -q '^sudo$'; then
        echo '[*] sudo group detected'
        sudo_group='sudo'
    elif echo "$groups" | grep -q '^wheel$'; then
        echo '[*] wheel group detected'
        sudo_group='wheel'
    fi
}

function install_prereqs {
    print_banner "Installing prerequisites"
    sudo $pm install zip unzip wget curl
}

function change_passwords {
    print_banner "Changing user passwords"
    echo "[*] Enter the new password for all users."
    while true; do
        password=""
        confirm_password=""

        # Ask for password
        read -p "Enter password: " -s password
        echo

        # Confirm password
        read -p "Confirm password: " -s confirm_password
        echo

        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    local user_list

    # Get a list of all user accounts (excluding system users)
    if ! user_list=$(getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}'); then
        echo "[X] ERROR: Unable to retrieve user list."
        exit 1
    fi

    # Loop through each user and change their password
    for user in $user_list; do
        if ! echo "$user:$new_password" | chpasswd; then
            echo "[X] ERROR: Failed to change password for $user."
        else
            echo "[*] Password for $user has been changed."
        fi
    done
}

function create_ccdc_users {
    print_banner "Creating ccdc users"
    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
            echo "[*] $user already exists. Skipping..."
        else
            echo "$user not found. Attempting to create..."
            sudo useradd "$user"
            sudo passwd "$user"
            if [ "$user" = "ccdcuser1" ]; then
                echo "[*] Adding to $sudo_group group"
                sudo usermod -aG $sudo_group "$user"
            fi
        fi
    done
}

function disable_users {
    print_banner "Disabling users"
    # TODO: turn this into sub function
    exclude_users=("${ccdc_users[@]}")
    echo "[*] Currently excluded users:" "${exclude_users[@]}"
    echo "[*] Would you like to exclude any additional users?"
    read -r -p "(y/n): " option
    option=$(echo "$option" | tr -d ' ') # truncates any spaces accidentally put in
    if [ "$option" == "y" ]; then
        compgen -u
        input=$(get_user_input)
        for item in $input; do
            exclude_users+=("$item")
        done
    fi

    echo "[*] Disabling users..."
    readarray -t disable_users < <(awk -F ':' '/bash/{print $1}' /etc/passwd)
    for user in "${exclude_users[@]}"; do
        # remove all instances of $user in $disable_users
        disable_users=("${disable_users[@]//$user}")
    done

    nologin_shell=""
    if [ -f /usr/sbin/nologin ]; then
        nologin_shell="/usr/sbin/nologin"
    elif [ -f /sbin/nologin ]; then
        nologin_shell="/sbin/nologin"
    else
        nologin_shell="/bin/false"
    fi

    for user in "${disable_users[@]}"; do
        sudo usermod -s "$nologin_shell" "$user"
    done
    echo "[*] Set nologin shell to $nologin_shell"
}

function remove_sudoers {
    print_banner "Removing sudoers"
    echo "[*] Removing users from the $sudo_group group"
    exclude_users=("${ccdc_users[@]}")
    echo "[*] Currently excluded users:" "${exclude_users[@]}"
    echo "[*] Would you like to exclude any additional users?"
    read -r -p "(y/n): " option
    option=$(echo "$option" | tr -d ' ') # truncates any spaces accidentally put in
    if [ "$option" == "y" ]; then
        compgen -u
        input=$(get_user_input)
        for item in $input; do
            exclude_users+=("$item")
        done
    fi

    echo "[*] Removing sudo users..."
    readarray -t unprivileged_users < <(awk -F ':' '/bash/{print $1}' /etc/passwd)
    for user in "${exclude_users[@]}"; do
        # remove all instances of $user in $disable_users
        unprivileged_users=("${unprivileged_users[@]//$user}")
    done

    for user in "${unprivileged_users[@]}"; do
        sudo gpasswd -d "$user" "$sudo_group"
    done
}

function remove_existing_firewall {
    echo "[*] Removing any existing firewalls and/or rules"
    if sudo command -v firewalld &>/dev/null; then
        echo "[*] firewalld detected; disabling"
        sudo systemctl stop firewalld
        sudo systemctl disable firewalld
    elif sudo command -v ufw &>/dev/null; then
        echo "[*] ufw detected; disabling"
        sudo ufw disable
    fi

    # Some systems may also have iptables as backend
    if sudo command -v iptables &>/dev/null; then
        echo "[*] iptables detected; clearing table"
        sudo iptables -F        
    fi
}

function setup_iptables {
    echo "[*] Installing iptables packages"
    sudo $pm install -y iptables iptables-persistent

    echo "[*] Setting up iptables rules"
    # TODO: create custom rules
}

function backups {
    # Get backup storage name
    while true; do
        backup_name=""
        read -r -p "Enter name for encrypted backups file (ex. cosmo.zip ): " backup_name
        if [ "$backup_name" != "" ]; then
            break
        fi
        echo "[X] ERROR: Backup name cannot be blank"
    done
    # Get backup storage location
    while true; do
        backup_dir=""
        read -r -p "Enter directory to place encrypted backups file (ex. /var/log/ ): " backup_dir
        if [ -e "$backup_dir" ]; then
            break
        fi
        echo "[X] ERROR: $backup_dir is invalid or does not exist: "
    done
    # Get backup encryption password
    echo "[*] Enter the backup encryption password."
    while true; do
        password=""
        confirm_password=""

        # Ask for password
        read -p "Enter password: " -s password
        echo

        # Confirm password
        read -p "Confirm password: " -s confirm_password
        echo

        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    sudo mkdir "$backup_dir/backups"
    dirs_to_backup=()

    # Zip all directories and store in backups directory
    for dir in "${dirs_to_backup[@]}"; do
        filename=$(basename "$dir")
        sudo zip -r "$backup_dir/backups/$filename.zip" "$dir" &> /dev/null
    done

    # Compress backups directory
    tar -czvf $backup_dir/backups.tar.gz -C "$backup_dir" backups &>/dev/null

    # Encrypt backup
    openssl enc -aes-256-cbc -salt -in "$backup_dir/backups.tar.gz" -out "$backup_dir/$backup_name" -k "$password"
    
    # Double check that backup exists before deleting intermediary files
    if [ -e "$backup_dir/$backup_name" ]; then
        sudo rm "$backup_dir/backups.tar.gz"
        sudo rm -rf "$backup_dir/backups"
        echo "[*] Backups successfully stored and encrypted."
    else
        echo "[X] ERROR: Could not successfully create backups."
    fi
}

function setup_splunk {
    print_banner "Installing splunk"
    read -r -p "What is the Splunk forward server ip? " indexer_ip

    wget $GITHUB_URL/splunk/splunk.sh --no-check-certificate
    sudo chmod +x splunk.sh
    case "$pm" in
        apt )
            ./splunk.sh deb "$indexer_ip"
        ;;
        dnf|yum|zypper )
            ./splunk.sh rpm "$indexer_ip"
        ;;
        * )
            ./splunk.sh tgz "$indexer_ip"
        ;;
    esac
}
#####################################################

######################## MAIN #######################
function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of script"

    detect_system_info
    install_prereqs

    change_passwords
    disable_users
    remove_sudoers
    create_ccdc_users

    remove_existing_firewall
    setup_iptables

    backups
    setup_splunk

    echo "[*] End of script"
}

DEBUG_LOG_PATH=$(dirname "$DEBUG_LOG")
if [ ! -d "$DEBUG_LOG_PATH" ]; then
    sudo mkdir -p "$DEBUG_LOG_PATH"
    sudo chown root:root "$DEBUG_LOG_PATH"
    sudo chmod 755 "$DEBUG_LOG_PATH"
fi
main "$@" 2>&1 | sudo tee -a $DEBUG_LOG
#####################################################