#!/bin/bash
# Usage: ./harden.sh [option]

###################### GLOBALS ######################
LOG='/var/log/ccdc/harden.log'
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/dev"
pm=""
sudo_group=""
ccdc_users=( "ccdcuser1" "ccdcuser2" )
debug="false"
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

    # Return the list by printing it
    # Note: Bash functions can't return arrays directly, but we can print them
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
    # TODO: install a syslog daemon for Splunk?
    # Needed for both hardening and Splunk installation
    sudo $pm install -y zip unzip wget curl acl
}

function create_ccdc_users {
    print_banner "Creating ccdc users"
    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
            echo "[*] $user already exists. Skipping..."
        else
            echo "[*] $user not found. Attempting to create..."
            if [ -f "/bin/bash" ]; then
                sudo useradd -m -s /bin/bash "$user"
            elif [ -f "/bin/sh" ]; then
                sudo useradd -m -s /bin/sh "$user"
            else
                echo "[X] ERROR: Could not find valid shell"
                exit 1
            fi
            
            echo "[*] Enter the new password for $user:"
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
                    continue
                fi

                if ! echo "$user:$password" | sudo chpasswd; then
                    echo "[X] ERROR: Failed to set password for $user"
                else
                    echo "[*] Password for $user has been set."
                    break
                fi
            done

            if [ "$user" == "ccdcuser1" ]; then
                echo "[*] Adding to $sudo_group group"
                sudo usermod -aG $sudo_group "$user"
            fi
        fi
        echo
    done
}

function change_passwords {
    print_banner "Changing user passwords"

    exclusions=("${ccdc_users[@]}")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi

    # if sudo [ -e "/etc/centos-release" ] ; then
    #     # CentOS starts numbering at 500
    #     targets=$(get_users '$3 >= 500 && $1 != "nobody" {print $1}' "${exclusions[*]}")
    # else
    #     # Otherwise 1000
    #     targets=$(get_users '$3 >= 1000 && $1 != "nobody" {print $1}' "${exclusions[*]}")
    # fi
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

    nologin_shell=""
    if [ -f /usr/sbin/nologin ]; then
        nologin_shell="/usr/sbin/nologin"
    elif [ -f /sbin/nologin ]; then
        nologin_shell="/sbin/nologin"
    else
        nologin_shell="/bin/false"
    fi

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

    echo "[*] Disabling users..."
    for user in $targets; do
        sudo usermod -s "$nologin_shell" "$user"
        echo "[*] Set shell for $user to $nologin_shell"
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

function disable_other_firewalls {
    print_banner "Disabling existing firewalls"
    if sudo command -v firewalld &>/dev/null; then
        echo "[*] disabling firewalld"
        sudo systemctl stop firewalld
        sudo systemctl disable firewalld
    fi
    # elif sudo command -v ufw &>/dev/null; then
    #     echo "[*] disabling ufw"
    #     sudo ufw disable
    # fi

    # Some systems may also have iptables as backend
    if sudo command -v iptables &>/dev/null; then
        echo "[*] clearing iptables rules"
        sudo iptables -F
    fi
}

function setup_ufw {
    print_banner "Configuring ufw"

    sudo $pm install -y ufw
    sudo which ufw &> /dev/null
    if [ $? == 0 ]; then
        echo -e "[*] Package ufw installed successfully\n"
        echo "[*] Which ports should be opened for incoming traffic?"
        echo "      WARNING: Do NOT forget to add 22/SSH if needed- please don't accidentally lock yourself out of the system!"
        sudo ufw --force disable
        sudo ufw reset
        ports=$(get_input_list)
        for port in $ports; do
            sudo ufw allow "$port"
            echo "[*] Rule added for port $port"
        done
        sudo ufw logging on
        sudo ufw --force enable
    else
        echo "[X] ERROR: Package ufw failed to install. Firewall will need to be configured manually"
    fi
}

function setup_iptables {
    # TODO: this needs work/testing on different distros
    print_banner "Configuring iptables"
    echo "[*] Installing iptables packages"

    if [ "$pm" == 'apt' ]; then
        # Debian and Ubuntu
        sudo "$pm" install -y iptables iptables-persistent #ipset
        SAVE='/etc/iptables/rules.v4'
    else
        # Fedora
        sudo "$pm" install -y iptables-services
        sudo systemctl enable iptables
        sudo systemctl start iptables
        SAVE='/etc/sysconfig/iptables'
    fi

    # echo "[*] Creating private ip range ipset"
    # sudo ipset create PRIVATE-IP hash:net
    # sudo ipset add PRIVATE-IP 10.0.0.0/8
    # sudo ipset add PRIVATE-IP 172.16.0.0/12
    # sudo ipset add PRIVATE-IP 192.168.0.0/16
    # sudo ipset save | sudo tee /etc/ipset.conf
    # sudo systemctl enable ipset

    echo "[*] Creating INPUT rules"
    sudo iptables -P INPUT DROP
    sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A INPUT -s 0.0.0.0/0 -j ACCEPT

    echo "[*] Which ports should be open for incoming traffic (INPUT)?"
    echo "[*] Warning: Do NOT forget to add 22/SSH if needed- please don't accidentally lock yourself out of the system!"
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A INPUT --dport "$port" -j ACCEPT
    done
    # TODO: is there a better alternative to this rule?
    sudo iptables -A INPUT -j LOG --log-prefix "[iptables] CHAIN=INPUT ACTION=DROP "

    echo "[*] Creating OUTPUT rules"
    # TODO: harden this as much as possible, like by limiting destination hosts
    # sudo iptables -P OUTPUT DROP
    # sudo iptables -A OUTPUT -o lo -j ACCEPT
    # sudo iptables -A OUTPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set PRIVATE-IP dst -j ACCEPT
    # Web traffic
    sudo iptables -A OUTPUT -p tcp -m multiport --dport 80,443 -j WEB
    sudo iptables -N WEB
    sudo iptables -A WEB -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j LOG --log-prefix "[iptables] WEB/private ip "
    sudo iptables -A WEB -j ACCEPT
    # DNS traffic
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

    echo "[*] Saving rules"
    sudo iptables-save | sudo tee $SAVE
}

function backups {
    print_banner "Backups"
    echo "[*] Would you like to backup any files?"
    option=$(get_input_string "(y/N): ")

    if [ "$option" != "y" ]; then
        return
    fi
    
    # Enter directories to backup
    repeat=true
    while $repeat; do
        repeat=false
        dirs_to_backup=()
        echo "Enter directories/files to backup:"
        input=$(get_input_list)
        for item in $input; do
            path=$(readlink -f "$item")
            if sudo [ -e "$path" ]; then
                dirs_to_backup+=("$path")
            else
                echo "[X] ERROR: $path is invalid or does not exist"
                repeat=true
            fi
        done
    done

    # Get backup storage name
    while true; do
        backup_name=$(get_input_string "Enter name for encrypted backups file (ex. cosmo.zip ): ")
        if [ "$backup_name" != "" ]; then
            break
        fi
        echo "[X] ERROR: Backup name cannot be blank"
    done
    # Get backup storage location
    while true; do
        backup_dir=$(get_input_string "Enter directory to place encrypted backups file (ex. /var/log/ ): ")
        backup_dir=$(readlink -f "$backup_dir")
        if sudo [ -e "$backup_dir" ]; then
            break
        fi
        echo "[X] ERROR: $backup_dir is invalid or does not exist"
    done
    # Get backup encryption password
    echo "[*] Enter the backup encryption password."
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

    # Zip all directories and store in backups directory
    sudo mkdir "$backup_dir/backups"
    for dir in "${dirs_to_backup[@]}"; do
        filename=$(basename "$dir")
        sudo zip -r "$backup_dir/backups/$filename.zip" "$dir" &> /dev/null
    done

    # Compress backups directory
    tar -czvf "$backup_dir/backups.tar.gz" -C "$backup_dir" backups &>/dev/null

    # Encrypt backup
    openssl enc -aes-256-cbc -salt -in "$backup_dir/backups.tar.gz" -out "$backup_dir/$backup_name" -k "$password"
    
    # Double check that backup exists before deleting intermediary files
    if sudo [ -e "$backup_dir/$backup_name" ]; then
        sudo rm "$backup_dir/backups.tar.gz"
        sudo rm -rf "$backup_dir/backups"
        echo "[*] Backups successfully stored and encrypted."
    else
        echo "[X] ERROR: Could not successfully create backups."
    fi
}

function setup_splunk {
    print_banner "Installing Splunk"
    indexer_ip=$(get_input_string "What is the Splunk forward server ip? ")

    wget $GITHUB_URL/splunk/splunk.sh --no-check-certificate
    chmod +x splunk.sh
    ./splunk.sh -f $indexer_ip
}
#####################################################

######################## MAIN #######################
function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of script"

    detect_system_info
    install_prereqs

    create_ccdc_users
    change_passwords
    disable_users
    remove_sudoers

    disable_other_firewalls
    setup_ufw
    # setup_iptables

    backups
    setup_splunk

    echo "[*] End of script"
    echo "[*] Script log can be viewed at $LOG"
    echo "[*] ***Please install system updates now***"
}

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --debug )
            echo "[*] Debug mode enabled"
            debug="true"
        ;;
    esac
done

# Set up logging
LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    sudo mkdir -p "$LOG_PATH"
    sudo chown root:root "$LOG_PATH"
    sudo chmod 750 "$LOG_PATH"
fi

# Run main function and log output
main "$@" 2>&1 | sudo tee -a $LOG
#####################################################