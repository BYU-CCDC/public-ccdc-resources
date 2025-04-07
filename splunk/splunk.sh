#!/bin/bash

# Copyright (C) 2025 deltabluejay
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

###################### GLOBALS ######################
DEBUG_LOG='/var/log/ccdc/splunk.log'
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
INDEXES=( 'system' 'web' 'network' 'windows' 'misc' 'snoopy' )
PM=""
IP=""
INDEXER=false
PACKAGE="auto"
LOCAL_PACKAGE=""
SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_ONLY=false
ADDITIONAL_LOGGING_ONLY=false
LOCAL=false
SYSTEMD_SYSTEM=false

# Special variables recognized by Splunk CLI for authentication
SPLUNK_OWNER="splunk"
SPLUNK_USERNAME="splunk"
SPLUNK_PASSWORD=""

# Indexer
indexer_deb="https://download.splunk.com/products/splunk/releases/9.2.5/linux/splunk-9.2.5-7bfc9a4ed6ba-linux-2.6-amd64.deb"
indexer_rpm="https://download.splunk.com/products/splunk/releases/9.2.5/linux/splunk-9.2.5-7bfc9a4ed6ba.x86_64.rpm"
indexer_tgz="https://download.splunk.com/products/splunk/releases/9.2.5/linux/splunk-9.2.5-7bfc9a4ed6ba-Linux-x86_64.tgz"

# Forwarder
deb="https://download.splunk.com/products/universalforwarder/releases/9.2.5/linux/splunkforwarder-9.2.5-7bfc9a4ed6ba-linux-2.6-amd64.deb"
rpm="https://download.splunk.com/products/universalforwarder/releases/9.2.5/linux/splunkforwarder-9.2.5-7bfc9a4ed6ba.x86_64.rpm"
tgz="https://download.splunk.com/products/universalforwarder/releases/9.2.5/linux/splunkforwarder-9.2.5-7bfc9a4ed6ba-Linux-x86_64.tgz"
arm_deb="https://download.splunk.com/products/universalforwarder/releases/9.2.5/linux/splunkforwarder-9.2.5-7bfc9a4ed6ba-Linux-armv8.deb"
arm_rpm="https://download.splunk.com/products/universalforwarder/releases/9.2.5/linux/splunkforwarder-9.2.5-7bfc9a4ed6ba.aarch64.rpm"
arm_tgz="https://download.splunk.com/products/universalforwarder/releases/9.2.5/linux/splunkforwarder-9.2.5-7bfc9a4ed6ba-Linux-armv8.tgz"
old_deb="https://download.splunk.com/products/universalforwarder/releases/9.0.9/linux/splunkforwarder-9.0.9-6315942c563f-linux-2.6-amd64.deb"
old_rpm="https://download.splunk.com/products/universalforwarder/releases/9.0.9/linux/splunkforwarder-9.0.9-6315942c563f.x86_64.rpm"
old_tgz="https://download.splunk.com/products/universalforwarder/releases/9.0.9/linux/splunkforwarder-9.0.9-6315942c563f-Linux-x86_64.tgz"
#####################################################

##################### FUNCTIONS #####################
# TODO: add return codes to stuff based on whether it errors or not

function print_banner {
    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
}

# TODO: add color?
function info {
    echo "[*] $1"
}

function error {
    echo "[X] ERROR: $1"
}

function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

function get_input_string {
    read -r -p "$1" input
    echo "$input"
}

function faketty () {
    script -qfc "$(printf "%q " "$@")" /dev/null
}

function download {
    url=$1
    output=$2

    if [[ "$LOCAL" == "true" && "$url" == "$GITHUB_URL"* ]]; then
        # Assume the URL is a local file path
        if [[ ! -f "$url" ]]; then
            error "Local file not found: $url"
            return 1
        fi
        cp "$url" "$output"
        info "Copied from local Github to $output"
        return 0
    fi
    
    # TODO: figure out how to fix the progress bar
    if ! wget -O "$output" --no-check-certificate "$url"; then
        # error "Failed to download with wget. Trying wget with older TLS version..."
        # if ! wget -O "$output" --secure-protocol=TLSv1 --no-check-certificate "$url"; then
            error "Failed to download with wget. Trying with curl..."
            if ! curl -L -o "$output" -k "$url"; then
                error "Failed to download with curl."
            fi
        # fi
    fi
}

function print_usage {
    echo "Usage:"
    echo "  ./splunk.sh -f <INDEXER IP> [flags]         # Install the forwarder"
    echo "  ./splunk.sh -i [flags]                      # Install the indexer"
    echo "  ./splunk.sh -a <LOG_PATH>                   # Add a new monitor"
    echo
    echo "Flags:
  -h            Show this help message
  -f <ip>       Install the forwarder (-f is required unless -i or -a are used)
  -i            Install the indexer
  -p <type>     Package type (defaults to auto- see below)
  -u            Print Splunk package URLs
  -S            Install Splunk only (no additional logging)
  -L            Install additional logging sources only (no Splunk)
  -l <path>     Install from a locally cloned GitHub repository (provide filesystem path to repo)
  -g <url>      Change the GitHub URL for downloading files (for local network hosting)
  -a <path>     Add a new monitor (use only after installation)"
    echo
    echo "Available packages:
  auto (default; autodetects best package format based on package manager)
  * (catch-all; replace with any variable in the script)
  Forwarder:
    deb (Debian-based distros)
    rpm (RHEL-based distros)
    tgz (generic .tgz file)
    arm_debian (deb for ARM machines)
    arm_rpm (rpm for ARM machines)
    arm_tgz (tgz for ARM machines)
    old_deb (compatibility package- try if you're getting glibc errors)
    old_rpm (compatibility package- try if you're getting glibc errors)
    old_tgz (compatibility package- try if you're getting glibc errors)
  Indexer:
    indexer_deb (Debian-based distros)
    indexer_rpm (RHEL-based distros)
    indexer_tgz (generic .tgz file)
"
}

function autodetect_os {
    print_banner "Autodetecting OS / package manager"
    # Borrowed from harden.sh
    sudo which apt-get &> /dev/null
    apt=$?
    sudo which dnf &> /dev/null
    dnf=$?
    sudo which zypper &> /dev/null
    zypper=$?
    sudo which yum &> /dev/null
    yum=$?

    if [ $apt == 0 ]; then
        info "apt/apt-get detected (Debian-based OS)"
        info "Updating package list"
        # TODO: pkill unattended-upgrades
        sudo apt-get update
        PM="apt-get"
    elif [ $dnf == 0 ]; then
        info "dnf detected (Fedora-based OS)"
        PM="dnf"
    elif [ $zypper == 0 ]; then
        info "zypper detected (OpenSUSE-based OS)"
        PM="zypper"
    elif [ $yum == 0 ]; then
        info "yum detected (RHEL-based OS)"
        PM="yum"
    else
        error "Could not detect package manager / OS"
        # exit 1
    fi
}

function install_dependencies {
    print_banner "Installing dependencies"

    if [ "$PM" == "" ]; then
        info "No package manager detected."
    else
        sudo "$PM" install -y wget curl acl
        if [ "$PM" == "apt-get" ]; then
            sudo "$PM" install -y debsums
        else
            sudo "$PM" install -y rpm
        fi
    fi

    if ! command -v wget &>/dev/null; then
        error "Please install wget before using this script"
        exit 1
    fi

    # Needed because curl can bypass some wget TLS/SSL errors
    if ! command -v curl &>/dev/null; then
        error "Please install curl before using this script"
        exit 1
    fi

    if ! command -v setfacl &>/dev/null; then
        error "Please install acl before using this script"
        exit 1
    fi
}

function check_prereqs {
    if [ "$INDEXER" != true ]; then
        if [[ $IP == "" ]]; then
            error "Please provide the IP of the splunk indexer (-h for help)"
            exit 1
        fi
        if [[ ! $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            error "Invalid IP address format: $IP"
            exit 1
        fi
    fi

    # user should not be root or run `sudo ./splunk.sh` since doing so makes the splunk install be owned by root
    # TODO: test if this actually matters anymore
    if [ "$EUID" == 0 ]; then
        error "Please run script without sudo prefix/not as root"
        exit 1
    fi

    # user needs sudo privileges to be able to run script
    user_groups=$(groups)
    if [[ $user_groups != *sudo* && $user_groups != *wheel* && $PM != "zypper" ]]; then
        if ! sudo grep -q '^Defaults targetpw' /etc/sudoers; then
            error "User needs sudo privileges. User not found in sudo/wheel group"
            exit 1
        fi
    fi

    # Check if home directory exists for current user. Home directory is needed for running splunk commands
    # since the commands are aliases for http request methods. The .splunk directory contains this auth
    # token, so without it, splunk fails to install.
    if [ ! -d /home/"$(whoami)" ]; then
        info "No home directory for user $(whoami). Creating home directory"
        sudo mkdir -p /home/"$(whoami)"
        sudo chown "$(whoami)":"$(whoami)" /home/"$(whoami)"
    fi

    # user needs write permissions for current directory
    if [ ! -w . ]; then
        error "User does not have write permissions for current directory"
        exit 1
    fi
}

function download_and_install_package {
    if [[ "$1" == *.deb ]]; then
        if [[ -z "$LOCAL_PACKAGE" ]]; then
            download "$1" splunk.deb
        fi
        sudo dpkg -i ./splunk.deb
    elif [[ "$1" == *.rpm ]]; then
        if [[ -z "$LOCAL_PACKAGE" ]]; then
            download "$1" splunk.rpm
        fi
        if command -v zypper &>/dev/null; then
            sudo zypper --no-gpg-checks install -y ./splunk.rpm
        else
            sudo yum install --nogpgcheck ./splunk.rpm -y
        fi
    elif [[ "$1" == *.tgz ]]; then
        if [[ -z "$LOCAL_PACKAGE" ]]; then
            download "$1" splunk.tgz
        fi
        info "Extracting to $SPLUNK_HOME"
        sudo tar -xvf splunk.tgz -C /opt/ &> /dev/null
        # TODO: make sure it actually extracts to $SPLUNK_HOME
        sudo chown -R splunk:splunk $SPLUNK_HOME
    else
        error "Unknown package type. Please install Splunk manually to $SPLUNK_HOME, then run this script again to configure it."
        exit
    fi
}

function install_splunk {
    # If Splunk does not already exist:
    if sudo [ ! -e $SPLUNK_HOME/bin/splunk ]; then
        # Determine package type and install
        case "$PACKAGE" in
            auto )
                info "Autodetecting best package format"
                case "$PM" in
                    apt-get )
                        PACKAGE="deb"
                        install_splunk
                    ;;
                    dnf|zypper|yum )
                        PACKAGE="rpm"
                        install_splunk
                    ;;
                    *)
                        error "Unknown package manager. Trying .tgz package."
                        PACKAGE="tgz"
                        install_splunk
                    ;;
                esac
                return
            ;;
            deb|debian )
                print_banner "Installing .deb package"
                echo
                if [ "$INDEXER" == true ]; then
                    info "Downloading indexer package"
                    download_and_install_package "$indexer_deb"
                else
                    info "Downloading forwarder package"
                    download_and_install_package "$deb"
                fi
            ;;
            rpm )
                print_banner "Installing .rpm package"
                echo
                if [ "$INDEXER" == true ]; then
                    info "Downloading indexer package"
                    download_and_install_package "$indexer_rpm"
                else
                    info "Downloading forwarder package"
                    download_and_install_package "$rpm"
                fi
            ;;
            tgz|tar|linux )
                print_banner "Installing generic .tgz package"
                echo
                if [ "$INDEXER" == true ]; then
                    info "Downloading indexer package"
                    download_and_install_package "$indexer_tgz"
                else
                    info "Downloading forwarder package"
                    download_and_install_package "$tgz"
                fi
            ;;
            *)
                # catch-all statement for unknown packages
                eval "pkg=\$$PACKAGE"
                if [[ -z $pkg ]]; then
                    error "Unknown package: $PACKAGE"
                    print_usage
                    exit 1
                else
                    print_banner "Installing $PACKAGE"
                    echo
                    download_and_install_package "$pkg"
                fi
            ;;
        esac
    else
        info "Install already exists. Proceeding to configure Splunk."
    fi
}

function create_splunk_user {
    set_pass=true

    # Create splunk user/group
    if id "splunk" &>/dev/null; then
        info "Splunk user already exists"
        info "Would you like to reset the password for the splunk user?"
        info "You'll need to do this if you're reinstalling splunk or setting it up for the first time."
        option=$(get_input_string "(Y/n): " | tr -d ' ')
        if [ "$option" == "n" ]; then
            set_pass=false
        fi
    else
        info "Creating splunk user"
        sudo useradd splunk -d $SPLUNK_HOME
        # Allow package verification
        if sudo [ -e /etc/sudoers.d ]; then
            SUDOERS_FILE="/etc/sudoers.d/splunk"
            if [[ "$PM" == "apt-get" ]]; then
                echo "splunk ALL=(ALL) NOPASSWD: $(which debsums) -as" | sudo tee "$SUDOERS_FILE" > /dev/null
            else
                echo "splunk ALL=(ALL) NOPASSWD: $(which rpm) -Va" | sudo tee "$SUDOERS_FILE" > /dev/null
            fi
            sudo chown root:root
            sudo chmod 440 "$SUDOERS_FILE"
        else
            error "Warning: /etc/sudoers.d does not exist. Splunk user will not have the sudo privileges needed for package verification."
        fi
    fi

    if ! getent group "splunk" > /dev/null; then
        sudo groupadd splunk
        sudo usermod -aG splunk splunk
    fi

    if [ "$set_pass" == true ]; then
        # Set splunk password
        info "Setting password for the splunk user"
        while true; do
            password=""
            confirm_password=""

            # Ask for password
            password=$(get_silent_input_string "Enter password for splunk user: ")
            echo

            # Confirm password
            confirm_password=$(get_silent_input_string "Confirm password: ")
            echo

            if [ "$password" != "$confirm_password" ]; then
                echo "Passwords do not match. Please retry."
                continue
            fi

            if ! echo "splunk:$password" | sudo chpasswd; then
                error "Failed to set password for splunk user"
            else
                info "Password for splunk user has been set."
                break
            fi
        done

        SPLUNK_PASSWORD=$password
        
        # Add splunk user as forwarder/indexer admin
        info "Adding splunk user to user-seed.conf"
        # TODO: give can_delete permissions
        sudo sh -c "printf '[user_info]\nUSERNAME = splunk\nPASSWORD = $password' > $SPLUNK_HOME/etc/system/local/user-seed.conf"
        # info "Please remember these credentials for when Splunk asks for them later during the configuration process"
    fi
    # Set ACL to allow splunk to read any log files (execute needed for directories)
    info "Giving splunk user access to /var/log/"
    sudo setfacl -R -m u:splunk:rx /var/log/

    # chown splunk installation directory
    sudo chown -R splunk:splunk $SPLUNK_HOME
}

function install_app {
    download "$1" /tmp/app.spl
    sudo chown splunk:splunk "/tmp/app.spl"
    sudo -H -u splunk $SPLUNK_HOME/bin/splunk install app "/tmp/app.spl" -update 1
    sudo rm /tmp/app.spl
}

function install_ccdc_add_on {
    print_banner "Installing CCDC Splunk add-on"
    install_app "$GITHUB_URL/splunk/ccdc-add-on.spl"
}

function install_sysmon_add_on {
    print_banner "Installing Sysmon Splunk add-on"
    install_app "$GITHUB_URL/splunk/linux/splunk-add-on-for-sysmon-for-linux_100.tgz"

    # Sysmon monitor is included with add-on, but we need to change the index
    info "Setting monitor index to sysmon"
    local dir="$SPLUNK_HOME/etc/apps/Splunk_TA_sysmon-for-linux/local/"
    sudo mkdir $dir
    sudo chown -R splunk:splunk $dir
    download "$GITHUB_URL/splunk/linux/sysmon-inputs.conf" inputs.conf
    sudo chown splunk:splunk inputs.conf
    sudo mv inputs.conf "$dir"
}

function install_ccdc_app {
    print_banner "Installing CCDC Splunk app"
    install_app "$GITHUB_URL/splunk/ccdc-app.spl"
}

function install_windows_soc_app {
    print_banner "Installing Windows SOC Splunk app"
    install_app "$GITHUB_URL/splunk/windows-security-operations-center_20.tgz"
}

function install_sysmon_security_monitoring_app {
    print_banner "Installing Sysmon Security Monitoring Splunk app"
    install_app "$GITHUB_URL/splunk/sysmon-security-monitoring-app-for-splunk_4013.tgz"
}

function install_audit_parse_app {
    print_banner "Installing Audit Hex Value Decoder app"
    install_app "$GITHUB_URL/splunk/linux-audit-log-hex-value-decoder_100.tgz"
}

function install_palo_alto_apps {
    print_banner "Installing Palo Alto apps"
    download "https://github.com/PaloAltoNetworks/Splunk-Apps/archive/refs/tags/v8.1.3.zip" /tmp/palo.zip
    unzip /tmp/palo.zip -d /tmp/palo-apps/

    sudo mv /tmp/palo-apps/Splunk-Apps-8.1.3/Splunk_TA_paloalto/ $SPLUNK_HOME/etc/apps/
    sudo mv /tmp/palo-apps/Splunk-Apps-8.1.3/SplunkforPaloAltoNetworks/ $SPLUNK_HOME/etc/apps/
    
    sudo chown -R splunk:splunk "$SPLUNK_HOME/etc/apps/Splunk_TA_paloalto/"
    sudo chown -R splunk:splunk "$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/"

    sudo rm /tmp/palo.zip
    sudo rm -rf /tmp/palo-apps/
}

function setup_indexer {
    print_banner "Configuring Indexer"

    info "Adding listening port 9997"
    sudo -H -u splunk $SPLUNK_HOME/bin/splunk enable listen 9997
    # sudo -H -u splunk $SPLUNK_HOME/bin/splunk enable deploy-server
    
    info "Adding Indexes"
    for i in "${INDEXES[@]}"; do
        sudo -H -u splunk $SPLUNK_HOME/bin/splunk add index "$i"
    done

    info "Giving splunk user can_delete role"
    sudo -H -u splunk $SPLUNK_HOME/bin/splunk edit user splunk -role admin -role can_delete

    info "Installing indexer apps"
    sudo rm /tmp/app.spl &>/dev/null
    install_ccdc_app
    install_windows_soc_app
    install_sysmon_security_monitoring_app
    install_audit_parse_app
    install_palo_alto_apps
}

# Installs splunk
function setup_splunk {
    print_banner "Setup"

    if [ "$INDEXER" != true ]; then
        if [[ $IP == "" ]]; then 
            error "Please provide the IP of the central splunk instance"
            exit 1
        fi
    fi
    install_splunk

    if sudo [ ! -e $SPLUNK_HOME/bin/splunk ]; then
        error "Splunk failed to install"
        exit 1
    else
        info "Splunk installed successfully"
    fi

    create_splunk_user

    info "Starting splunk"
    # For some reason, splunk start doesn't work on Ubuntu 14 without a tty...
    faketty sudo -H -u splunk $SPLUNK_HOME/bin/splunk start --accept-license --no-prompt

    # Make sure the correct username/password is provided before continuing
    # (this will do nothing if already logged in)
    res=-1
    while [ $res -ne 0 ]; do
        if [ "$SPLUNK_PASSWORD" == "" ]; then
            # TODO: verify this twice
            # TODO: also try passing -auth to every splunk command
            SPLUNK_PASSWORD=$(get_silent_input_string "Enter the password for splunk user: ")
        fi
        sudo -H -u splunk $SPLUNK_HOME/bin/splunk login -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"
        res=$?
    done

    if [ "$INDEXER" == true ]; then
        setup_indexer
        # TODO: add firewall rules
        # sudo iptables -I INPUT 1 -p tcp -m multiport --dport 8000,9443 -j ACCEPT
        # sudo iptables -I INPUT 1 -p tcp --dport 9997 -j ACCEPT
    else
        setup_forward_server "$IP"
    fi
    sudo chown -R splunk:splunk $SPLUNK_HOME
}

# Checks for existence of a file or directory and add it as a monitor if it exists
# Arguments:
#   $1: Path of log source
#   $2: Index name
function add_monitor {
    source=$1
    index=$2
    if sudo [ -e "$source" ]; then
        sudo -H -u splunk $SPLUNK_HOME/bin/splunk add monitor "$source" -index "$index"
        # info "Added monitor for $source"
    else
        error "No file or dir found at $source"
    fi
}

# Adds a scripted input to Splunk
# Arguments:
#   $1: Path of log source
#   $2: Index name
#   $3: Interval
#   $4: Sourcetype (arbitrary)
function add_script {
    source=$1
    index=$2
    interval=$3
    sourcetype=$4
    sudo -H -u splunk $SPLUNK_HOME/bin/splunk add exec "$source" -index "$index" -interval "$interval" -sourcetype "$sourcetype"
}

function add_system_logs {
    print_banner "Adding various system logs"
    info "Some of these will fail due to distribution differences"

    INDEX="system"
    # add_monitor "/etc/services" "$INDEX"
    # add_monitor "/etc/systemd/" "$INDEX"
    # add_monitor "/etc/init.d/" "$INDEX"
    # add_monitor "/etc/profile.d/" "$INDEX"
    # add_monitor "/var/log/cron" "$INDEX" # this probably won't exist by default
    add_monitor "/var/log/syslog" "$INDEX"
    add_monitor "/var/log/messages" "$INDEX"
    add_monitor "/var/log/auth.log" "$INDEX"
    add_monitor "/var/log/secure" "$INDEX"
    add_monitor "/var/log/audit/audit.log" "$INDEX"

    INDEX="misc"
    # add_monitor "/tmp/" "$INDEX"
}

function add_firewall_logs {
    print_banner "Adding firewall logs"
    INDEX="network"
    
    if sudo command -v firewalld &>/dev/null; then
        info "firewalld detected"
        FIREWALL_LOG="/var/log/firewalld"

        info "Enabling firewalld logging"
        sudo firewall-cmd --set-log-denied=all

        info "Adding firewalld error logs"
        add_monitor "$FIREWALL_LOG" "$INDEX"
        info "firewalld access logs contained in /var/log/messages (already added)"
    elif sudo command -v ufw &>/dev/null; then
        info "ufw detected"
        FIREWALL_LOG="/var/log/ufw.log"

        info "Enabling ufw logging"
        sudo ufw logging low
        # Log all existing rules
        sudo ufw status | awk '/^[0-9]/ { print $1 }' | while read -r INPUT; do sudo ufw allow log "$INPUT"; done

        info "Adding monitors for ufw logs"
        # sudo touch "$FIREWALL_LOG"
        add_monitor "$FIREWALL_LOG" "$INDEX"
        info "ufw logs also contained in /var/log/syslog"
    elif sudo command -v iptables &>/dev/null; then
        # TODO: make this the main option and make it actually work with harden.sh
        info "iptables detected"
        FIREWALL_LOG="/var/log/iptables.log"

        info "Enabling iptables logging"
        LOGGING_LEVEL=1
        # Not sure if the order of where this rule is placed in the chain matters or not
        sudo iptables -A INPUT -j LOG --log-prefix "[iptables] CHAIN=INPUT ACTION=DROP: " --log-level $LOGGING_LEVEL
        # sudo iptables -A OUTPUT -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        # sudo iptables -A FORWARD -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        
        info "Adding monitors for iptables"
        # sudo touch "$FIREWALL_LOG"
        add_monitor "$FIREWALL_LOG" "$INDEX"
    else
        error "No firewall found. Please forward logs manually."
    fi
}

function add_package_logs {
    print_banner "Adding package logs"
    
    INDEX="misc"
    if command -v dpkg &>/dev/null; then
        info "Adding monitors for dpkg logs"
        PACKAGE_LOGS="/var/log/dpkg.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v apt &>/dev/null; then
        info "Adding monitors for apt logs"
        PACKAGE_LOGS="/var/log/apt/history.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v dnf &>/dev/null; then
        info "Adding monitors for dnf logs"
        PACKAGE_LOGS="/var/log/dnf.rpm.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v yum &>/dev/null; then
        info "Adding monitors for yum logs"
        PACKAGE_LOGS="/var/log/yum.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v zypper &>/dev/null; then
        info "Adding monitors for zypper logs"
        PACKAGE_LOGS="/var/log/zypp/history"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi
}

# function add_ssh_key_logs {
#     print_banner "Adding user ssh key logs"
#     INDEX="system"
#     for dir in /home/*; do
#         if [ -d "$dir" ]; then
#             if [ -d "$dir/.ssh" ]; then
#                 info "Adding $dir/.ssh/"
#                 add_monitor "$dir/.ssh" "$INDEX"
#             fi
#         fi
#     done
# }

function add_web_logs {
    print_banner "Adding web logs"

    INDEX="web"
    if [ -d "/var/log/apache2/" ]; then
        echo "Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/apache2/access.log"
        APACHE_ERROR="/var/log/apache2/error.log"
        add_monitor "$APACHE_ACCESS" "$INDEX"
        add_monitor "$APACHE_ERROR" "$INDEX"
    elif [ -d "/var/log/httpd/" ]; then
        info "Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/httpd/access_log"
        APACHE_ERROR="/var/log/httpd/error_log"
        add_monitor "$APACHE_ACCESS" "$INDEX"
        add_monitor "$APACHE_ERROR" "$INDEX"
    elif [ -d "/var/log/lighttpd/" ]; then
        info "Adding monitor for lighttpd error logs"
        # LIGHTTPD_ACCESS="/var/log/lighhtpd/access.log"
        LIGHTTPD_ERROR="/var/log/lighttpd/error.log"
        # add_monitor "$LIGHTTPD_ACCESS" "$INDEX"
        add_monitor "$LIGHTTPD_ERROR" "$INDEX"
        print_banner "Please manually modify lighttpd config file in /etc/lighttpd/lighttpd.conf."
        info "Add \"mod_accesslog\" in server.modules, and at the bottom of the file add \`accesslog.filename = \"/var/log/lighttpd/access.log\"\`"
        info "Then, add a Splunk monitor for /var/log/lighttpd/access.log"
    elif [ -d "/var/log/nginx" ]; then
        info "Adding monitors for Nginx logs"
        NGINX_ACCESS="/var/log/nginx/access.log"
        NGINX_ERROR="/var/log/nginx/error.log"
        add_monitor "$NGINX_ACCESS" "$INDEX"
        add_monitor "$NGINX_ERROR" "$INDEX"
    else
        info "Did not find webserver (Apache, Nginx, or lighttpd) on this system."
    fi
}

function add_mysql_logs {
    print_banner "Adding MySQL logs"

    INDEX="web"
    MYSQL_CONFIG="/etc/mysql/my.cnf" # Adjust the path based on your system

    if [ -f "$MYSQL_CONFIG" ]; then
        # Make sure there's actually a MySQL or MariaDB service
        if command -v systemctl &> /dev/null; then
            if ! sudo systemctl status mysql &> /dev/null && ! sudo systemctl status mariadb &> /dev/null; then
                info "Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
            fi
        elif command -v service &> /dev/null; then
            if ! sudo service mysql status &> /dev/null && ! sudo service mariadb status &> /dev/null; then
                info "Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
            fi
        else
            info "Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
        fi
        info "Adding monitors for MySQL logs"

        # Log file paths
        GENERAL_LOG="/var/log/mysql/mysql.log"
        ERROR_LOG="/var/log/mysql/error.log"

        # Enable General Query Log
        echo "[mysqld]" | sudo tee -a "$MYSQL_CONFIG"
        echo "general_log = 1" | sudo tee -a "$MYSQL_CONFIG"
        echo "general_log_file = $GENERAL_LOG" | sudo tee -a "$MYSQL_CONFIG"

        # Enable Error Log
        echo "log_error = $ERROR_LOG" | sudo tee -a "$MYSQL_CONFIG"

        # Restart MySQL service
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart mysql
        elif command -v service &> /dev/null; then
            sudo service mysql restart
        else
            error "Unable to restart MySQL. Please restart the MySQL service manually."
        fi

        # sudo touch "$GENERAL_LOG"
        # sudo touch "$ERROR_LOG"
        add_monitor "$GENERAL_LOG" "$INDEX"
        add_monitor "$ERROR_LOG" "$INDEX"
    else
        info "Did not find MySQL on this system."
    fi
}

# Adds scripted inputs
function add_scripts {
    print_banner "Adding scripted inputs"
    # TOOD: add this to the add-on inputs.conf instead
    info "Adding user sessions script"
    add_script $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/sessions.sh "system" "180" "ccdc-sessions"
    info "Adding package integrity verification"
    add_script $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/package-check.sh "system" "600" "ccdc-package-integrity"
}

# Adds monitors for the Splunk indexer service itself
function add_indexer_web_logs {
    print_banner "Adding indexer web logs"

    INDEX="web"
    SPLUNK_WEB_ACCESS="$SPLUNK_HOME/var/log/splunk/web_access.log"

    info "Adding monitors for Splunk web logs"
    add_monitor "$SPLUNK_WEB_ACCESS" "$INDEX"
}

# Asks the user to specify additional logs to add
function add_additional_logs {
    print_banner "Adding additional logs"

    info "Indexes: ${INDEXES[*]}"
    info "Would you like to add any additional monitors?"
    option=$(get_input_string "(y/N): " | tr -d ' ')    # truncate any spaces accidentally put in
    if [ "$option" == "y" ]; then
        for index in "${INDEXES[@]}"; do
            info "Would you like to add additional sources for index '$index'?"
            option=$(get_input_string "(y/N): " | tr -d ' ')

            sources=()
            continue="true"
            if [ "$option" == "y" ]; then
                while [ "$continue" != "false" ]; do
                    userInput=$(get_input_string "Enter additional logs sources: (one entry per line; enter blank line to finish): " | tr -d ' ')
                    if [[ "$userInput" == "" ]]; then
                        continue="false"
                    else
                        sources+=("$userInput")
                    fi
                    # TODO: check that file exists during input loop
                done
                for source in "${sources[@]}"; do
                    add_monitor "$source" "$index"
                done
            fi
        done
    fi
}

function setup_monitors {
    print_banner "Adding Monitors"

    # Add monitors
    add_system_logs
    # add_firewall_logs
    add_package_logs
    # add_ssh_key_logs
    add_web_logs
    add_mysql_logs
    install_ccdc_add_on
    add_scripts

    if [ "$INDEXER" == true ]; then
        add_indexer_web_logs
    fi
}

function setup_forward_server {
    print_banner "Adding Forward Server"
    sudo -H -u splunk $SPLUNK_HOME/bin/splunk add forward-server "$1":9997
    # sudo -H -u splunk $SPLUNK_HOME/bin/splunk enable deploy-client
    # sudo -H -u splunk $SPLUNK_HOME/bin/splunk set deploy-poll "$1":8089
}

function install_auditd {
    print_banner "Installing auditd"

    # Install auditd
    info "Installing auditd package"
    sudo $pm install -y auditd
    if command -v systemctl &> /dev/null; then
        sudo systemctl enable auditd
        sudo systemctl start auditd
    elif command -v service &> /dev/null; then
        sudo service auditd start
    fi

    # Add custom rules
    info "Adding custom audit rules"
    if ! sudo [ -d "/etc/audit/rules.d/" ]; then
        error "Could not locate audit rules directory"
        return 1
    fi
    CUSTOM_RULE_FILE='/etc/audit/rules.d/ccdc.rules'

    # Download custom rule file
    download $GITHUB_URL/splunk/linux/ccdc.rules ./ccdc.rules
    sudo chown root:root ./ccdc.rules
    sudo chmod 600 $CUSTOM_RULE_FILE
    sudo mv ./ccdc.rules $CUSTOM_RULE_FILE

    # Add home directory rules
    echo '' | sudo tee -a $CUSTOM_RULE_FILE
    for dir in /home/*; do
        if [ -d "$dir" ]; then
            echo "-w ${dir}/.ssh/ -p w -k CCDC_modify_ssh_user" | sudo tee -a $CUSTOM_RULE_FILE

            if [ -f "$dir/.bashrc" ]; then
                echo "-w ${dir}/.bashrc -p w -k CCDC_modify_bashrc_user" | sudo tee -a $CUSTOM_RULE_FILE
            fi
        fi
    done

    sudo augenrules --load
    sudo service auditd reload

    info "Applied rules:"
    sudo auditctl -l

    sudo setfacl -R -m u:splunk:rx /var/log/audit
    # TODO: add check for successful Splunk login to all Splunk commands
    add_monitor "/var/log/audit/audit.log" "system"
}

function install_snoopy {
    version="$1"
    print_banner "Installing Snoopy (trying version $version)"
    if sudo [ -e /usr/local/lib/libsnoopy.so ]; then
        info "Snoopy is already installed"
        return 0
    fi

    download https://github.com/a2o/snoopy/raw/install/install/install-snoopy.sh "install-snoopy.sh"
    chmod 755 install-snoopy.sh
    
    # Install dependencies
    case "$PM" in
        apt )
        ;;
        dnf|zypper|yum )
            if sudo test -f "/etc/centos-release" || sudo test -f "/etc/redhat-release"; then
                sudo "$PM" install -y epel-release
            fi
            sudo "$PM" install -y gcc gzip make procps socat tar wget
        ;;
        * )
        ;;
    esac

    # Try installing Snoopy
    download "https://github.com/a2o/snoopy/releases/download/snoopy-$version/snoopy-$version.tar.gz" "snoopy-$version.tar.gz"
    if ! sudo ./install-snoopy.sh "./snoopy-$version.tar.gz"; then
        # If it fails
        error "Snoopy installation for version $version failed"
        return 1
    else
        # If it succeeds
        SNOOPY_CONFIG='/etc/snoopy.ini'
        if sudo [ -f $SNOOPY_CONFIG ]; then
            sudo touch /var/log/snoopy.log
            # Unfortunately required by snoopy in order to use a log file other than syslog/messages
            SNOOPY_LOG='/var/log/snoopy.log'
            sudo chmod 622 $SNOOPY_LOG
            sudo setfacl -m u:splunk:rx /var/log/snoopy.log
            echo "filter_chain = \"exclude_spawns_of:splunkd,btool\"" | sudo tee -a $SNOOPY_CONFIG
            echo "output = file:$SNOOPY_LOG" | sudo tee -a $SNOOPY_CONFIG
            echo
            info "Set Snoopy output to $SNOOPY_LOG."
            # Restart snoopy
            # TODO: these commands aren't consistent across all systems
            sudo /usr/local/sbin/snoopy-disable
            sudo /usr/local/sbin/snoopy-enable
            sudo -H -u splunk $SPLUNK_HOME/bin/splunk add monitor "$SNOOPY_LOG" -index "snoopy" -sourcetype "snoopy"
        else
            error "Could not find Snoopy config file. Please add \`output = file:/var/log/snoopy.log\` to the end of the config."
        fi
        info "Snoopy installed successfully."
        info "NOTE: Unless you restart the server, Snoopy may not pick up on commands from existing processes."
        # see https://github.com/a2o/snoopy/issues/212
        return 0
    fi
}

function install_sysmon {
    print_banner "Installing Sysmon"
    download "$GITHUB_URL/linux/sysmon/sysmon.sh" sysmon.sh
    chmod +x sysmon.sh

    if [[ "$LOCAL" == true ]]; then
        ./sysmon.sh -l "$GITHUB_URL"
    else
        ./sysmon.sh -g "$GITHUB_URL"
    fi

    if [[ $? -eq 0 ]]; then
        info "Sysmon installed successfully"
        install_sysmon_add_on
    else
        error "Sysmon installation failed"
    fi
}

function install_ossec {
    print_banner "Installing OSSEC"
    download "$GITHUB_URL/linux/ossec.sh" ossec.sh
    chmod +x ossec.sh

    cmd="./ossec.sh "
    if [[ "$LOCAL" == true ]]; then
        cmd+="-l $GITHUB_URL "
    else
        cmd+="-g $GITHUB_URL "
    fi

    if [[ "$INDEXER" == true ]]; then
        cmd+="-i $IP"
    else
        cmd+="-f $IP"
    fi

    eval $cmd

    if [[ $? -eq 0 ]]; then
        info "OSSEC installed successfully"
    else
        error "OSSEC installation failed"
    fi
}
#####################################################

######################## MAIN #######################
function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    info "Start of script"

    check_prereqs
    autodetect_os
    install_dependencies

    if [ "$ADDITIONAL_LOGGING_ONLY" == false ]; then
        setup_splunk

        setup_monitors
        # add_additional_logs

        print_banner "Starting Splunk"
        sudo -H -u splunk $SPLUNK_HOME/bin/splunk stop
        if command -v systemctl &> /dev/null; then
            info "Enabling systemd service"
            sudo $SPLUNK_HOME/bin/splunk enable boot-start -systemd-managed 1 -user splunk
            if [ "$INDEXER" == true ]; then
                sudo systemctl enable Splunkd
                sudo systemctl start Splunkd
            else
                sudo systemctl enable SplunkForwarder
                sudo systemctl start SplunkForwarder
            fi
        else
            info "Not a systemd machine; using splunk start"
            sudo -H -u splunk $SPLUNK_HOME/bin/splunk start
        fi

        echo
    fi

    if [ "$SPLUNK_ONLY" == false ]; then
        print_banner "Installing additional logging sources"
        info "Installing and configuring:"
        echo "   - auditd (file monitor)"
        echo "   - snoopy (command logger)"
        echo "   - sysmon (system and network monitor)"

        install_auditd
        if ! install_snoopy "2.5.2"; then
            if ! install_snoopy "2.4.15"; then
                if ! install_snoopy "2.3.2"; then
                    error "Failed to install Snoopy"
                fi
            fi
        fi
        install_sysmon
        install_ossec
    else
        info "Skipping installation of additional logging sources"
    fi

    print_banner "End of script"
    # TODO: print status of installation of all components
    info "You can add additional monitors with this script."
    echo "   Usage: ./splunk.sh -a <LOG_PATH>"
    # info "Add future additional scripted inputs with 'sudo -H -u splunk $SPLUNK_HOME/bin/splunk add exec $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/<SCRIPT> -interval <SECONDS> -index <INDEX>'"
    echo
    info "A debug log is located at $DEBUG_LOG"
    echo
}

# TODO: add a reinstall option
while getopts "hp:P:f:ig:uSa:Ll:" opt; do
    case $opt in
        h)
            print_usage
            exit 0
            ;;
        u)
            # prints download urls for Splunk
            echo "Linux indexer deb (indexer_deb): $indexer_deb"
            echo
            echo "Linux indexer rpm (indexer_rpm): $indexer_rpm"
            echo
            echo "Linux indexer tgz (indexer_tgz): $indexer_tgz"
            echo
            echo "Linux deb (deb): $deb"
            echo
            echo "Linux rpm (rpm): $rpm"
            echo
            echo "Linux tgz (tgz): $tgz"
            echo
            echo "Linux ARM deb (arm_deb): $arm_deb"
            echo
            echo "Linux ARM rpm (arm_rpm): $arm_rpm"
            echo
            echo "Linux ARM tgz (arm_tgz): $arm_tgz"
            echo
            echo "A full list of URLs can be found in the markdown page on Github"
            exit 0
            ;;
        p)
            PACKAGE=$OPTARG
            ;;
        P)
            LOCAL_PACKAGE=$OPTARG
            ;;
        f)
            IP=$OPTARG
            ;;
        i)
            INDEXER=true
            SPLUNK_HOME="/opt/splunk"
            ;;
        g)
            GITHUB_URL=$OPTARG
            ;;
        S)
            SPLUNK_ONLY=true
            ;;
        L)
            ADDITIONAL_LOGGING_ONLY=true
            ;;
        l)
            LOCAL=true
            GITHUB_URL="$(realpath "$OPTARG")"  # Use local path for GITHUB_URL
            ;;
        a)
            # Pass -i before this argument if on the indexer
            while true; do
                info "Indexes: ${INDEXES[*]}"
                index=$(get_input_string "Select an index: " | tr -d ' ')
                matches=false
                for value in "${INDEXES[@]}"
                do
                  [[ "$index" = "$value" ]] && matches=true
                done
                if [ "$matches" = true ]; then
                    break
                fi
                error "Invalid index: $index"
            done
            add_monitor "$OPTARG" "$index"
            exit 0
            ;;
        \?)
            error "Invalid option: $OPTARG"
            print_usage
            exit 1
            ;;
        :)
            error "Option -$OPTARG requires an argument (-h for help)"
            exit 1
            ;;
    esac
done

DEBUG_LOG_PATH=$(dirname "$DEBUG_LOG")
if [ ! -d "$DEBUG_LOG_PATH" ]; then
    sudo mkdir -p "$DEBUG_LOG_PATH"
    sudo chown root:root "$DEBUG_LOG_PATH"
    sudo chmod 700 "$DEBUG_LOG_PATH"
fi
main 2>&1 | sudo tee $DEBUG_LOG
#####################################################