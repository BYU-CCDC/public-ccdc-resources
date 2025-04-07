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

###################### NOTES ######################
## Ports ##
# Server:
# - INPUT 1514/UDP- main ossec port
# - INPUT 1515/UDP- agent auth port
# Client:
# - OUTPUT 1514/UDP- main ossec port
# - OUTPUT 1515/UDP- agent auth port
#
## Manually add an agent ##
# Server:
# - sudo $OSSEC_DIR/bin/manage_agents -a <CLIENT_IP> -n <NAME>
# - sudo $OSSEC_DIR/bin/manage_agents -e 1      # get key
# Client:
# - sudo $OSSEC_DIR/bin/manage_agents -i <KEY>
#####################################################

###################### GLOBALS ######################
IP=""
SERVER=false
OSSEC_DIR="/var/ossec"
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
LOCAL=false
PM=""
#####################################################

##################### FUNCTIONS #####################
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
        exit 1
    fi
}

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

function setup_ossec_server {
    # Generate server key signing certificate
    info "Generating server keys..."
    sudo openssl req -x509 -newkey rsa:4096 \
        -keyout $OSSEC_DIR/etc/sslmanager.key \
        -out $OSSEC_DIR/etc/sslmanager.cert \
        -days 365 \
        -subj "/C=US/ST=./L=./O=BYU-CCDC/OU=./CN=./emailAddress=." \
        -nodes > /dev/null
    sudo chown root:ossec $OSSEC_DIR/etc/sslmanager.cert
    sudo chown root:ossec $OSSEC_DIR/etc/sslmanager.key

    # Backup old configuration files
    sudo mv $OSSEC_DIR/etc/ossec.conf $OSSEC_DIR/etc/ossec.conf.bak 2>/dev/null
    sudo mv $OSSEC_DIR/etc/ossec-agent.conf $OSSEC_DIR/etc/ossec-agent.conf.bak 2>/dev/null
    sudo mv $OSSEC_DIR/etc/shared/agent.conf  $OSSEC_DIR/etc/shared/agent.conf.bak 2>/dev/null
    sudo mv $OSSEC_DIR/etc/shared/ossec-agent.conf $OSSEC_DIR/etc/shared/ossec-agent.conf.bak 2>/dev/null

    # Download custom server config
    info "Downloading custom OSSEC server configuration..."
    SERVER_CONF="$OSSEC_DIR/etc/ossec.conf"
    download $GITHUB_URL/splunk/linux/ossec.conf ./ossec.conf
    sudo mv ossec.conf $SERVER_CONF
    sudo chown root:ossec $SERVER_CONF
    sudo chmod 660 $SERVER_CONF

    # Download custom shared client config
    info "Downloading custom shared OSSEC client configuration..."
    SHARED_CONF="$OSSEC_DIR/etc/shared/agent.conf"
    download $GITHUB_URL/splunk/linux/ossec-agent-shared.conf ./agent.conf
    sed -i "s/{SERVER_IP}/$IP/" agent.conf
    sudo mv agent.conf $SHARED_CONF
    sudo chown root:ossec $SHARED_CONF
    sudo chmod 660 $SHARED_CONF

    # Start OSSEC
    info "Starting OSSEC server..."
    sudo systemctl start ossec

    # Start ossec-authd for automatic agent registration
    sudo $OSSEC_DIR/bin/ossec-authd -p 1515 -n
}

function install_ossec {
    print_banner "Installing OSSEC"

    # Check if it's already installed
    if sudo [ -e "$OSSEC_DIR" ]; then
        info "OSSEC directory already exists at $OSSEC_DIR. Skipping installation."
        return 0
    fi

    # Install dependencies
    sudo $PM install -y inotify-tools
    if [[ "$PM" != "apt-get" ]]; then
        sudo $PM install -y inotify-tools-devel
    fi

    # Install appropriate package
    if [ $SERVER == true ]; then
        # Server installation
        info "Starting OSSEC server installation..."
        sudo $PM install -y ossec-hids-server
    else
        # Client installation
        info "Starting OSSEC client installation..."
        sudo $PM install -y ossec-hids-agent
    fi

    # Check if installation was successful
    if [ $? -ne 0 ]; then
        error "Failed to install OSSEC"
        exit 1
    elif sudo [ ! -d "$OSSEC_DIR" ]; then
        error "OSSEC directory not found"
        exit 1
    else
        info "OSSEC installation completed successfully"
    fi

    # Configure OSSEC
    info "Configuring OSSEC..."
    if [ $SERVER == true ]; then
        setup_ossec_server
    else
        # Backup old configuration files
        sudo mv $OSSEC_DIR/etc/ossec.conf $OSSEC_DIR/etc/ossec.conf.bak 2>/dev/null
        sudo mv $OSSEC_DIR/etc/ossec-agent.conf  $OSSEC_DIR/etc/ossec-agent.conf.bak 2>/dev/null
        sudo mv $OSSEC_DIR/etc/shared/agent.conf  $OSSEC_DIR/etc/shared/agent.conf.bak 2>/dev/null
        sudo mv $OSSEC_DIR/etc/shared/ossec-agent.conf $OSSEC_DIR/etc/shared/ossec-agent.conf.bak 2>/dev/null
        
        # Download custom config
        info "Downloading OSSEC client configuration..."
        CLIENT_CONFIG="$OSSEC_DIR/etc/ossec.conf"
        # sudo sed -i "s/<server-ip>[\d\.]+</server-ip>/<server-ip>$IP</server-ip>/" $OSSEC_DIR/etc/ossec.conf
        download $GITHUB_URL/splunk/linux/ossec-agent-local.conf ./ossec-agent.conf
        # Replace dynamic values
        sed -i "s/{SERVER_IP}/$IP/" ossec-agent.conf
        sudo mv ossec-agent.conf $CLIENT_CONFIG
        sudo chown root:ossec $CLIENT_CONFIG
        sudo chmod 660 $CLIENT_CONFIG

        # Register agent
        sudo $OSSEC_DIR/bin/agent-auth -m $IP -p 1515

        # Start OSSEC
        info "Starting OSSEC client..."
        sudo systemctl start ossec-hids
    fi
}

function setup_ossec {
    install_ossec
}
#####################################################

######################## MAIN #######################
function main {
    # Add Atomicorp repo
    wget -q -O - https://updates.atomicorp.com/installers/atomic | sudo bash
    autodetect_os
    setup_ossec

    print_banner "End of script"
    info "Don't forget to open the necessary ports in your firewall!"
}

while getopts "f:i:g:l:" opt; do
    case $opt in
        f)
            IP=$OPTARG
            ;;
        i)
            SERVER=true
            IP="$OPTARG"
            ;;
        g)
            GITHUB_URL=$OPTARG
            ;;
        l)
            LOCAL=true
            GITHUB_URL="$(realpath "$OPTARG")"  # Use local path for GITHUB_URL
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

main
#####################################################