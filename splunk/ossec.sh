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

function install_ossec {
    sudo $pm install inotify-tools inotify-tools-devel
    # Server installation
    if [ $SERVER == true ]; then
        # Install OSSEC
        sudo $pm install ossec-hids-server

        # Download custom config
        sudo rm $OSSEC_DIR/etc/ossec.conf 2>/dev/null
        sudo rm $OSSEC_DIR/etc/ossec-agent.conf 2>/dev/null
        download $GITHUB_URL/splunk/linux/ossec.conf $OSSEC_DIR/etc/ossec.conf
        sudo chown root:ossec $OSSEC_DIR/etc/ossec.conf
        sudo chmod 660 $OSSEC_DIR/etc/ossec.conf

        # Generate server key signing certificate
        sudo openssl req -x509 -newkey rsa:4096 \
            -keyout $OSSEC_DIR/etc/sslmanager.key \
            -out $OSSEC_DIR/etc/sslmanager.cert \
            -days 365 \
            -subj "/C=US/ST=./L=./O=BYU-CCDC/OU=./CN=./emailAddress=." \
            -nodes
        sudo chown root:ossec $OSSEC_DIR/etc/sslmanager.cert
        sudo chown root:ossec $OSSEC_DIR/etc/sslmanager.key

        # Start OSSEC
        sudo systemctl start ossec

        # Start ossec-authd for automatic agent registration
        sudo $OSSEC_DIR/bin/ossec-authd -p 1515 -n
    
    # Client installation
    else
        # Install OSSEC
        sudo $pm install ossec-hids-agent

        # Download custom config
        sudo rm $OSSEC_DIR/etc/ossec.conf 2>/dev/null
        sudo rm $OSSEC_DIR/etc/ossec-agent.conf 2>/dev/null
        download $GITHUB_URL/splunk/linux/ossec-agent.conf ./ossec-agent.conf

        # Replace dynamic values
        sed -i "s/{SERVER_IP}/$IP/" ossec-agent.conf

        if [[ -f "/var/log/syslog" ]]; then
            # If /var/log/syslog exists, use it for syslog location
            sed -i "s/{SYSLOG_LOCATION}/\/var\/log\/syslog/" ossec-agent.conf
        elif [[ -f "/var/log/messages" ]]; then
            # If /var/log/messages exists, use it for syslog location
            sed -i "s/{SYSLOG_LOCATION}/\/var\/log\/messages/" ossec-agent.conf
        else
            error "Neither /var/log/syslog nor /var/log/messages found. Please set the syslog location manually."
        fi

        if [[ -f "/var/log/auth.log" ]]; then
            # If /var/log/auth.log exists, use it for auth log location
            sed -i "s/{AUTHLOG_LOCATION}/\/var\/log\/auth.log/" ossec-agent.conf
        elif [[ -f "/var/log/secure" ]]; then
            # If /var/log/secure exists, use it for auth log location
            sed -i "s/{AUTHLOG_LOCATION}/\/var\/log\/secure/" ossec-agent.conf
        else
            error "Neither /var/log/auth.log nor /var/log/secure found. Please set the auth log location manually."
        fi

        mv ossec-agent.conf $OSSEC_DIR/etc/ossec.conf
        sudo chown root:ossec $OSSEC_DIR/etc/ossec.conf
        sudo chmod 660 $OSSEC_DIR/etc/ossec.conf

        # Register agent
        sudo $OSSEC_DIR/bin/agent-auth -m $IP -p 1515

        # Start OSSEC
        sudo systemctl start ossec-hids
    fi
}

function main {
    # Add Atomicorp repo
    wget -q -O - https://updates.atomicorp.com/installers/atomic | sudo bash
    autodetect_os
    install_ossec
}

while getopts "f:ig:l:" opt; do
    case $opt in
        f)
            IP=$OPTARG
            ;;
        i)
            SERVER=true
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