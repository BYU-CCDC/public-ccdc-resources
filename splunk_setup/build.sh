#!/bin/bash

###################### INDEXES ######################
indexes=('misc' 'service_auth' 'service')
service_monitors=( 'service' '/etc/services/' '/etc/init.d' '/var/log/apache/access.log' '/var/log/apache/error.log' '/var/log/mysql/error' '/var/www/' ) # service
service_auth_monitors=( 'service_auth' '/var/log/auth.log' '/var/log/secure/' '/var/log/audit/audit.log' ) # service_auth
misc_monitors=( 'misc' '/tmp' '/etc/passwd' ) # misc

#####################################################

function print_sources {
    index=("$@")
    isFirst=true
    for value in "${index[@]}"; do
        if [ "$isFirst" = true ]; then
            isFirst=false # ignores the name of the index and only outputs the logs sources
        else
            options+="$value, "
        fi
    done
    options=${options%, }  # Remove the trailing comma and space
    echo "       -- $options"
}

function build_indexer {

    sleep 3
    spl_url="https://download.splunk.com/products/splunk/releases/9.0.4.1/linux/splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb"
    echo "############# Installing Splunk #############"
    if [[ ! -d /opt/splunk ]]; then
        if command -v wget &> /dev/null; then
            wget -O splunk.deb $spl_url
        else
            curl -o splunk.deb $spl_url
        fi
        sudo dpkg -i ./splunk.deb
        echo "############# Starting Splunk #############"
        echo "Starting up splunk. Please set name to.....you know and the password to....you know"
        sudo /opt/splunk/bin/splunk start --accept-license
    else
        echo "Install already exists. Proceeding to configure indexer"
        echo "Verifying Splunk. If prompted, please set username to.....you know and the password to....you know"
        sudo /opt/splunk/bin/splunk start --accept-license
    fi
    sudo chown -R CCDCUser1 /opt/splunk
    sudo chgrp -R CCDCUser1 /opt/splunk
    echo "############# Adding Splunk Indexes #############"
    sudo /opt/splunk/bin/splunk enable listen 9997
    for i in "${indexes[@]}"; do
        sudo /opt/splunk/bin/splunk add index "$i"
    done
    echo "############# Installing Searches #############"
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk_setup/savedsearches.conf
    sudo mkdir -p /opt/splunk/etc/users/splunk/search/local/
    sudo cp /opt/splunk/etc/users/splunk/search/local/savedsearches.conf /opt/splunk/etc/users/splunk/search/local/savedsearches.bk
    sudo mv ./savedsearches.conf /opt/splunk/etc/users/splunk/search/local/savedsearches.conf
    echo "############# Adding Monitors #############"
    add_monitors "${misc_monitors[@]}"
    add_monitors "${service_auth_monitors[@]}"
    add_monitors "${service_monitors[@]}"
    sudo /opt/splunk/bin/splunk restart

}

function add_monitors {
    log_sources=("$@")
    isFirst=true
    echo "The following questions pertain to this host system....."
    sleep 2
    echo "Would you like to add additional log locations for index: ${log_sources[0]}"
    echo "   -- Default log locations are:"
    print_sources  "${log_sources[@]}"
    read -r -p "(y/n): " option
    option=$(echo "$option" | tr -d ' ') #truncates any spaces accidentally put in
    l="true"
    if [ "$option" == "y" ]; then
        while [ "$l" != "false" ]; do
            read -r -p "Enter additional logs sources for index: ${log_sources[0]} (one entry per line; hit enter to continue): " userInput
            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                log_sources+=("$userInput")
            fi
        done
    fi
    isFirst=true
    for source in "${log_sources[@]}"; do
        if [ "$isFirst" = true ]; then
            isFirst=false # ignores the name of the index and only adds the logs sources
        else
            sudo /opt/splunk/bin/splunk add monitor "$source" -index "${log_sources[0]}"
        fi
    done
}

function check_prereqs {
    # user should not be root or run `sudo ./splunf.sh` doing so makes the splunk forwarder install be owned by root
    if [ "$EUID" == 0 ]; then
        echo "Please run script without sudo prefix/not as root"
        exit 1
    fi

    # check if home directory exists for current user. Home directory is needed for running splunk commands since the commands are aliases for http request methods;
    # the .splunk directory contains this auth token so without it splunk fails to install
    if [ ! -d /home/"$(whoami)" ]; then
        echo "No home directory for user $(whoami). Creating home directory"
        sudo mkdir -p /home/"$(whoami)"
    fi
}

################## MAIN ##################
check_prereqs
build_indexer