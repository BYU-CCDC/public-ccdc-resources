#!/bin/bash
function build_indexer {
    indexes=('misc' 'service_auth' 'service')
    echo "Run this script as sudo user, exit and rerun if not sudo user (should be CCDCUserXX). Script will begin in 3 seconds"
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
    sudo /opt/splunk/bin/splunk restart

}

function check_user {
    if [[ "$(whoami)" != "CCDCUser1" ]]; then
        echo "Please run this with our privileged user"
        exit 1
    fi
}

################## MAIN ##################
check_user
build_indexer