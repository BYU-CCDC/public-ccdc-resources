#!/bin/bash
# https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/10.0/back-up-and-archive-your-indexes/back-up-indexed-data

INDEXES=( 'system' 'web' 'network' 'windows' 'misc' 'snoopy' 'ossec' 'edr' )
mode=$1

if [[ "$mode" = "backup" ]]; then
    echo "Backing up Splunk eventdata"

    echo "Rolling buckets from hot to warm"
    sudo -u splunk /opt/splunk/bin/splunk _internal call /data/indexes/main/roll-hot-buckets
    for index in "${INDEXES[@]}"; do
        sudo -u splunk /opt/splunk/bin/splunk _internal call /data/indexes/"$index"/roll-hot-buckets
    done

    echo "Stopping Splunk service"
    sudo systemctl stop Splunkd

    echo "Backing up Splunk indexes to /opt/splunk.bak/"
    sudo mkdir -p /opt/splunk.bak/
    chown -R splunk:splunk /opt/splunk.bak/

    echo "Backing up main index"
    sudo cp -rp /opt/splunk/var/lib/splunk/defaultdb/ /opt/splunk.bak/defaultdb/
    for index in "${INDEXES[@]}"; do
        echo "Backing up $index index"
        sudo cp -rp /opt/splunk/var/lib/splunk/"$index"/ /opt/splunk.bak/"$index"/
    done

    echo "Done. Please copy /opt/splunk.bak/ to a safe location."
elif [[ "$mode" = "restore" ]]; then
    echo "Restoring Splunk eventdata from /opt/splunk.bak/"
    sudo systemctl stop Splunkd
    sudo -u splunk /opt/splunk/bin/splunk clean eventdata

    for index in "${INDEXES[@]}"; do
        echo "Restoring $index index"
        sudo rm -rf /opt/splunk/var/lib/splunk/"$index"/
        sudo cp -rp /opt/splunk.bak/"$index"/ /opt/splunk/var/lib/splunk/"$index"/
    done

    echo "Done! Starting Splunk service"
    sudo systemctl start Splunkd
else
    echo "Usage: $0 {backup|restore}"
    exit 1
fi