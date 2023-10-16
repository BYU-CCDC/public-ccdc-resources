#!/bin/bash
indexes=('misc' 'service_auth' 'service')
echo "Run this script as root, exit and rerun if not root user. Script will begin in 3 seconds"
sleep 3
spl_url="https://download.splunk.com/products/splunk/releases/9.0.4.1/linux/splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb"
if apt list | grep -q 'wget'; then 
    wget -O splunk.deb $spl_url
else
    curl -o splunk.deb $spl_url    
fi
echo "Grabbing splunk install"
echo "Currently Installing Splunk, please wait at least 2-3 minutes for completion"
sudo dpkg -i ./splunk.deb
echo "Installation should be done"
echo "alias splunk='/opt/splunk/bin/splunk'" >> ~/.bashrc
reset
sleep 3
echo "****** Starting Splunk ******"
# needed here since we will disable root after the script is run
# and it gives us full access over splunk
if id "CCDCUser1" >/dev/null 2>&1; then
    sudo chown -R CCDCUser1 /opt/splunk
    sudo chgrp -R CCDCUser1 /opt/splunk
else
    sudo useradd CCDCUser1
    sudo usermod -aG sudo
    sudo chown -R CCDCUser1 /opt/splunk
    sudo chgrp -R CCDCUser1 /opt/splunk
fi
echo "****** Adding Indexes to Splunk ******"
for i in "${indexes[@]}"; do
    sudo /opt/splunk/bin/splunk add index $i
done
echo "Starting up splunk. Please set name to.....you know and the password to....you know"
sudo /opt/splunk/bin/splunk start --accept-license
