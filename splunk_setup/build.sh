#!/bin/bash
echo "Script runs best when run as root. Switching to root user"
sudo su
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
sudo chown -R CCDCUser1 /opt/splunk
sudo chgrp -R CCDCUser1 /opt/splunk
echo "Starting up splunk. Please set name to.....you know and the password to....you know"
sudo /opt/splunk/bin/splunk start --accept-license




