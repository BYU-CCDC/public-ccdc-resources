#!/bin/bash
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
sudo chown -R CCDCUser1 /opt/splunk
sudo chgrp -R CCDCUser1 /opt/splunk
echo "Starting up splunk. Please set name to.....you know and the password to....you know"
sudo /opt/splunk/bin/splunk start --accept-license

#!/bin/bash
if [[ $1 == "" ]]; then 
    echo "Error please provide the IP of the central splunk instance"
    exit
fi
echo "Run this script as root, exit and rerun if not root user. Script will begin in 3 seconds"
sleep 3
sudo /opt/splunkforwarder/bin/splunk add forward-server $1:9997
# enables logging in mysql
path=""
if [[ -d /etc/mysql ]]; then
    if [[ -f /etc/alternatives/my.cnf ]]; then
        path="/etc/alternatives/my.cnf"
    else
        path="/etc/mysql/my.cnf"
    fi
    sudo echo "[mysqld_safe]
    log_error=/var/log/mysql/mysql_error.log

    [mysqld]
    log_error=/var/log/mysql/mysql_error.log" >> $path
    echo "***** Attempting to restart mysql *******"
    service mysql restart
fi

# these are separated in order to use indexes in splunk which increases searchability and organization
services=( '/etc/services/' '/etc/init.d' '/var/log/apache/access.log' '/var/log/apache/error.log' '/var/log/mysql/error' '/var/www/')
logs=('/var/log/auth.log' '/var/log/secure/' '/var/log/audit/audit.log')
misc=('/tmp' '/etc/passwd')

for i in "${services[@]}"; do
    if [[ -f $i || -d $i ]]; then
        sudo /opt/splunkforwarder/bin/splunk add monitor $i index="service"
        echo "$i added as a monitored file"
    else
        echo "$i does not exist"
    fi
done

for i in "${logs[@]}"; do
    if [[ -f $i || -d $i ]]; then
        sudo /opt/splunkforwarder/bin/splunk add monitor $i index="audit"
        echo "$i added as a monitored file"
    else
        echo "$i does not exist"
    fi
done

for i in "${misc[@]}"; do
    if [[ -f $i || -d $i ]]; then
        sudo /opt/splunkforwarder/bin/splunk add monitor $i index="misc"
        echo "$i added as a monitored file"
    else
        echo "$i does not exist"
    fi
done
echo "****** Restarting Splunk *******"
sudo /opt/splunkforwarder/bin/splunk restart