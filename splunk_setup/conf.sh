#!/bin/bash
if [[ $1 == "" ]]; then 
    echo "Error please provide the IP of the central splunk instance"
    exit
fi
echo "Script runs best when run as root. Switching to root user"
sudo su
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