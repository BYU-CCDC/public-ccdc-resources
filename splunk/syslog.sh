#!/bin/bash
firewall_ip=$1
sudo apt-get install rsyslog
echo "module(load=\"imupd\")
input(type=\"imudp\" port=\"514\")
if \$fromhost-ip == '$firewall_ip' and \$msg contains 'AccessControlRuleAction' then /var/log/fw_network.log
& stop
if \$fromhost-ip == '$firewall_ip' then /var/log/fw_system.log" | sudo tee -a /etc/rsyslog.conf
sudo service rsyslog restart
sudo service rsyslog status
sudo -u splunk /opt/splunk/bin/splunk add monitor /var/log/fw_network.log -index network -hostname "CISCO_FTD"
sudo -u splunk /opt/splunk/bin/splunk add monitor /var/log/fw_system.log -index system -hostname "CISCO_FTD"