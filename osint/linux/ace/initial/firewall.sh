#!/bin/bash
DNS=.5
SMTP=.10
iptables -N TRAFFICINPUT
iptables -A INPUT -s 10.128.0.0/9 -j TRAFFICINPUT
# Fix the ports variable to properly capture output
ports=$(ss -tulpn | grep -v "10.255.255.254" | grep -v "127.0.0.1" | tail -n +2 | tr -s ' ' | cut -d" " -f5 | cut -d":" -f2)

# Get the IP address details and parse for 10.x.x.x or 172.16.x.x
ip_info=$(ip a | grep -E 'inet (10\.[0-9]0|172\.16\.[0-9]0)')
box_ip=""
subnet_prefix=""
connection_ip=$(env | grep SSH_CONNECTION | cut -f 2 -d = | cut -f 1 -d " ")

iptables -A INPUT -p tcp --dport 22 -s $connection_ip -j ACCEPT

if echo "$ip_info" | grep -q '10\.'; then
    # Extract the box IP from 10.x.x.x format
    box_ip=$(echo "$ip_info" | grep '10\.' | awk '{print $2}' | cut -d/ -f1 | cut -d. -f4)
    subnet_prefix="10.$(echo "$ip_info" | grep '10\.' | awk '{print $2}' | cut -d/ -f1 | cut -d. -f2-3)"
elif echo "$ip_info" | grep -q '172\.16\.'; then
    # Extract the box IP from 172.16.x.x format
    box_ip=$(echo "$ip_info" | grep '172\.16\.' | awk '{print $2}' | cut -d/ -f1 | cut -d. -f4)
    subnet_prefix="172.16.$(echo "$ip_info" | grep '172\.16\.' | awk '{print $2}' | cut -d/ -f1 | cut -d. -f3)"
fi

# Set DNS server IP based on the detected subnet
dns_server="${subnet_prefix}${DNS}"
smtp_server="${subnet_prefix}${SMTP}"

# Fix the ports variable to properly capture output
ports=$(ss -tulpn | grep -v "10.255.255.254" | grep -v "127.0.0" | grep -v -F "[::1]" | tail -n +2 | tr -s ' ' | cut -d" " -f5 | cut -d":" -f2)

for i in $(seq 30 130); do
    iptables -A OUTPUT -p tcp --dport 3306 -d ${subnet_prefix}.$i -m state --state NEW,ESTABLISHED -j ACCEPT
done
echo $ports
iptables -A OUTPUT -d 10.120.0.0/16 -j ACCEPT
#Whitelist white team
iptables -A INPUT -s 10.120.0.0/16 -j ACCEPT
# Add rules to allow traffic only for the ports found by ss command
#DNS
iptables -A INPUT -p udp --dport 53 -d $dns_server -j ACCEPT
iptables -A INPUT -p udp --sport 53 -d $dns_server -j ACCEPT

iptables -A OUTPUT -p udp --dport 53 -d $dns_server -j ACCEPT
iptables -A OUTPUT -p udp --sport 53 -d $dns_server -j ACCEPT
#Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#max bytes
iptables -A TRAFFICINPUT -m connbytes --connbytes 15000 --connbytes-dir both --connbytes-mode bytes -j DROP

#max connections
iptables -A TRAFFICINPUT -m connlimit --connlimit-above 2 -j REJECT
iptables -A TRAFFICINPUT -m connlimit --connlimit-above 2 -j REJECT


iptables -I TRAFFICINPUT -p tcp --dport 80 -m string ! --string "Mozilla" --algo bm --to 1000 -m conntrack --ctstate RELATED,ESTABLISHED  -j DROP
iptables -A TRAFFICINPUT -p tcp --dport 80 -m string ! --string "Windows" --algo bm --to 1000 -m conntrack --ctstate RELATED,ESTABLISHED -j DROP

iptables -I TRAFFICINPUT -p tcp --dport 22 -j DROP

for port in $ports; do
    # Add conntrack rules for each port
    if [ "$port" -eq 3306 ]; then
        iptables -A TRAFFICINPUT -p tcp --dport "$port" -d "${subnet_prefix}.0/24" -m state --state NEW,ESTABLISHED -j ACCEPT
    else
        iptables -A TRAFFICINPUT -p tcp --dport "$port" -m state --state NEW,ESTABLISHED -j ACCEPT
    fi
#    iptables -A TRAFFICINPUT -p udp --dport $port -m state --state NEW,ESTABLISHED -j ACCEPT
done

for port in $ports; do
    # Add conntrack rules for each port
    iptables -I OUTPUT -p tcp --sport $port -m state --state RELATED,ESTABLISHED -j ACCEPT
#    iptables -A OUTPUT -p udp --dport $port -m state --state RELATED,ESTABLISHED -j ACCEPT
done


# Set default policy to DROP for TRAFFICINPUT chain
iptables -A TRAFFICINPUT -j DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -P INPUT DROP

if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
fi

