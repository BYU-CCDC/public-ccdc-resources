#!/bin/env bash
# Credit to DSU for the original version of this script

function yesno() {
    read YESNO
    YESNO="$(tr '[:upper:]' '[:lower:]' <<<"$YESNO" | head -c1)"
    test "$YESNO" == "y" && return 0
    test "$YESNO" == "n" && return 1
    test "$1" == 'y'
    return $?
}

function genPortList() {
    read PORT_LIST
    for port in $PORT_LIST; do
        iptables -A "$1" -p "$2" --dport $port $3 -j ACCEPT
    done
}

if [ "$EUID" != 0 ]; then
    echo "Please run script with sudo prefix or as root"
    exit 1
fi

# Stop other firewalls, courtesy of chat
if command -v ufw >/dev/null 2>&1; then
    ufw disable
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
        systemctl stop firewalld
        systemctl disable firewalld
    fi
fi

# TODO: preserve docker rules
if [ "$(iptables --list-rules | wc -l)" -gt 3 ]; then
    echo 'It looks like there are already some firewall rules. Do you want to remove them? (y/N)'
    yesno n && iptables -F
fi

iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment "related/established"
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment "related/established"

iptables -A INPUT -i lo -j ACCEPT -m comment --comment "loopback"
iptables -A OUTPUT -o lo -j ACCEPT -m comment --comment "loopback"

iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT -m comment --comment "ping"
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT -m comment --comment "ping"

echo 'Would you like to allow traffic to Splunk? (Y/n)'
if yesno y; then
    echo 'Splunk indexer IP:'
    read SPLUNK_IP
    iptables -A OUTPUT -d $SPLUNK_IP -p tcp --dport 9997 -j ACCEPT -m comment --comment "Splunk"
    # iptables -A OUTPUT -d $SPLUNK_IP -p udp --dport 1514 -j ACCEPT
    # iptables -A OUTPUT -d $SPLUNK_IP -p udp --dport 1515 -j ACCEPT
else
    echo 'Would you like to allow traffic to a syslog server? (y/N)'
    yesno n && {
        echo 'Syslog server IP:'
        read SYSLOG_IP
        iptables -A OUTPUT -d $SYSLOG_IP --dport 514 -p tcp -j ACCEPT -m comment --comment "syslog"
        iptables -A OUTPUT -d $SYSLOG_IP --dport 514 -p udp -j ACCEPT -m comment --comment "syslog"
    }
fi

echo 'Space-separated list of DNS Server IPs (OUTPUT udp/53):'
read DNS_IPS
for ip in $DNS_IPS; do
    iptables -A OUTPUT -d $ip -p udp --dport 53 -j ACCEPT -m comment --comment "DNS"
done

echo 'Would you like to allow all HTTP/HTTPS traffic? (Y/n)'
yesno y && {
    iptables -A OUTPUT -m multiport -p tcp --dports 80,443 -j ACCEPT -m comment --comment "HTTP/S"
}

for CHAIN in INPUT OUTPUT; do
    for PROTO in tcp udp; do
        echo "Space-separated list of $CHAIN $PROTO ports/services:"
        genPortList $CHAIN $PROTO
    done
done

echo 'Is this machine bound to the domain? If so, this script assumes the DC IP is the same as your DNS server. (y/N)'
yesno n && {
    # echo 'IP of the Domain Controller: '
    # read DC_IP
    echo 'Opening AD ports...'
    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements
    iptables -A OUTPUT -d $DNS_IPS -m multiport -p tcp --dports 88,389 -j ACCEPT -m comment --comment "AD"
    iptables -A OUTPUT -d $DNS_IPS -m multiport -p udp --dports 88,389 -j ACCEPT -m comment --comment "AD"
    iptables -A OUTPUT -d $DNS_IPS -m multiport -p tcp --dports 139,445 -j ACCEPT -m comment --comment "AD"
}

echo 'Would you like to whitelist traffic to a specific IP or subnet? (y/N)'
yesno n && {
    echo 'IP or subnet: '
    read IP
    for PROTO in tcp udp; do
        echo "Space-separated list of INPUT $PROTO ports/services from whitelisted IP/subnet:"
        genPortList INPUT $PROTO "-s $IP"
    done
    for PROTO in tcp udp; do
        echo "Space-separated list of OUTPUT $PROTO ports/services to whitelisted IP/subnet:"
        genPortList OUTPUT $PROTO "-d $IP"
    done
}

iptables -A OUTPUT -j LOG --log-prefix "iptables: "

echo 'Changing policy...'
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# TODO: iptables save

sleep 0.5
echo 'Policy changed.'
echo 'If you can see this, press Ctrl+C'
echo 'Reverting policies in 5s...'
sleep 5

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
