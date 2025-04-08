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

if [ "$(iptables --list-rules | wc -l)" -gt 3 ]; then
    echo 'It looks like there are already some firewall rules. Do you want to remove them? (y/N)'
    yesno n && iptables -F
fi

iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

echo 'Splunk indexer IP: '
read SPLUNK_IP
iptables -A OUTPUT -d $SPLUNK_IP -p tcp --dport 9997 -j ACCEPT

if [ -n "$SSH_CLIENT" ]; then
    echo 'SSH Detected. Whitelist client? (Y/n)'
    yesno y && iptables -A INPUT -s "$(cut -f1 -d' ' <<<"$SSH_CLIENT")" -p tcp --dport 22 -j ACCEPT
fi

echo 'DNS Server IPs: (OUTPUT udp/53)'
read DNS_IPS
for ip in $DNS_IPS; do
    iptables -A OUTPUT -d $ip -p udp --dport 53 -j ACCEPT
done

for CHAIN in INPUT OUTPUT; do
    for PROTO in tcp udp; do
        echo "Space-seperated list of $CHAIN $PROTO ports/services:"
        genPortList $CHAIN $PROTO
    done
done

echo 'Would you like to whitelist traffic to a specific IP or subnet? (y/N)'
yesno n && {
    echo 'IP or subnet: '
    read IP
    for PROTO in tcp udp; do
        echo "Space-seperated list of INPUT $PROTO ports/services from whitelisted IP/subnet:"
        genPortList INPUT $PROTO "-s $IP"
    done
    for PROTO in tcp udp; do
        echo "Space-seperated list of OUTPUT $PROTO ports/services to whitelisted IP/subnet:"
        genPortList OUTPUT $PROTO "-d $IP"
    done
}

echo 'Changing policy...'
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

sleep 0.5
echo 'Policy changed.'
echo 'If you can see this, press Ctrl+C'
echo 'Reverting policies in 5s...'
sleep 5

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
