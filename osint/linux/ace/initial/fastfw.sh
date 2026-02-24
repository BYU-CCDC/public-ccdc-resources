#!/bin/env bash

function yesno() {
    read YESNO
    YESNO="$(tr '[:upper:]' '[:lower:]' <<<"$YESNO" | head -c1)"
    test "$YESNO" == "y" && return 0
    test "$YESNO" == "n" && return 1
    test "$1" == 'y'
    return $?
}

if [ "$(iptables --list-rules | wc -l)" -gt 3 ]; then
    echo 'It looks like there are already some firewall rules. Do you want to remove them? (y/N)'
    yesno n && iptables -F
fi

iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

echo 'Local subnet:'
read LOCAL_SUBNET

if [ -n "$SSH_CLIENT" ]; then
    echo 'SSH Detected. Whitelist client? (Y/n)'
    yesno y && iptables -A INPUT -s "$(cut -f1 -d' ' <<<"$SSH_CLIENT")" -p tcp --dport 22 -j ACCEPT
fi

echo 'DNS Server IPs: (OUTPUT udp/53)'
read DNS_IPS
for ip in $DNS_IPS; do
    iptables -A OUTPUT -d $ip -p udp --dport 53 -j ACCEPT
done

echo 'Space-seperated list of whitelisted subnets/addresses: (Both INPUT/OUTPUT)'
read WHITE_IPS
for ip in $WHITE_IPS; do
    iptables -A OUTPUT -d $ip -j ACCEPT
    iptables -A INPUT -d $ip -j ACCEPT
done

function genPortList() {
    read PORT_LIST
    for port in $PORT_LIST; do
        iptables -A "$1" -p "$2" --dport $port $3 -j ACCEPT
    done
}

for CHAIN in INPUT OUTPUT; do
    for PROTO in tcp udp; do
        echo "Space-seperated list of $CHAIN $PROTO ports/services:"
        genPortList $CHAIN $PROTO
    done
done

for CHAIN in INPUT OUTPUT; do
    for PROTO in tcp udp; do
        echo "Space-seperated list of local $CHAIN $PROTO ports/services:"
        genPortList $CHAIN $PROTO "-d $LOCAL_SUBNET"
    done
done

iptables -A INPUT -p tcp -m multiport --destination-ports=80,443,22,21,25,110,995 -m comment --comment 'Remove me' -j ACCEPT
iptables -A INPUT -s "$LOCAL_SUBNET" -p tcp -m multiport --destination-ports=3306,5432 -m comment --comment 'Remove me' -j ACCEPT
iptables -A OUTPUT -d "$LOCAL_SUBNET" -p tcp -m multiport --destination-ports=3306,5432 -m comment --comment 'Remove me' -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m comment --comment 'Remove me' -j ACCEPT

echo 'Changing policy...'
iptables -P INPUT DROP
iptables -P OUTPUT DROP

sleep 0.5
echo 'Policy changed.'
echo 'If you can see this, press Ctrl+C'
echo 'Reverting policies in 5s...'
sleep 5

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT