#!/bin/bash
#THIS IS A TEMPLATE FOR IPTABLES


# ONLY if you have FTP

#modprobe ip_conntrack_ftp
#echo "net.netfilter.nf_conntrack_helper=1" >> /etc/sysctl.conf
#sysctl -p

I() { iptables $@; }
I -F; I -X
I -P INPUT DROP; I -P OUTPUT DROP; I -P FORWARD DROP
I -A INPUT  -i lo -j ACCEPT
I -A OUTPUT -o lo -j ACCEPT
#in
I -A INPUT  -p tcp -m multiport --dports 22,80,x,y -j ACCEPT
I -A OUTPUT -p tcp -m multiport --sports 22,80,x,y -j ACCEPT
#out
I -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

#dns
I -A OUTPUT -p udp --dport 53 -j ACCEPT

# FOR UBUNTU 22:
I -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# FOR UBUNTU 20:
#I -A INPUT  -m state --ctstate RELATED,ESTABLISHED -j ACCEPT

# FOR FEDORA 36
#I -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT