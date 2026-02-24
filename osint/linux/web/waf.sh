#!/bin/bash
ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)

$ipt -P OUTPUT ACCEPT

RHEL() {
    # Install required packages and ModSecurity for Apache on RHEL-based systems
    echo "not implemented"
}

DEBIAN() {
    # Install required packages and ModSecurity for Apache on Debian-based systems
    apt-get update
    apt-get -y install libapache2-mod-security2

    # Enable ModSecurity in Apache
    a2enmod security2
    sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    sed -e 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
    systemctl restart apache2
}

ALPINE() {
    # Install ModSecurity for Nginx on Alpine (example)
    echo "not implemented"
    # Additional steps to integrate with Nginx if needed
}

# Detect Linux distribution and install ModSecurity
if command -v yum >/dev/null; then
    RHEL
elif command -v apt-get >/dev/null; then
    if grep -qi ubuntu /etc/os-release; then
        DEBIAN
    else
        DEBIAN  # Assuming other Debian-based distros like Debian itself
    fi
elif command -v apk >/dev/null; then
    ALPINE
else
    echo "Unsupported distribution"
    exit 1
fi

$ipt -P OUTPUT DROP