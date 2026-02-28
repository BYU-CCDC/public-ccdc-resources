#!/bin/bash

# OS template credit to CPP

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# for curl ssl errors, supply --cacert flag with the .pem file
# to configure system wide, rename .pem file to .crt and do the normal process to add it

#####################################
# crt format is required for ubuntu #
#####################################
#######################################################
# pem format is used inside browser under authorities #
#######################################################

# can change to a prompt
#read -p "Enter the URL of the certificate file to download: (e.g., http://1.1.1.1/certificate.crt)" PATCH_URL

# can change to a prompt
#read -p "Enter the IP and port of the proxy (e.g., 10.120.0.200:8080): " PROXY

PROXY=http://192.168.1.107:8000
PATCH_URL=http://192.168.1.107:9000/mitmproxy-ca-cert.crt
PEM_URL=http://192.168.1.107:9000/mitmproxy-ca-cert.pem

PATH=$PATH:/usr/sbin/

RHEL(){
    echo "Setting up for RHEL"
    yum install -y ca-certificates
    yum install -y curl
    # Install certificate
    curl -o cert.crt --proxy "$PROXY" "$PATCH_URL"
    curl -o cert.pem --proxy "$PROXY" "$PEM_URL"
    cp cert.crt /etc/pki/ca-trust/source/anchors/
    cp cert.pem /etc/pki/ca-trust/source/anchors/
    chmod +x /etc/pki/ca-trust/source/anchors/cert.crt
    chmod +x /etc/pki/ca-trust/source/anchors/cert.pem
    update-ca-trust

    # configure for yum
    echo "proxy=$PROXY" | sudo tee -a /etc/yum.conf >/dev/null

    # configure for environment
    #echo "export http_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
    #echo "export https_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
    #echo "export ftp_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
    #echo "export no_proxy=\"localhost,127.0.0.1\"" | sudo tee -a /etc/environment >/dev/null
    source /etc/environment

    # configure for bash
    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc
    source ~/.bashrc
    echo "If there are still issues, verify the http_proxy and https_proxy env variables were set (source ~/.bashrc)"
}


DEBIAN(){
    echo "Setting up proxy for debian"
    # download and install certificate
    apt update
    apt install -y ca-certificates
    apt install -y curl
    curl -o cert.crt --proxy "$PROXY" "$PATCH_URL"
    curl -o certPem.pem --proxy "$PROXY" "$PEM_URL"
    mv certPem.pem certPem.crt
    mkdir /usr/share/ca-certificates/extra
    cp cert.crt /usr/share/ca-certificates/extra/cert.crt
    cp cert.crt /etc/ssl/certs/
    cp certPem.crt /usr/share/ca-certificates/extra/certPem.crt
    cp certPem.crt /etc/ssl/certs/
    dpkg-reconfigure ca-certificates
    update-ca-certificates
    if [ $? -ne 0 ]; then
         /usr/sbin/update-ca-certificates
    fi

    #configure for apt
    touch /etc/apt/apt.conf.d/proxy.conf
    echo "Acquire::http::Proxy \"$PROXY\";" | sudo tee -a /etc/apt/apt.conf.d/proxy.conf >/dev/null
    echo "Acquire::https::Proxy \"$PROXY\";" | sudo tee -a /etc/apt/apt.conf.d/proxy.conf >/dev/null

    #configure for environment
    echo "http_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
    echo "https_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
    echo "ftp_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
    echo "no_proxy=\"localhost,127.0.0.1\"" | sudo tee -a /etc/environment >/dev/null
    source /etc/environment

    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc

    echo "If there are still issues, verify the http_proxy and https_proxy env variables were set (source ~/.bashrc)"
    source ~/.bashrc
}

UBUNTU(){
    echo "Setting up proxy for Ubuntu"
    DEBIAN
}

# TODO
ALPINE(){
    apk add --no-cache ca-certificates

    # Install certificate
    curl -o cert.pem --proxy "http://$PROXY" "$PATCH_URL"
    cp cert.pem /usr/local/share/ca-certificates/
    update-ca-certificates

    # Configure proxy
    echo "http://$PROXY/alpine/latest/main" | sudo tee -a /etc/apk/repositories >/dev/null
    echo "https://$PROXY/alpine/latest/main" | sudo tee -a /etc/apk/repositories >/dev/null
    echo "http://$PROXY/alpine/latest/community" | sudo tee -a /etc/apk/repositories >/dev/null
    echo "https://$PROXY/alpine/latest/community" | sudo tee -a /etc/apk/repositories >/dev/null

    #configure for environment
    echo "export http_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
    echo "export https_proxy=\"$PROXY\"" | sudo tee -a /etc/environment >/dev/null
}

# not important
SLACK(){
    echo "good luck soldier"
}

if command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    if $(cat /etc/os-release | grep -qi Ubuntu); then
        UBUNTU
    else
        DEBIAN
    fi
elif command -v apk >/dev/null ; then
    ALPINE
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -i slackware) ; then
    SLACK
fi