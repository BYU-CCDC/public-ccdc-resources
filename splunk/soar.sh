#!/bin/bash
rhel_7="https://download.splunk.com/products/splunk_soar-unpriv/releases/6.3.0/linux/splunk_soar-unpriv-6.3.0.719-d9df3cc1-el7-x86_64.tgz"
rhel_8="https://download.splunk.com/products/splunk_soar-unpriv/releases/6.3.0/linux/splunk_soar-unpriv-6.3.0.719-d9df3cc1-el8-x86_64.tgz"
VERSION=$2
download=""

# Choose version
if [ "$VERSION" -eq 7 ]; then
    download=$rhel_7
elif [ "$VERSION" -eq 8 ]; then
    download=$rhel_8
fi

# Install SOAR
wget -O splunk_soar.tgz "$download"
tar -xzvf ./splunk_soar.tgz
sud mkdir /opt/soar
sudo ./splunk-soar/soar-prepare-system --splunk-soar-home /opt/soar