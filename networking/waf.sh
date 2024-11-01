#!/bin/bash

# Download and install Nginx
sudo apt update
sudo apt install nginx

# Allow Nginx through the firewall
sudo ufw allow 'Nginx HTTP'

# Write to the Nginx configuration file
sudo echo "server {\n\tlisten:80;\n\tlisten[::]:80;\n\tserver_name 192.168.1.2;\n\tlocation / {\n\t\tproxy_pass http://192.168.1.3/;\n\t\tinclude proxy_params;\n\t}\n}" >> /etc/nginx/sites-available/configuration

# Enable the new configuration
sudo ln -s /etc/nginx/sites-available/configuration /etc/nginx/sites-enabled/

# Restart Nginx
sudo systemctl restart nginx


## Set up a WAF

# Install needed libraries
sudo apt-get install git g++ apt-utils autoconf automake build-essential libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre2-dev libtool libxml2-dev libyajl-dev pkgconf zlib1g-dev

# Install ModSecurity
cd ~
git clone --recursive https://github.com/owasp-modsecurity/ModSecurity ModSecurity
cd ModSecurity
git submodule init
git submodule update
sh build.sh
./configure --with-pcre2
make # this takes awhile
sudo make install

# Download the OWASP v3 rules
cd test/benchmark
./download-owasp-v3-rules.sh

# Download and compile the ModSecurity-Nginx connector
cd ~
git clone https://github.com/owasp-modsecurity/ModSecurity-nginx
nginx -v # Note the version
cd /opt
sudo wget http://nginx.org/download/nginx-1.24.0.tar.gz # Make the version the same
sudo tar -xvzmf nginx-1.24.0.tar.gz
cd nginx-1.24.0
./configure --add-dynamic-module=/home/reverseproxy/ModSecurity-nginx --with-compat
sudo make modules
sudo mkdir /etc/nginx/modules
sudo cp obs/ngx_http_modsecurity_module.so /etc/nginx/modules

# Add the module to Nginx
sudo "load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;" >> /etc/nginx/nginx.conf

# Get the OWASP Core Rule Set (CRS) and implement the example files
cd /opt
sudo git clone https://github.com/coreruleset/coreruleset /usr/local/modsecurity-crs
sudo mv /usr/local/modsecurity-crs/crs-setup.conf.example /usr/local/modsecurity-crs/crs-setup.conf
sudo mv /usr/local/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /usr/local/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf

# Configure ModSecurity
sudo mkdir -p /etc/nginx/modsec
sudo cp /home/reverseproxy/ModSecurity/unicode.mapping /etc/nginx/modsec/
sudo cp /home/reverseproxy/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
sudo mkdir /etc/modsecurity
sudo cp /home/reverseproxy/ModSecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo nano /etc/modsecurity/modsecurity.conf

# Turn on prevention: Change the sixth line to On
sed -i -e 's/DetectionOnly/On/g' /etc/modsecurity/modsecurity.conf

# Attach modsecurity to Nginx
echo "Include /etc/nginx/modsec/modsecurity.conf\nInclude /usr/local/modsecurity-crs/crs-setup.conf\nInclude /usr/local/modsecurity-crs/rules/*.conf\n" >> /etc/nginx/modsec/main.conf
sudo echo "server {\n\tlisten:80;\n\tlisten[::]:80;\n\tmosecurity on;\n\tmodsecurity_rules_file /etc/nginx/modsec/main.conf;\n\tserver_name 192.168.1.2;\n\tlocation / {\n\t\tproxy_pass http://192.168.1.3/;\n\t\tinclude proxy_params;\n\t}\n}" >> /etc/nginx/sites-available/configuration
sudo systemctl restart nginx