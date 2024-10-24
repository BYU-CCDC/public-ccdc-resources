#!/bin/bash
# This is to be used in case other machines dont have access to the internet. Ideally the splunk server should have internet access
# so that you can download the main server. Use this to share the splunk forwarder scripts with teammates
sudo apt install -y samba
sudo mkdir /srv/samba/splunk
sudo nano /etc/samba/smb.conf
sudo cat >> /etc/samba/smb.conf << EOF
[sambashare]
	comment = Splunk File Share	
	path = /srv/samba/splunk
	read only = yes
	browsable = yes
EOF

if id "CCDCUser1" >/dev/null 2>&1; then
    sudo smbpasswd -a CCDCUser1
else
    sudo useradd CCDCUser1
    sudo usermod -aG sudo
    sudo smbpasswd -a CCDCUser1
fi

sudo service smbd restart