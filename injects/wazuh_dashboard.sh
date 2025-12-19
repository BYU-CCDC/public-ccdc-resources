    sudo apt install curl

curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a -i
sudo systemctl status wazuh-manager
