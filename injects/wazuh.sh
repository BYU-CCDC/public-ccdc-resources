# 1. CLEANUP: Remove any broken previous attempts
sudo rm -f /usr/share/keyrings/wazuh.gpg
sudo rm -f /etc/apt/sources.list.d/wazuh.list

# 2. KEY: Download and install the GPG key correctly
# (We use -o to save to file directly to avoid the 'no valid OpenPGP data' error)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

# 3. REPO: Add the Wazuh repository file
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# 4. UPDATE: Refresh the package list (CRITICAL STEP)
# If this step shows errors, the install WILL fail.
sudo apt-get update

# 5. INSTALL: Install the agent
sudo WAZUH_MANAGER="192.168.220.240" apt-get install -y wazuh-agent

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
systemctl status wazuh-agent
