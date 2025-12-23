# 1. Ask the user for the IP address of the device.
read -p "Enter the IP address you want to allow for RDP: " TARGET_IP

# 2. Check if the user actually typed something (Basic validation)
if [ -z "$TARGET_IP" ]; then
    echo "Error: No IP address entered. Exiting."
    exit 1
fi

sudo apt update
# 3. Install a specific GUI for the RDP'd device. 
sudo apt install xfce4 xfce4-goodies -y
# 4. install xrdp
sudo apt install xrdp -y
# 5. create RDP sessions
echo "xfce4-session" | tee ~/.xsession

sudo systemctl restart xrdp
# 6. create a firewall rule to allow RDP
sudo iptables -A INPUT -s "$TARGET_IP/32" -p tcp --dport 3389 -j ACCEPT
