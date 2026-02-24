

#Patches pwnkit, 
chmod 0755 /usr/bin/pkexec


#patches CVE-2023-32233
sysctl -w kernel.unprivileged_userns_clone=0
echo "kernel.unprivileged_userns_clone = 0" >> /etc/sysctl.conf
sysctl -p

