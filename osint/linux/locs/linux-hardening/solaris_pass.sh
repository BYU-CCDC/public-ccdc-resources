#!/bin/bash
cp /etc/shadow /etc/shadow2.bak
chmod 640 /etc/shadow2.bak

# exclude root
cat /etc/shadow | grep "root" | tee /etc/shadow
users=`getent passwd | cut -d ":" -f 1 | grep -v root`m                                                                                                      

for user in $users; do                 
    pass=`dd if=/dev/urandom count=4 bs=1 2>/dev/null | digest -a md5 | cut -c -10`          
        hash=`/usr/sfw/bin/openssl passwd -1 "$pass"`                                                                                                                            
            echo "$user:$hash:::::::" >> /etc/shadow  
                echo "$user,$pass"
                done
                echo "Old /etc/shadow stored in /etc/shadow2.bak. Delete once passwords verified to be working and uploaded to scoring engine"