#!/usr/bin/env bash

function remove_profiles {
    print_banner "Removing Profile Files"

    sudo mv /etc/prof{i,y}le.d /etc/profile.d.bak 2>/dev/null
    sudo mv /etc/prof{i,y}le /etc/profile.bak 2>/dev/null

    for f in ".profile" ".bashrc" ".bash_login"; do
        sudo find /home /root \(
            -path "/root/*" -o -path "/home/ccdcuser1/*" -o -path "/home/ccdcuser2/*"
        \) -prune -o -name "$f" -exec sudo rm {} \;
    done
}
