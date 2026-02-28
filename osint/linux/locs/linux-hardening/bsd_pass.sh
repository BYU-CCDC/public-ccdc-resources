#!/bin/sh
for u in $(getent passwd | grep -v "root" | cut -d ":" -f1); do
    p=`tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo ''`
        echo "$p" | pw mod user $u -h 0 2>/dev/null
            echo "$u:$p"
            done