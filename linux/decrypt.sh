#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <backup_file> <output_dir>"
    exit 1
fi
read -rsp "Enter backups password: " password
openssl enc -aes-256-cbc -d -salt -in "$1" -out "$2/backups.tar.gz" -k "$password"
tar -xzvf "$2/backups.tar.gz" -C "$2" backups &>/dev/null
