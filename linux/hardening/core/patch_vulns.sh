#!/usr/bin/env bash

function patch_vulnerabilities {
    print_banner "Patching Vulnerabilities"

    sudo chmod 0755 /usr/bin/pkexec
    sudo sysctl -w kernel.unprivileged_userns_clone=0
    echo "kernel.unprivileged_userns_clone = 0" | sudo tee -a /etc/sysctl.conf >/dev/null
    sudo sysctl -p >/dev/null
}
