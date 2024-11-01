external_subnet=''
internal_subnet=''
external_interface=''

function print_banner {
    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
}

function get_input_string {
    read -r -p "$1" input
    echo "$input"
}

function get_input_list {
    local input_list=()

    while [ "$continue" != "false" ]; do
        input=$(get_input_string "Enter input: (one entry per line; hit enter to continue): ")
        if [ "$input" == "" ]; then
            continue="false"
        else
            input_list+=("$input")
        fi
    done

    # Return the list by printing it
    # Note: Bash functions can't return arrays directly, but we can print them
    echo "${input_list[@]}"
}

# check if installed and install if not yet installed
sudo which iptables &> /dev/null
iptables=$?
if [ $iptables != 0 ]; then
    sudo apk add iptables
fi

echo "[*] Saving previous config to the file: ~/old.cnf"
sudo iptables-save > ~/old.cnf

echo "[*] Configuring global variables:"
while true; do
    echo "[*] What are the first three octets of the external subnet? (Format: 0.0.0)"
    external_subnet=$(get_input_string "==> ")
    option=$(get_input_string "Is $external_subnet.0 the correct external subnet? (y/N): ")
    if [ "$option" == "y" ]; then
        break
    fi
done
while true; do
    echo "[*] What are the first three octets of the internal subnet? (Format: 0.0.0)"
    internal_subnet=$(get_input_string "==> ")
    option=$(get_input_string "Is $internal_subnet.0 the correct internal subnet? (y/N): ")
    if [ "$option" == "y" ]; then
        break
    fi
done
external_interface=$(get_input_string "What is the name of the external (WAN) network interface? ")

echo "[*] Configuring per-user NAT / firewall rules"
while true; do
    ip_addr=$(get_input_string "Enter the last octet of an internal ip address for NAT rules or 0 to quit: (Format: 10) ")
    if [ "$ip_addr" == '0' ]; then
        break
    fi
    sudo iptables -t nat -I PREROUTING -d "$external_subnet.$ip_addr" -j RETURN
    echo "[*] Which *TCP* ports should be open for incoming traffic (INPUT)?"
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -t nat -I PREROUTING -d "$external_subnet.$ip_addr" -p tcp --dport "$port" -j DNAT --to-destination "$internal_subnet.$ip_addr:$port"
    done
    echo "[*] Which *UDP* ports should be open for incoming traffic (INPUT)?"
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -t nat -I PREROUTING -d "$external_subnet.$ip_addr" -p udp --dport "$port" -j DNAT --to-destination "$internal_subnet.$ip_addr:$port"
    done
done

# echo "[*] Configuring rules for the internal network"
# sudo iptables -t nat -A PREROUTING -d "$internal_subnet.0/24" -j ACCEPT

echo "[*] Configuring logging and the netmap"
sudo iptables -t nat -A PREROUTING -d "$external_subnet.0/24" -j LOG --log-prefix "[iptables] ALLOWED TRAFFIC : " --log-level 1
sudo iptables -t nat -A PREROUTING -d "$external_subnet.0/24" -j NETMAP --to "$internal_subnet.0/24"
sudo iptables -t nat -A POSTROUTING -s "$internal_subnet.0/24" -j NETMAP --to "$external_subnet.0/24"
# sudo iptables -t nat -A POSTROUTING -o "$external_interface" -j MASQUERADE
