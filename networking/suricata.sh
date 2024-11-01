
# LOG='/var/log/ccdc/harden.log'
pm=""
sudo_group=""
ccdc_users=( "ccdcuser1" "ccdcuser2" )
debug="false"

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


function detect_system_info {
    print_banner "Detecting system info"
    echo "[*] Detecting package manager"

    sudo which apt-get &> /dev/null
    apt=$?
    sudo which dnf &> /dev/null
    dnf=$?
    sudo which zypper &> /dev/null
    zypper=$?
    sudo which yum &> /dev/null
    yum=$?

    if [ $apt == 0 ]; then
        echo "[*] apt/apt-get detected (Debian-based OS)"
        echo "[*] Updating package list"
        sudo apt-get update
        pm="apt-get"
    elif [ $dnf == 0 ]; then
        echo "[*] dnf detected (Fedora-based OS)"
        pm="dnf"
    elif [ $zypper == 0 ]; then
        echo "[*] zypper detected (OpenSUSE-based OS)"
        pm="zypper"
    elif [ $yum == 0 ]; then
        echo "[*] yum detected (RHEL-based OS)"
        pm="yum"
    else
        echo "[X] ERROR: Could not detect package manager"
        exit 1
    fi

    echo "[*] Detecting sudo group"

    groups=$(compgen -g)
    if echo "$groups" | grep -q '^sudo$'; then
        echo '[*] sudo group detected'
        sudo_group='sudo'
    elif echo "$groups" | grep -q '^wheel$'; then
        echo '[*] wheel group detected'
        sudo_group='wheel'
    else
        echo '[X] ERROR: could not detect sudo group'
	exit 1
    fi
}

function setup_suricata() {
    # echo "You will need to know the network interface name before running this script"

    if [ $pm == "apt-get" ]

    ### Install Suricata ###
    sudo apt install suricata
    sudo suricata-update

    ### Start Suricata ###
    sudo systemctl enable suricata
    sudo systemctl start suricata

    ### Try to automate the Yaml file?
    :' 
    Example yaml file:
        vars:
            address-groups:
                HOME_NET: "[173.122.0.0/12,167.253.0.0/16,192.168.0.0/16,10.3.0.0/8]"

            port-groups:
                FILE_DATA_PORTS: "[$HTTP_PORTS,110,143,443,51820]"
                TCP_PORTS: "[1723,1701]"
                UDP_PORTS: "[500,4500,1194]"

            af-packet:
            - interface: nordlynx

            netmap:
            - interface: nordlynx
    
    So for yaml, we will need the interface name, port groups (we can just take comma separate lists), lists of subnet addresses?
    '
}
