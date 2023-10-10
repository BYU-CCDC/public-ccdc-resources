#!/bin/bash
os=""
lpm=""


function detect_os {
if [ -f /etc/os-release ]; then
    # Source the file to get distribution information
    source /etc/os-release

    # Convert the distribution ID to lowercase for case-insensitive comparison
    dist_id_lower=$(echo "$ID" | tr '[:upper:]' '[:lower:]')

    case $dist_id_lower in
        debian)
            echo "This is a Debian-based Linux distribution (case-insensitive)."
            lpm="apt"
            os="debian"
            ;;
        ubuntu)
            echo "This is an Ubuntu Linux distribution (case-insensitive)."
            lpm="apt"
            os="ubuntu"

            ;;
        fedora)
            echo "This is a Fedora-based Linux distribution (case-insensitive)."
            lpm="dnf"
            os="fedora"
            ;;
        centos)
            echo "This is a CentOS-based Linux distribution (case-insensitive)."
            lpm="yum"
            os="centos"
            ;;
        *)
            echo "This is neither Debian-based, Ubuntu-based, Fedora-based, nor CentOS-based (case-insensitive)."
            exit
            ;;
    esac
elif [ -f /etc/lsb-release ];
then
    distrib_id=$(awk -F= '$1=="DISTRIB_ID" {gsub(/"/, "", $2); print $2}' /etc/lsb-release)
    dist_id_lower=$(echo "$distrib_id" | tr '[:upper:]' '[:lower:]')
        case $dist_id_lower in
        debian)
            echo "This is a Debian-based Linux distribution (case-insensitive)."
            lpm="apt"
            os="debian"
            ;;
        ubuntu)
            echo "This is an Ubuntu Linux distribution (case-insensitive)."
            lpm="apt"
            os="ubuntu"

            ;;
        fedora)
            echo "This is a Fedora-based Linux distribution (case-insensitive)."
            lpm="dnf"
            os="fedora"
            ;;
        centos)
            echo "This is a CentOS-based Linux distribution (case-insensitive)."
            lpm="yum"
            os="centos"
            ;;
        *)
            echo "This is neither Debian-based, Ubuntu-based, Fedora-based, nor CentOS-based (case-insensitive)."
            exit
            ;;
    esac

else
    echo "The /etc/os-release file does not exist. Unable to determine the Linux distribution."
    exit
fi

}
function backup {
    local backup_dir="/backups"

    # Check if /backups directory exists; if not, create it
    if [ ! -d "$backup_dir" ]; then
        sudo mkdir -p "$backup_dir"
    fi

    if [ -d "$1" ]; then
        # If $1 is a directory, copy it recursively to the backup directory
        sudo cp -r "$1" "$backup_dir/"
    else
        # If $1 is a file, copy it to the backup directory with a .bak extension
        sudo cp "$1" "$backup_dir/$(basename "$1").bak"
    fi

    sudo chattr +i "$1" # Make file immutable
}

function harden_ssh {
    # Hardens ssh
    file_path="/etc/ssh/sshd_config"
    backup "$file_path"
    old_lines=( '.*PermitRootLogin yes' '.*RSAAuthentication yes' '.*PubkeyAuthentication yes' '.*UsePAM yes' )
    new_lines=( 'PermitRootLogin no' 'RSAAuthentication no' 'PubkeyAuthentication no' 'UsePAM no' )

    # Replace old lines with new lines in the sshd_config file
    for index in "${!old_lines[@]}"; do
        old_line="${old_lines[index]}"
        new_line="${new_lines[index]}"
        sudo sed -i "s/$old_line/$new_line/g" "$file_path"
    done

    # Add a line to allow a specific user (replace CCDCUser1 with your desired user)
    sudo echo "AllowUsers CCDCUser1" >> "$file_path"

    echo "RESTARTING SSH"
    sleep 1

    # Determine the operating system
    if [ "$os" == "fedora" ] || [ "$os" == "centos" ]; then
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart sshd
        else
            sudo service sshd restart
        fi
    elif [ "$os" == "debian" ] || [ "$os" == "ubuntu" ]; then
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart ssh
        else
            sudo service ssh restart
        fi
    else
        echo "************ SSH was not restarted. Restart Manually ************"
        sleep 3
    fi
}


function change_passwords {
    # change all non-system user passwords
    users_to_exclude=("CCDCUser1" "CCDCUser2")
    non_system_users=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)
    for user in $non_system_users; do
        # Generate a random password (change as needed)
        exclude=false
        for excluded_user in "${users_to_exclude[@]}"; do
            if [ "$user" == "$excluded_user" ]; then
                exclude=true
                break
            fi
        done

        # done change passwd for user if user is in excluded users
        if [ "$exclude" == "false" ]; then
            new_password=$(openssl rand -base64 12)
            echo "$user:$new_password" | sudo chpasswd
        fi

    done


}

function remove_sudoers {
    users_to_exclude=("CCDCUser1")

    # Iterate through all users in the target group
    for user in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
        # Check if the user should be excluded
        exclude=false
        for excluded_user in "${users_to_exclude[@]}"; do
            if [ "$user" == "$excluded_user" ]; then
                exclude=true
                break
            fi
        done

        # Remove the user from the group if not excluded
        if [ "$exclude" == "false" ]; then
            sudo deluser $user sudo
            echo "Removed $user from sudo"
        fi
    done
}

function disable_users {
    awk -F ':' '/bash/{print $1}' /etc/passwd | while read line; do sudo usermod -s /usr/bin/nologin $line; done
    change_passwords
    remove_sudoers
    
}
function print_options {
    echo "options are:
        full - full automated hardening
        ssh - ssh only harden
        pass - change passwords of all non-system users"
}
function report {
    # Get server name (hostname)
    server_name=$(hostname)

    # Get OS type and version
    os_info=$(cat /etc/os-release)
    os_type=$(grep -oP 'ID=\K\w+' <<< "$os_info")
    os_version=$(grep -oP 'VERSION_ID="\K[0-9.]+' <<< "$os_info")

    # Get list of running services (systemd-based systems)
    services=$(systemctl list-units --type=service --state=running | awk '{print $1}')

    # Print the collected information
    echo "Server Name: $server_name"
    echo "OS Type: $os_type"
    echo "OS Version: $os_version"
    echo -e "Running Services:\n$services"
}

function setup_firewall {
    # Set the IFS to a comma (,) to split the parameter
    echo "What ports need to be allowed? (give list in a comma separated string i.e. "22,23,53" )"
    read ports
    IFS=',' read -ra values <<< "$ports"
    sudo $lpm install -y ufw
    #obvious ports
    sudo ufw allow 22/tcp
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw logging on
    sudo ufw limit ssh


    # Iterate through the array of values
    for value in "${values[@]}"; do
        sudo ufw allow $value
    done
}

function setup_splunk {
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk_setup/splunkf.sh
    sudo chmod +x splunkf.sh
    if [ $os == "ubuntu" ]; then os="debian"; fi
    echo "what is the forward server ip?"
    read ip
    ./splunkf.sh $os "$ip:9997"
}

function full_harden {

    detect_os
    echo "returned from dtect"
    disable_users
    echo "returned from dis"
    harden_ssh
    echo "returned from hard"

    setup_firewall
    echo "returned from fire"
    echo "Do you want to install a splunk forwarder? (y/n)"
    read opt
    if [ $opt == "y" ]; then setup_splunk; fi
    report
}
######## MAIN ########

# Check if there are at least two arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 [OPTION]"
    print_options
    exit 1
fi
case $1 in
    "options")
        print_options
    ;;
    "full")
        full_harden
    ;;
    "ssh")
        harden_ssh
    ;;
    "pass")
        change_passwords
    ;;
    "splunk")
        setup_splunk
    ;;
    *)
        echo "not an option"
    ;;

esac









