#!/bin/bash
os=""
lpm=""

log="./harden_log.txt"

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
    echo "The /etc/os-release file does not exist. Unable to determine the Linux distribution." >> $log
    exit
fi

echo $os $lpm >> $log


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
        echo "Made backup: $backup_dir/$1"  >> $log
    else
        # If $1 is a file, copy it to the backup directory with a .bak extension
        sudo cp "$1" "$backup_dir/$(basename "$1").bak"
        echo "Made backup: $backup_dir/$(basename "$1").bak"  >> $log
        
    fi
    sudo chattr +i "$backup_dir/$(basename "$1").bak" # Make backup file/directory immutable
    echo "Made backup: $backup_dir/$(basename "$1") immutable"  >> $log
}

function harden_ssh {
    detect_os
    # Hardens ssh
    file_path="/etc/ssh/sshd_config"
    backup "$file_path"
    old_lines=( '.*PermitRootLogin yes' '.*PermitRootLogin without-password' '.*RSAAuthentication yes' '.*PubkeyAuthentication yes' '.*UsePAM yes' )
    new_lines=( 'PermitRootLogin no' 'PermitRootLogin no' 'RSAAuthentication no' 'PubkeyAuthentication no' 'UsePAM no' )

    # Replace old lines with new lines in the sshd_config file
    for index in "${!old_lines[@]}"; do
        old_line="${old_lines[index]}"
        new_line="${new_lines[index]}"
        sudo sed -i "s/$old_line/$new_line/g" "$file_path"
    done

    # Add a line to allow a specific user (replace CCDCUser1 with your desired user)
    sudo sed -i '$a\AllowUsers CCDCUser1' "$file_path"
    echo "*********** SSH config updated ***********"
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
        echo "************ SSH was not able to restart. Restart Manually ************"
        sleep 3
    fi
    echo "************ SSH DONE ************"
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
            echo "Changed password for $user" >> $log
            new_password=$(sudo openssl rand -base64 12)
            echo "$user:$new_password" | sudo chpasswd
        fi

    done


}

function remove_sudoers {
    users_to_exclude=("CCDCUser1")
    backup /etc/passwd
    # Check if the user exists
    for username in "${users_to_exclude[@]}";
        do
            if id "$username" &>/dev/null; then
                echo "excluding CCDCUser1"
            else
                echo "CCDCUser1 not found in sudoers. Adding user...."
                sudo useradd CCDCUser1
                sudo passwd CCDCUser1
                sudo usermod -aG sudo CCDCUser1
            fi
    done
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
            echo "Removed $user from sudo" >> $log
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
        pass - change passwords of all non-system users
        backup '/dir1,/dir2/dir3,/dir1/file.txt' - backup directories
        splunk - setup splunk forwarder"
}
function report {
    # Get server name (hostname)
    server_name=$(hostname)

    # Get OS type and version
    os_info=$(cat /etc/os-release)
    os_type=$(grep -oP 'ID=\K\w+' <<< "$os_info")
    os_version=$(grep -oP 'VERSION_ID="\K[0-9.]+' <<< "$os_info")

    # Get list of running services (systemd-based systems)
    if command -v systemctl &> /dev/null; then
        echo -e "Running Services:\n$(systemctl list-units --type=service --state=running | awk '{print $1}')"
    else
        echo -e "Running Services:\n$(service --status-all)"
    fi
    echo "Server Name: $server_name"
    echo "OS Type: $os_type"
    echo "OS Version: $os_version"

    echo "************ END REPORT ************"

}

function setup_firewall {
    detect_os
    # Set the IFS to a comma (,) to split the parameter
    echo "What ports need to be allowed for the firewall? (give list in a comma separated string i.e. "22,23,53" )"
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
    echo "************ FIREWALL DONE ************"
}

function setup_splunk {
    detect_os
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk_setup/splunkf.sh
    sudo chmod +x splunkf.sh
    if [ $os == "ubuntu" ]; then os="debian"; fi
    echo "what is the forward server ip?"
    read ip
    ./splunkf.sh $os "$ip:9997"
    echo "************ SPLUNK DONE ************"
}

function full_harden {
    detect_os
    echo "************ BEGIN SSH HARDENING ************"
    harden_ssh
    echo "************ BEGIN FIREWALL SETUP ************"
    setup_firewall
    echo "Do you want to install a splunk forwarder? (y/n)"
    read opt
    if [ $opt == "y" ]; then echo "************ BEGIN SPLUNK SETUP ************"; setup_splunk; fi
    echo "************ BEGIN USER HARDENING ************"
    disable_users # placed here bc if the user running the script is removed from 
                  # the sudoers before end of execution theres a possibility the script will fail
    report
    echo "************ REPORT CAN BE FOUND AT $log ************"
    echo "************ END OF SCRIPT ************"
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
    "splunk")
        setup_splunk
    ;;
    "backup")
        # Check if the array argument is provided
        if [ -z "$2" ]; then
            echo "No array provided as an argument for backup. format should be \"/dir1,/dir2/file.txt,/dir3/dir2/\""
            exit 1
        fi
        IFS=','
        # Split the argument into an array
        read -a my_array <<< "$1"
        # Display the array elements
        for element in "${my_array[@]}"; do
            backup "$element"
        done
    ;;
    *)
        echo "not an option"
    ;;

esac









