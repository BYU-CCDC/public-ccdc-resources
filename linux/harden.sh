#!/bin/bash
os=""
lpm=""
log="/backups/harden_log.txt"
sudo_group=""

function locate_services {
    services=('mysql' 'phpmyadmin' 'apache2')
    echo "Preparing to locate services:
    -- Default added services are:"
    for item in "${services[@]}"; do
        echo "      - $item"
    done
    l="true"
    while [ "$l" != "false" ]; do
        read -r -p "Enter additional services to search for (one entry per line; hit enter to continue): " userInput

        if [[ "$userInput" == "" ]]; then
            l="false"
        else
            services+=("$userInput")
        fi
    done

    for service in "${services[@]}"; do
        result=$(locate "$service" | head -n 1)
        if [ -n "$result" ]; then
            echo "First folder containing '$service': $result"
            echo "First folder containing '$service': $result" >> $log
        else
            echo "No folder found containing '$service'."
            echo "No folder found containing '$service'." >> $log
        fi
    done
    echo "************ DONE LOCATING SERVICES ************"

}


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
            sudo_group="sudo"
            ;;
        ubuntu)
            echo "This is an Ubuntu Linux distribution (case-insensitive)."
            lpm="apt"
            os="ubuntu"
            sudo_group="sudo"            
            ;;
        fedora)
            echo "This is a Fedora-based Linux distribution (case-insensitive)."
            lpm="dnf"
            os="fedora"
            sudo_group="wheel"
            ;;
        centos)
            echo "This is a CentOS-based Linux distribution (case-insensitive)."
            lpm="yum"
            os="centos"
            sudo_group="wheel"            
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

}

function full_backup {
    backup_dirs=('/etc/apache2' '/var/www/html' '/var/lib/mysql' '/bin')
    echo -e "\nWould you like to append more directories to backup? (y/n)
    -- Default added directoriesn are:"
    for item in "${backup_dirs[@]}"; do
        echo "      - $item"
    done
    read -r option
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" != "false" ]; do
            read -r -e -p "\nEnter additional directory (one entry per line; enter  to continue script): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                backup_dirs+=("$userInput")
            fi
        done
    fi
    for dir in "${backup_dirs[@]}"; do
        if [ -d $dir ]; then
            echo "Attempting to back up $dir" >> $log
            echo "Attempting to back up $dir"
            backup "$dir"
        else
            echo "$dir was not found" >> $log
            echo "$dir was not found"
        fi
    done
    #mysql database
    echo "Do you know the mysql user password?(y/n)"
    read -r option
    if [ "$option" == 'y' ];
    then
        echo "Attempting to back up MYSQL database" >> $log
        echo "Attempting to back up MYSQL database"
        echo "enter username:"
        read -r MYSQL_USER
        echo "enter password:"
        read -r -s MYSQL_PASSWORD
        mysqldump -u "$MYSQL_USER" -p "$MYSQL_PASSWORD" --all-databases > "/backups/mysql-original-$DATE.sql"
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
        path_with_dashes=$(echo "$1" | sed 's/\//-/g') # helps preserve whats backuped without the complexity of putting it in the correct directory...just trust me
        sudo zip -r "$backup_dir/$path_with_dashes"_backup.zip "$1"
        echo "Made backup for dir: $backup_dir$1"  >> $log
        echo "Made backup for dir: $backup_dir$1"
    elif [ -f "$1" ]; then
        # If $1 is a file, copy it to the backup directory with a .bak extension
        sudo cp "$1" "$backup_dir/$(basename "$1").bak"
        echo "Made backup for file: $backup_dir/$(basename "$1").bak"  >> $log
        echo "Made backup for file: $backup_dir/$(basename "$1").bak"
    else
        echo "Either $1 doesn not exist or failed to make backup for $1"
        echo "Either $1 doesn not exist or failed to make backup for $1" >> $log
    fi
}

function harden_ssh {
    detect_os
    # Hardens ssh
    file_path="/etc/ssh/sshd_config"
    backup "$file_path"
    new_config="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/linux/sshd_config"
    wget -O sshd_config $new_config
    if [ $? -eq 0 ]; then
        sudo mv "$(pwd)"/sshd_config /etc/ssh/sshd_config
        sudo sed -i '$a\AllowUsers CCDCUser1' "$file_path"
        echo "*********** SSH config updated ***********"
        # Determine the lpm and restart command
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
    else
        echo "SSH config download failed with exit status $?."
        echo "SSH config download failed with exit status $?." >> $log
        echo "************ SSH CONFIG UPDATE FAILED! UPDATE MANUALLY ************"
        echo "************ SSH CONFIG UPDATE FAILED! UPDATE MANUALLY ************" >> $log
        sleep 3

    fi
    echo "************ SSH DONE ************"
}




function change_passwords {
    # change all non-system user passwords
    users_to_exclude=("CCDCUser1" "CCDCUser2")
    echo -e "\nWould you like to append more users to exclude? (y/n)
    -- Default excluded users are:"
    for item in "${users_to_exclude[@]}"; do
        echo "      - $item"
    done
    read -r option
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" != "false" ]; do
            read -r -e -p "\nEnter additional user (one entry per line; enter  to continue script): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                users_to_exclude+=("$userInput")
            fi
        done
    fi
    non_system_users=$(awk -F: '$3 >= 1000 && $1 != "nobody" && $1 != "nfsnobody" {print $1}' /etc/passwd)
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
    echo -e "\nWould you like to append more users to exclude from being removed from the $sudo_group group? (y/n)
    -- Default excluded users are:"
    for item in "${users_to_exclude[@]}"; do
        echo "      - $item"
    done
    read -r option
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" != "false" ]; do
            read -r -e -p "\nEnter additional user (one entry per line; enter  to continue script): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                users_to_exclude+=("$userInput")
            fi
        done
    fi
    backup "/etc/passwd"
    # Check if the user exists
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
            sudo deluser $user $sudo_group
            echo "Removed $user from $sudo_group"
            echo "Removed $user from $sudo_group" >> $log
        fi
    done
}

function disable_users {
    bash_users=('CCDCUser1')
    l="true"
    while [ "$l" != "false" ]; do
        read -r -e -p "\nEnter additional users who need bash access (one entry per line; hit enter to continue script): " userInput

        if [[ "$userInput" == "" ]]; then
            l="false"
        else
            bash_users+=("$userInput")
        fi
    done
    awk -F ':' '/bash/{print $1}' /etc/passwd | while read line; do sudo usermod -s /usr/bin/nologin $line; done
    for user in "${bash_users[@]}"; do
        sudo usermod -s /bin/bash $user;
    done
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
    sudo $lpm install -y ufw
    if [ $? -eq 0 ]; then
        default_ports=('22/tcp' '80/tcp' '443/tcp' '53/udp')
        echo "Package UFW installed successfully."
        echo "Do you want to add other ports? (y/n) 
        Defaults:"
        for item in "${default_ports[@]}"; do
            echo "      - $item"
        done
        read -r option
        if [ "$option" == "y" ]; then
            echo "What other ports need to be allowed for the firewall? (give list in a comma separated string i.e. "22/tcp,23/tcp,53/udp" )"
            # Set the IFS to a comma (,) to split the parameter
            read -r ports
            IFS=',' read -ra new_ports <<< "$ports"
            for port in "${new_ports[@]}"; do
                sudo ufw allow "$port"
            done
        fi
        #obvious ports
        for port in "${default_ports[@]}"; do
            sudo ufw allow "$port"
        done
        sudo ufw logging on
        sudo ufw limit ssh
        #enable rules
        sudo ufw enable

    else
        echo "Package UFW failed to install. Trying ip tables"
        default_ports=('22' '80' '443' '53')
        echo "Do you want to add other ports? (y/n) 
        Defaults:"
        for item in "${default_ports[@]}"; do
            echo "      - $item"
        done
        read -r option
        if [ "$option" == "y" ]; then
            echo "What other ports need to be allowed for the firewall? (give list in a comma separated string i.e. "22,23,53" )"
            # Set the IFS to a comma (,) to split the parameter
            read -r ports
            IFS=',' read -ra new_ports <<< "$ports"
            for port in "${new_ports[@]}"; do
                # general rule
                sudo iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
                sudo iptables -A OUTPUT -p tcp --sport "$port" -j ACCEPT
                echo "Rule added for port $port. (incoming & outgoing)" >> $log
                echo "Rule added for port $port. (incoming & outgoing)"

            done
            sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            sudo iptables -A INPUT -i lo -j ACCEPT # allow loopback
            sudo iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT # allow ping
            sudo iptables -A OUTPUT -j DROP # default deny outgoing
            sudo iptables -P INPUT DROP # default deny incoming
        fi
        # Save the iptables rules to make them persistent
        service iptables save
        service iptables restart
    fi
    
    
    echo "************ FIREWALL DONE ************"
}

function setup_splunk {
    detect_os
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk_setup/splunkf.sh
    sudo chmod +x splunkf.sh
    if [ $os == "ubuntu" ]; then os="debian"; fi
    if  [ $os == "fedora" ] ||   [ $os == "centos" ] ; then os="rpm"; fi

    echo "what is the forward server ip?"
    read ip
    ./splunkf.sh $os "$ip:9997"
    echo "************ SPLUNK DONE ************"
}

function full_harden {
    echo "************ BEGIN USER HARDENING ************"
    disable_users
    echo "************ BEGIN SSH HARDENING ************"
    harden_ssh
    echo "************ BEGIN FIREWALL SETUP ************"
    setup_firewall
    echo "Do you want to install a splunk forwarder? (y/n)"
    read opt
    if [ $opt == "y" ]; then echo "************ BEGIN SPLUNK SETUP ************"; setup_splunk; fi
    echo "************ BEGIN FULL BACKUP ************"
    full_backup
    echo "************ BEGIN LOCATING SERVICES ************"
    locate_services

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
#prereqs
detect_os
if id "CCDCUser1" &>/dev/null; then
    echo "CCDCUser1 already created"
else
    echo "CCDCUser1 not found. Attempting to create..."
    sudo useradd CCDCUser1
    sudo passwd CCDCUser1
    sudo usermod -aG $sudo_group CCDCUser1
fi

if command -v zip &> /dev/null; then
    echo "zip is installed. Proceeding"
else
    echo "zip is not installed. Installing..."
    sudo $lpm install -y zip
fi

#end prereqs

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
    "full_backup")
        full_backup
        sudo su CCDCUser1
        sudo mkdir /backups/
        sudo chown -R "CCDCUser1:CCDCUser1" /backups
        sudo chmod -R 744 /backups
    ;;
    *)
        echo "not an option"
    ;;

esac
