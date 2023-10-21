#!/bin/bash
os=""
lpm=""
log="$HOME/backups/harden_log.txt"
backup_dir="$HOME/backups"
sudo_group=""

function detect_os {
    if [ -f /etc/os-release ]; then
        # Source the file to get distribution information
        source /etc/os-release

        # Convert the distribution ID to lowercase for case-insensitive comparison
        dist_id_lower=$(echo "$ID" | tr '[:upper:]' '[:lower:]')

        case $dist_id_lower in
            debian)
                echo "This is a Debian-based Linux distribution (case-insensitive)." >> "$log"
                lpm="apt"
                os="debian"
                sudo_group="sudo"
                ;;
            ubuntu)
                echo "This is an Ubuntu Linux distribution (case-insensitive)." >> "$log"
                lpm="apt"
                os="ubuntu"
                sudo_group="sudo"            
                ;;
            fedora)
                echo "This is a Fedora-based Linux distribution (case-insensitive)." >> "$log"
                lpm="dnf"
                os="fedora"
                sudo_group="wheel"
                ;;
            centos)
                echo "This is a CentOS-based Linux distribution (case-insensitive)." >> "$log"
                lpm="yum"
                os="centos"
                sudo_group="wheel"            
                ;;
            *)
                echo "This is neither Debian-based, Ubuntu-based, Fedora-based, nor CentOS-based (case-insensitive)." >> "$log"
                exit
                ;;
        esac
    elif [ -f /etc/lsb-release ];
    then
        distrib_id=$(awk -F= '$1=="DISTRIB_ID" {gsub(/"/, "", $2); print $2}' /etc/lsb-release)
        dist_id_lower=$(echo "$distrib_id" | tr '[:upper:]' '[:lower:]')
            case $dist_id_lower in
            debian)
                echo "This is a Debian-based Linux distribution (case-insensitive)." >> "$log"
                lpm="apt"
                os="debian"
                ;;
            ubuntu)
                echo "This is an Ubuntu Linux distribution (case-insensitive)." >> "$log"
                lpm="apt"
                os="ubuntu"

                ;;
            fedora)
                echo "This is a Fedora-based Linux distribution (case-insensitive)." >> "$log"
                lpm="yum"
                os="fedora"
                ;;
            centos)
                echo "This is a CentOS-based Linux distribution (case-insensitive)." >> "$log"
                lpm="yum"
                os="centos"
                ;;
            *)
                echo "This is neither Debian-based, Ubuntu-based, Fedora-based, nor CentOS-based (case-insensitive)." >> "$log"
                exit
                ;;
        esac
    elif [ -f /etc/centos-release ]; then
        echo "This is a CentOS-based Linux distribution (case-insensitive)." >> "$log"
        lpm="yum"
        os="centos"
        sudo_group="wheel"
    else
        echo "The /etc/os-release file does not exist. Unable to determine the Linux distribution."
        echo "The /etc/os-release file does not exist. Unable to determine the Linux distribution." >> "$log"
        exit
    fi

}

function locate_services {
    services=('mysql' 'phpmyadmin' 'apache2')
    echo "Would you like to locate additional services:
    -- Default added services are:"
    for item in "${services[@]}"; do
        echo "      - $item"
    done
    read -r -p "(y/n): " option
    l="true"
    if [ "$option" == "y" ]; then
        while [ "$l" != "false" ]; do
            read -r -p "Enter additional services (one entry per line; hit enter to continue): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                services+=("$userInput")
            fi
        done

    fi
    for service in "${services[@]}"; do
        result=$(locate "$service" | head -n 1)
        if [ -n "$result" ]; then
            echo "First folder containing '$service': $result"
            echo "First folder containing '$service': $result" >> "$log"
        else
            echo "No folder found containing '$service'."
            echo "No folder found containing '$service'." >> "$log"
        fi
    done
    echo "************ DONE LOCATING SERVICES ************"

}



function full_backup {
    backup_dirs=('/etc/apache2' '/var/www/html' '/var/lib/mysql')
    echo -e "Would you like to append more directories to backup?
    -- Default added directories are:"
    for item in "${backup_dirs[@]}"; do
        echo "      - $item"
    done
    echo "      - /bin"
    read -r -p "(y/n): " option
    sudo cp -r /bin "$backup_dir/bin_copy"
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" != "false" ]; do
            read -r -e -p "Enter additional directory (one entry per line; enter  to continue script): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                backup_dirs+=("$userInput")
            fi
        done
    fi
    for dir in "${backup_dirs[@]}"; do
        if [ -d "$dir" ]; then
            backup "$dir"
            echo "Attempting to back up $dir" >> "$log"
            echo "Attempting to back up $dir"
        else
            echo "$dir was not found" >> "$log"
            echo "$dir was not found"
        fi
    done
    #mysql database
    read -r -p "Do you know the mysql user password?(y/n)" option
    if [ "$option" == 'y' ];
    then
        echo "Attempting to back up MYSQL database" >> "$log"
        echo "Attempting to back up MYSQL database"
        read -r -p "enter username: " MYSQL_USER
        read -r -s -p "enter password: " MYSQL_PASSWORD
        # no space between the p and the password is required
        touch "$HOME/backups/mysql-bkp.sql"
        mysqldump -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" --all-databases > "$HOME/backups/mysql-bkp.sql"
    fi
    # revert ownership to user who ran script
    sudo chown -R "$(whoami):$(whoami)" "$HOME/backups"
    sudo chmod -R 744 "$HOME/backups"

}

function backup {
    # Check if $HOME/backups directory exists; if not, create it
    if [ -d "$1" ]; then
        # If $1 is a directory, copy it recursively to the backup directory
        path_with_dashes=$(echo "$1" | sed 's/\//-/g') # helps preserve whats backuped without the complexity of putting it in the correct directory...just trust me
        sudo zip -r "$backup_dir/$path_with_dashes"_backup.zip "$1"
        echo "Made backup for dir: $backup_dir$1"  >> "$log"
        echo "Made backup for dir: $backup_dir$1"
    elif [ -f "$1" ]; then
        # If $1 is a file, copy it to the backup directory with a .bak extension
        sudo cp "$1" "$backup_dir/$(basename "$1").bak"
        echo "Made backup for file: $backup_dir/$(basename "$1").bak"  >> "$log"
        echo "Made backup for file: $backup_dir/$(basename "$1").bak"
    else
        echo "Either $1 doesn not exist or failed to make backup for $1"
        echo "Either $1 doesn not exist or failed to make backup for $1" >> "$log"
    fi
}

function change_passwords {
    # change all non-system user passwords
    users_to_exclude=("CCDCUser1" "CCDCUser2")
    echo -e "Would you like to append more users to exclude from a password change?
    -- Default excluded users are:"
    for item in "${users_to_exclude[@]}"; do
        echo "      - $item"
    done
    read -r -p "(y/n): " option
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" != "false" ]; do
            read -r -e -p "Enter additional user (one entry per line; enter  to continue script): " userInput

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
            echo "Changed password for $user" >> "$log"
            new_password=$(sudo openssl rand -base64 12)
            echo "$user:$new_password" | sudo chpasswd
        fi

    done
}

function remove_sudoers {
    users_to_exclude=("CCDCUser1")
    echo -e "Would you like to append more users to exclude from being removed from the $sudo_group group?
    -- Default excluded users are:"
    for item in "${users_to_exclude[@]}"; do
        echo "      - $item"
    done
    read -r -p "(y/n): " option
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" != "false" ]; do
            read -r -e -p "Enter additional user (one entry per line; enter  to continue script): " userInput

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
    for user in $(getent group $sudo_group | cut -d: -f4 | tr ',' ' '); do
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
            if [ $os == "debian" ]; then
                sudo deluser $user $sudo_group
                echo "Removed $user from $sudo_group"
                echo "Removed $user from $sudo_group" >> "$log"
            elif [ $os != "debian" ]; then
                sudo gpasswd -d $user $sudo_group
                echo "Removed $user from $sudo_group"
                echo "Removed $user from $sudo_group" >> "$log"
            else
                echo "Failed to remove $user from $sudo_group"
            fi
        fi
    done
}

function disable_users {
    bash_users=('CCDCUser1')
    
    echo -e "Would you like to append more users who need bash access? 
    -- Default excluded users are:"
    for item in "${bash_users[@]}"; do
        echo "      - $item"
    done
    l="true"
    read -r -p "(y/n): " option
    if [ "$option" == "y" ]; then
        while [ "$l" != "false" ]; do
            read -r -e -p "Enter additional users (one entry per line; hit enter to continue script): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                bash_users+=("$userInput")
            fi
        done    
    fi
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
    default_ports=('22/tcp' '80/tcp' '443/tcp' '53/udp' '9997/tcp')
    if command -v ufw &>/dev/null; then
        default_ports=('22/tcp' '80/tcp' '443/tcp' '53/udp' '9997/tcp')
        echo "Package UFW installed successfully."
        echo "Do you want to add other ports?
        Defaults:"
        for item in "${default_ports[@]}"; do
            echo "      - $item"
        done
        
        read -r -p "(y/n): " option
        if [ "$option" == "y" ]; then
            while [ "$l" != "false" ]; do
                read -r -e -p "Enter additional ports (ex. 22/tcp; hit enter to continue script): " userInput

                if [[ "$userInput" == "" ]]; then
                    l="false"
                else
                    default_ports+=("$userInput")
                fi
            done
        fi
        for port in "${default_ports[@]}"; do
            sudo ufw allow "$port"
            echo "Rule added for port $port" >> "$log"
        done
        sudo ufw logging on
        sudo ufw limit ssh
        #enable rules
        sudo ufw enable

    else
        default_ports=('22/tcp' '80/tcp' '443/tcp' '53/udp' '9997/tcp')
        echo "Package UFW failed to install. Trying firewalld instead"
        echo "Do you want to add other ports?
        -- Defaults:"
        for item in "${default_ports[@]}"; do
            echo "    - $item"
        done
        read -r -p "(y/n): " option
        if [ "$option" == "y" ]; then
            while [ "$l" != "false" ]; do
                read -r -e -p "Enter additional ports (ex. 53/udp; hit enter to continue script): " userInput

                if [[ "$userInput" == "" ]]; then
                    l="false"
                else
                    default_ports+=("$userInput")
                fi
            done
        fi
        for port in "${default_ports[@]}"; do
            sudo firewall-cmd --add-port=$port
            echo "Rule added for port $port"
            echo "Rule added for port $port" >> "$log"
        done

        # Enable established and related connections
        sudo firewall-cmd --add-service=ssh
        sudo firewall-cmd --add-service=http
        sudo firewall-cmd --add-service=https
        sudo firewall-cmd --add-service=dns

        echo "Rules added for ESTABLISHED, RELATED, loopback, ping, SSH, HTTP, HTTPS, and DNS." >> "$log"

        # Set the default zone to drop incoming traffic
        # Save the rules to make them persistent
        sudo firewall-cmd --runtime-to-permanent
        sudo firewall-cmd --list-all >> "$log"
        sudo firewall-cmd --reload
        sudo systemctl start firewalld
        sudo systemctl enable firewalld

    fi
    echo "************ FIREWALL DONE ************"
}

function setup_splunk {
    detect_os
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk_setup/splunkf.sh
    sudo chmod +x splunkf.sh
    if [ $os == "ubuntu" ]; then os="debian"; fi
    if [ $os == "fedora" ] || [ $os == "centos" ] ; then os="rpm"; fi

    echo "what is the forward server ip?"
    read ip
    ./splunkf.sh $os "$ip:9997"
    echo "************ SPLUNK DONE ************"
}

function full_harden {
    echo "************ BEGIN USER HARDENING ************"
    disable_users
    echo "************ BEGIN FIREWALL SETUP ************"
    setup_firewall
    read -r -p "Do you want to install a splunk forwarder? (y/n)" opt
    if [ $opt == "y" ]; then echo "************ BEGIN SPLUNK SETUP ************"; setup_splunk; fi
    echo "************ BEGIN FULL BACKUP ************"
    full_backup
    echo "************ BEGIN LOCATING SERVICES ************"
    locate_services

    report
    echo "************ REPORT CAN BE FOUND AT "$log" ************"
    echo "************ END OF SCRIPT ************"
    echo ""
    echo "***********************************************************"
    echo "************ SSH NEEDS TO BE HARDENED MANUALLY ************"
    echo "************        PLEASE DO SO NOW           ************"
    echo "***********************************************************"
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
if [ ! -d "$backup_dir" ]; then mkdir -p "$backup_dir"; fi
if [ ! -f "$HOME/backups/harden_log.txt" ]; then touch "$log"; fi
sudo chown -R "$(whoami):$(whoami)" "$HOME/backups"
sudo chmod -R 744 "$HOME/backups"

#end prereqs

case $1 in
    "options")
        print_options
    ;;
    "full")
        full_harden
    ;;
    "firewall")
        setup_firewall
    ;;
    "splunk")
        setup_splunk
    ;;
    "full_backup")
        full_backup
    ;;
    *)
        echo "not an option"
    ;;

esac
