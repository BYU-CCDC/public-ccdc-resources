#!/bin/bash

#++++++++++++++++++++++++++ GLOBAL VARS ++++++++++++++++++++++++#

log_dir=""
log_file=""
backup_dir=""
os=""
lpm=""
admin_group=""
scored_users=()
scored_users_exist="true"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

####################### Support Functions #######################
function format {
    # Function takes in a string($1) and puts it into lower case
    # $1: string to convert
    # $2: y/n if n then no truncation of whitespaces (implicit accept)

    if [ "$2" == "n" ]; then
        echo "$1" | tr '[:upper:]' '[:lower:]'
    else
        lower=$(echo "$1" | tr '[:upper:]' '[:lower:]')
        echo "$lower" | tr -d ' '
    fi
}

function logger {
    # Log $1 (string) into scripts audit log

    # Redundancy in case dir does not get set
    if [ "$log_dir" == "" ]; then
        read -r -p "Enter path for harden script log location (ex. /etc/var/log ): " log_dir
        while [ ! -e "$log_dir" ]; do
            echo "$log_dir is invalid or does not exist: "
            read -r -p "Enter path for harden script log location (ex. /etc/var/log ): " log_dir
        done
    fi
    log_file="$log_dir/harden_script.log"
    if [ ! -f "$log_file" ]; then sudo touch "$log_file"; sudo chown -R "$(whoami):$(whoami)" "$log_file"; fi

    echo "$1"
    echo "$1" >> "$log_file"
}

function cleanup_files {
    #use to move used scripts to folder to help declutter home directory
    cleanup=('harden.sh' 'splunkf.sh' 'splunkf.deb')
    for file in "${cleanup[@]}"; do
        if [[ -f "$file" ]]; then sudo mv "$file" "$backup_dir/scripts/"; else logger "Couldnt cleanup $file"; fi
    done
}

function print_options {
    echo "
    Usage: $0 [OPTION]

    Options:
    full          Perform full system hardening
    firewall      Setup firewall rules
    splunk        Install Splunk forwarder
    indexer       Setup Splunk indexer
    full_backup   Perform full system backup
    decrypt       Decrypt a file
    rmsudoers     Remove all sudo users besides the ones you choose to exclude from prompt
    disable_users Disable bash access for all users besides the ones you choose to exclude from prompt
    chpass        Change all user passwords besides excluded users from prompt
    help          Display this help message
    "
}

function set_custom_password {
    l="true"
    echo "$user:$pass" | sudo chpasswd
    echo "$user:$pass" >> $HOME/passwd_changed.txt
}

function generate_word {
    # grabs a random word from the downloaded list
    shuf -n1 "$(pwd)/list.txt"
}

# Function to generate a random password in the format: word-word-word
function generate_passphrase {
    word1=$(generate_word)
    word2=$(generate_word)
    word3=$(generate_word)
    new_password="${word1}-${word2}-${word3}"
    logger "Changed password for $user"
    echo "$user:$new_password" | sudo chpasswd
    echo "$user:$new_password" >> $HOME/passwd_changed.txt    
}

function var_check {
    # A function that checks that certain vars have been set. This is important for functionality of some functions
    # that require the OS, lpm or admin groups should they be run standalone

    if [ "$log_dir" == "" ] || [ "$log_file" == "" ] || [ "$backup_dir" == "" ] ||  [ "$os" == "" ] || [ "$lpm" == "" ] || [ "$admin_group" == "" ] || [ "${#scored_users[@]}" -eq "0"  ];
        then setup
    fi
}

function decrypt_file {

    echo "************ Starting Decryption ************"
    echo "Current directory: $(pwd)" #spacing is weird i know. just trust me
    echo "What is the full path for the \"in\" file (usually ends with .enc; i.e. /path/to/file.txt.enc)? " 
    read -r -p "File Path: " file_path
    echo "What is the full path for the \"out\" file (in file excluding the .enc; i.e /path/to/file.txt)? "
    read -r -p "File Path: " dest_path
    read -r -s -p "What is the decryption password: " password
    echo " "
    
    openssl enc -d -aes-256-cbc -in "$file_path" -out "$dest_path" -k "$password"
    if [ $? -eq 0 ]; then
        echo "$file_path successfully decrypted to $dest_path"
    else
        echo "Decryption failed for some reason"
        echo "Try decrypting manually with the following command:
                openssl enc -d -aes-256-cbc -in <encrypted_file_path> -out <destination_file_path> -k <password>"
    fi
}

function check_for_scored_users {
    l="true"
    if [ $scored_users_exist == "true" ] && [ "${#scored_users[@]}" -eq "0" ]; then
        while [ "$l" == "true" ]; do
            read -r -p "Enter Scored Users Usernames: (one entry per line; hit enter to continue; enter 'none' if no scored users): " userInput
            if [ "$userInput" == "" ]; then
                l="false"
            elif [ "$userInput" == "none" ]; then
                scored_users_exist="false"
                l="false"
            else
                if id "$userInput" &>/dev/null; then
                    logger "Added $userInput to scored users array"
                    scored_users+=("$userInput")
                else
                    echo "User '$userInput' could not be found. Possible typo"
                    sleep 2
                fi
                
            fi
        done
    fi
}


####################### End Support Functions ###################
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
####################### Test Functions ##########################
function verify_test {
    # verify test results 
    # $1: current value 
    # $2: expected value

    if [ "$1" == "$2" ]; then
        echo "pass"
    else 
        echo "fail"
    fi
}

function test_functions {
    pass_count=0
    echo "Testing to_lower"
    test1=$(format "THISTEST")
    p=$(verify_test "$test1" "thistest")
    if [ "$p" == "pass" ]; then echo "------Test #1 Passed----"; pass_count+=1; else echo "-----Test #1 Failed----"; fi

}

####################### End Test Functions ######################
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
####################### Main Functions ##########################
function setup {
    # This function performs basic setup and install packages or other things to help the script not run into errors during execution

    get_os
    if id "CCDCUser1" &>/dev/null; then
        echo "CCDCUser1 already created"
    else
        echo "CCDCUser1 not found. Attempting to create..."
        sudo useradd CCDCUser1
        sudo passwd CCDCUser1
        sudo usermod -aG "$admin_group" CCDCUser1
    fi

    read -r -p "Enter path for harden script log location (ex. /var/log ): " log_dir
    while [ ! -e "$log_dir" ]; do
        echo "$log_dir is invalid or does not exist: "
        read -r -p "Enter path for log location (ex. /var/log ): " log_dir
    done
    log_file="$log_dir/harden_script.log"
    logger "Chosen harden script log location: $log_file"
    read -r -p "Enter path for backups location (ex. /var/log ): " backup_dir
    while [ ! -e "$backup_dir" ]; do
        echo "$backup_dir is invalid or does not exist: "
        read -r -p "Enter path for backups location (ex. /var/log ): " backup_dir
    done
    logger "Chosen backup directory location: $backup_dir"
    # Pre Reqs
    if command -v zip &> /dev/null; then
        echo "zip is installed. Proceeding"
    else
        echo "zip is not installed. Installing..."
        sudo $lpm install -y zip &> /dev/null
        logger "zip package installed"
    fi

    check_for_scored_users

}

function get_os {
    # This function prompts the user for the type of OS. This is necessary in order to use the correct
    # package manager, sudo groups, firewalls configs, etc.
    while true; do
        read -r -p "What is the OS based on? (Debian, RedHat, SuSE, CentOs): " os
        case $os in
            "debian"|"redhat"|"suse"|"centos")
                break ;;
            *)
                echo "Invalid option. Options are (Debian, RedHat, SuSE, CentOS). Other options are not supported" ;;
        esac
    done
    os=$(format "$os" "y")
    case $os in
        "debian")
            echo "      Selection: Debian-based"
            echo "      Package Manager: apt"
            echo "      Admin Group Name: sudo"
            read -r -p "Is this correct? (y/n): " opt
            if [ "$(format "$opt")" == "n" ]; then
                echo "Please enter correct info:"
                read -r -p "    Package Manager: " lpm
                read -r -p "    Admin Group Name: " admin_group
            else
                lpm="apt"
                admin_group="sudo"
            fi
        ;;
        "redhat")
            echo "      Selection: RedHat-based"
            echo "      Package Manager: dnf"
            echo "      Admin Group Name: wheel"
            read -r -p "Is this correct? (y/n): " opt
            if [ "$(format "$opt")" == "n" ]; then
                echo "Please enter correct info:"
                read -r -p "    Package Manager: " lpm
                read -r -p "    Admin Group Name: " admin_group
            else
                lpm="dnf"
                admin_group="wheel"
            fi

        ;;
        "suse")
            echo "      Selection: OpenSuSE"
            echo "      Package Manager: zypper"
            echo "      Admin Group Name: wheel"
            read -r -p "Is this correct? (y/n): " opt
            if [ "$(format "$opt")" == "n" ]; then
                echo "Please enter correct info:"
                read -r -p "    Package Manager: " lpm
                read -r -p "    Admin Group Name: " admin_group
            else
                lpm="zypper"
                admin_group="wheel"
            fi
        ;;
        "centos")
            echo "      Selection: CentOS"
            echo "      Package Manager: yum"
            echo "      Admin Group Name: wheel"
            read -r -p "Is this correct? (y/n): " opt
            if [ "$(format "$opt")" == "n" ]; then
                echo "Please enter correct info:"
                read -r -p "    Package Manager: " lpm
                read -r -p "    Admin Group Name: " admin_group
            else
                lpm="yum"
                admin_group="wheel"
            fi
        ;;
        *)

        ;;
    esac

}

function locate_services {
    # This function attempts to find files associated with services the user specifies
    var_check
    services=()
    echo "What services would you like to locate: "
    l="true"
    while [ "$l" == "true" ]; do
        read -r -p "Enter additional services (one entry per line; hit enter to continue): " userInput
        if [[ "$userInput" == "" ]]; then
            l="false"
        else
            services+=("$userInput")
        fi
    done
    # Search for services on the system
    for service in "${services[@]}"; do
        result=$(locate "$service" | head -n 1)
        if [ -n "$result" ]; then
            logger "First folder containing '$service': $result"
        else
            logger "No folder found containing '$service'."
        fi
    done
}


function  full_backup {
    # This function performs a full backup for all directories and files that the users adds plus the defaults listed in backup_dirs

    var_check
    sudo $lpm install -y zip &> /dev/null # redundancy to make sure we can zip files
    # Redundancy in case dir does not get set
    if [ "$backup_dir" == "" ]; then
        read -r -p "Enter path for backups location (ex. /var/log ): " backup_dir
        while [ ! -e "$backup_dir" ]; do
            echo "$backup_dir is invalid or does not exist: "
            read -r -p "Enter path for backups location (ex. /var/log ): " backup_dir
        done
    fi
    sudo mkdir "$backup_dir/backups"
    sudo chown -R "$(whoami):$(whoami)" "$backup_dir/backups"
    # Takes a backup of all specified folder plus any other folders that the user inputs
    dirs_to_backup=('/etc/apache2' '/var/www/html' '/var/lib/mysql')
    echo -e "Would you like to append more directories to backup?
    -- Default added directories are:"    
    for item in "${dirs_to_backup[@]}"; do
        echo "      - $item"
    done
    echo "      - /bin"
    read -r -p "(y/n): " option
    option=$(format "$option")
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" == "true" ]; do
            read -r -e -p "Enter directory's full path (one entry per line; enter  to continue script): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                dirs_to_backup+=("$userInput")
            fi
        done
    fi
    #backup files and directories
    for dir in "${dirs_to_backup[@]}"; do
        if [ -e "$dir" ]; then
            logger "Attempting to back up $dir"
            backup "$dir"
        else
            logger "$dir was not found"
        fi
    done
    sudo zip -r "$backup_dir/backups/bin_backup.zip" /bin &> /dev/null
    logger "Made backup for dir: /bin in $backup_dir"

    # Take MYSQL backup if it is installed on machine
    read -r -p "Is mysql installed? (y/n): " option
    if [ "$option" == 'y' ];
    then
        logger "Attempting to back up MYSQL database"
        read -r -p "enter username: " MYSQL_USER
        read -r -s -p "enter password: " MYSQL_PASSWORD
        # no space between the -p and the password is required
        touch "$backup_dir/mysql-bkp.sql"
        mysqldump -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" --all-databases > "$backup_dir/mysql-bkp.sql"
    fi

    # revert ownership to user who ran script
    sudo chown -R "$(whoami):$(whoami)" "$backup_dir"
    sudo chmod -R 744 "$backup_dir"
    echo $backup_dir
    tar -czvf $backup_dir/backups.tar.gz -C "$backup_dir" backups &>/dev/null
    l="true"
    while [ $l == "true" ]; do
        read -r -s -p "Enter Password for encrypting backups: " enc
        echo " " #new line
        read -r -s -p "Confirm Password for encrypting backups: " enc2
        if [ "$enc" == "$enc2" ]; then
            echo " "
            echo "Passwords matched"
            l="false"
        else
            echo " "
            echo "Passwords did not match. Try again..."
        fi
    done   
    openssl enc -aes-256-cbc -salt -in "$backup_dir/backups.tar.gz" -out "$backup_dir/backups.tar.gz.enc" -k "$enc"
    sudo rm "$backup_dir/backups.tar.gz"
    sudo rm -rf "$backup_dir/backups"
    echo "Backups encrypted"

}

function backup {
    # a supporting funciton for full_backup that backups the directory or file passed in as $1
    # $1: file or directory to backup
    
    if [ -d "$1" ]; then
        # If $1 is a directory, copy it recursively to the backup directory
        path_with_dashes=$(echo "$1" | sed 's/\//-/g') # helps preserve whats backuped without the complexity of putting it in the correct directory...just trust me
        sudo zip -r "$backup_dir/backups/$path_with_dashes"_backup.zip "$1" &> /dev/null
        logger "Made backup for dir: $1 in $backup_dir"
    elif [ -f "$1" ]; then
        # If $1 is a file, copy it to the backup directory with a .bak extension
        sudo cp "$1" "$backup_dir/backups/$(basename "$1").bak" &> /dev/null
        logger "Made backup for file: $backup_dir/$(basename "$1").bak"
    else
        logger "** Either $1 does not exist or failed to make backup for $1"
    fi
}

function change_passwords {
    # A supporting function for disable_users. This function can do one of three things. 
    # (1) Change passwords to a passphrase (i.e. apple-house-pants6)
    # (2) using dev/urandom to generate a complex password (jal$dng6Ni)
    # (3) set the password for all users to one password 

    var_check

    users_to_exclude=("CCDCUser1" "CCDCUser2")
    check_for_scored_users
    for scored_user in "${scored_users[@]}"; do 
        users_to_exclude+=("$scored_user")
    done
    l="true"
    while [ "$l" == "true" ]; do
        read -r -p "Would you like a passphrase or password for the new passwords? (1-passphrase; 2-password; 3-custom password): " opt1
        if [ "$opt1" = "1" ]; then
            wget -O "list.txt" "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/linux/list.txt" &> /dev/null # grab a wordlist
            if [ $? -eq 0 ]; then 
                logger "Successfully grabbed wordlist. Setting option to: Passphrase"
                opt1=1
            else
                logger "Failed to grab wordlist. Setting option to: Custom Password"
                opt1=3
            fi
            l="false"
        elif [ "$opt1" = "2" ]; then
            sudo openssl rand -base64 12 &>/dev/null
            if [ $? -eq 0 ]; then
                logger "Command test succeeded. Setting option to: Random Password "
                opt1=2
            else
                logger "Command failed. Setting option to: Custom Password"
                opt1=3
            fi
            l="false"
        elif [ "$opt1" = "3" ]; then
            logger "User Opted for custom password"
            opt1=3
            l="false"
        else
            echo "Option: $opt1 is not a valid option. Try Again."
        fi
    done

    echo -e "Would you like to append more users to exclude from a password change?
    -- Default excluded users are:"
    for item in "${users_to_exclude[@]}"; do
        echo "      - $item"
    done
    read -r -p "(y/n): " option
    option=$(echo "$option" | tr -d ' ') #truncates any spaces accidentally put in
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" == "true" ]; do
            read -r -e -p "Enter additional user (one entry per line; enter  to continue script): " userInput

            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                users_to_exclude+=("$userInput")
            fi
        done
    fi
    readarray -t non_system_users < <(awk -F: '$3 >= 1000 && $1 != "nobody" && $1 != "nfsnobody" {print $1}' /etc/passwd)    # remove user from users if user is in excluded users
    for excluded_user in "${users_to_exclude[@]}"; do
        non_system_users=("${non_system_users[@]//$excluded_user}")
    done
    # if all users are excluded no need to run through this. niche case for an almost blank machine
    if [ "${#non_system_users[@]}" != "0" ]; then
        if [ "$opt1" == "3" ]; then
            l="true"
            while [ $l == "true" ]; do
                read -r -s -p "Enter Password for user passwords: " pass
                echo " " #new line
                read -r -s -p "Confirm Password for user passwords: " pass2
                if [ "$pass" == "$pass2" ]; then
                    echo " "
                    echo "Passwords matched"
                    l="false"
                    break
                else
                    echo " "
                    echo "Passwords did not match. Try again..."
                fi
            done
            for user in "${non_system_users[@]}"; do
                if [ "$user" != "" ]; then
                    echo "$user:$pass" | sudo chpasswd
                    echo "$user:$pass" >> "$HOME/passwd_changed.txt"
                    logger "Changed password for $user"
                fi
            done
        else
            for user in "${non_system_users[@]}"; do
                if [ "$user" != "" ]; then # line 498 replaces entries with an empty string. this line checks if the current user is one of those blank strings
                    if [ "$opt1" == "1" ]; then
                        generate_passphrase
                    elif [ "$opt1" == "2" ]; then
                        new_password=$(sudo openssl rand -base64 12)
                        echo "$user:$new_password" | sudo chpasswd
                        echo "$user:$new_password" >> "$HOME/passwd_changed.txt"
                        logger "Changed password for $user"
                    else
                        echo "Error option was not set correctly"
                    fi
                fi
            done    
        fi
        # recursive check that the encryption password was typed correctly
        l="true"
        while [ $l == "true" ]; do
            read -r -s -p "Enter Password for encrypting user passwords: " enc
            echo " " #new line
            read -r -s -p "Confirm Password for encrypting user passwords: " enc2
            if [ "$enc" == "$enc2" ]; then
                echo " "
                echo "Passwords matched"
                l="false"
            else
                echo " "
                echo "Passwords did not match. Try again..."
            fi
        done
        
        openssl enc -aes-256-cbc -salt -in "$HOME/passwd_changed.txt" -out "$HOME/passwd_changed.txt.enc" -k "$enc"
        sudo rm "$HOME/passwd_changed.txt"
        echo "Password file successfully encrypted"
        if [ -f $HOME/list.txt ]; then
            read -r -p "Would you like to remove list.txt (wordlist for passwords)? (y/n):" option
            option=$(format "$option")
            if [ $option == "y" ]; then rm list.txt; fi
        fi
    else
        logger "No users in the list to modify passwords for. Skipping changing passwords"
    fi
}

function remove_sudoers {
    # A supporting function for disable users that remove any users who do not belong in the sudo group
    # You can also exclude certain users from being removed.

    var_check
    users_to_exclude=("CCDCUser1")
    check_for_scored_users
    for scored_user in "${scored_users[@]}"; do 
        users_to_exclude+=("$scored_user")
    done
    echo -e "Would you like to append more users to exclude from being removed from the $admin_group group?
-- Current excluded users are:"
    for item in "${users_to_exclude[@]}"; do
        echo "      - $item"
    done
    read -r -p "(y/n): " option
    option=$(echo "$option" | tr -d ' ') #truncates any spaces accidentally put in #truncates any spaces accidentally put in
    if [ "$option" == "y" ]; then
        l="true"
        while [ "$l" == "true" ]; do
            read -r -e -p "Enter additional user (one entry per line; enter  to continue script): " userInput
            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                users_to_exclude+=("$userInput")
            fi
        done
    fi
    backup "/etc/passwd" # in case it gets screwed up
    # Iterate through all users in the target group
    admin_members=$(getent group "$admin_group" | cut -d: -f4)
    IFS=',' read -r -a admin_group_members <<< "$admin_members"
    for excluded_user in "${users_to_exclude[@]}"; do
        admin_group_members=("${admin_group_members[@]/$excluded_user}")
    done
    for user in "${admin_group_members[@]}"; do
        # Remove the user from the group if not excluded
        if [ "$user" != "" ]; then
            if [ "$os" == "debian" ]; then
                sudo deluser "$user" "$admin_group"
                logger "Removed $user from $admin_group"
            elif [ "$os" != "debian" ]; then
                sudo gpasswd -d "$user" "$admin_group"
                logger "Removed $user from $admin_group"
            else
                logger "**Failed to remove $user from $admin_group"
            fi
        fi
    done
}

function disable_users {
    # disables users bash access by setting it to /nologin
    check_for_scored_users
    bash_users=('CCDCUser1')
    for scored_user in "${scored_users[@]}"; do 
        bash_users+=("$scored_user")
    done
    read -r -p "Would you like to remove bash access for users? (y/n): " opt
    if [ "$opt" == "y" ]; then
        echo -e "Would you like to append more users who need bash access? 
    -- Current excluded users are:"
        for item in "${bash_users[@]}"; do
            echo "      - $item"
        done
        read -r -p "(y/n): " option
        option=$(echo "$option" | tr -d ' ') #truncates any spaces accidentally put in
        if [ "$option" == "y" ]; then
            l="true"
            while [ "$l" == "true" ]; do
                read -r -e -p "Enter additional users (one entry per line; hit enter to continue script): " userInput

                if [[ "$userInput" == "" ]]; then
                    l="false"
                else
                    bash_users+=("$userInput")
                fi
            done    
        fi
        readarray -t remove_bash_access_user_list < <(awk -F ':' '/bash/{print $1}' /etc/passwd)
        for bash_user in "${bash_users[@]}"; do
            # remove users who need bash access from the to-be-removed list
            remove_bash_access_user_list=("${remove_bash_access_user_list[@]//$bash_user}")
            # make sure that the user has bash access
            sudo usermod -s /bin/bash "$bash_user"
            logger "$bash_user granted bash access"
        done
        # remove bash access from users
        for user in "${remove_bash_access_user_list[@]}"; do
            if [ "$user" != "" ]; then
                if [ -f /usr/sbin/nologin ]; then
                    sudo usermod -s /usr/sbin/nologin "$user"
                    logger "$user set to nologin";
                elif [ -f /sbin/nologin ]; then
                    sudo usermod -s /sbin/nologin "$user"
                    logger "$user set to nologin"
                else
                    logger "No usable bin for preventing bash logins aka /usr/sbin/nologin & /sbin/nologin do not exist"
            fi
        fi
        done
    fi
}

function setup_firewall {

    var_check
    default_ports=('53/udp' '9997/tcp')
    if [ "$os" == "debian" ]; then
        sudo $lpm install -y ufw &> /dev/null
        if command -v ufw &> /dev/null; then
            logger "Package UFW installed successfully"
            echo "Do you want to add other ports?"
            echo "   Defaults:"
            for item in "${default_ports[@]}"; do
                echo "      - $item"
            done
            read -r -p "(y/n): " option
            option=$(format "$option") #truncates any spaces accidentally put in
            if [ "$option" == "y" ]; then
                l="true"
                while [ "$l" == "true" ]; do
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
                logger "Rule added for port $port"
            done
            sudo ufw logging on
            sudo ufw limit ssh
            sudo ufw enable
        else
            logger "**Package UFW failed to install. Firewall will need to be configured manually**"
        fi
    else
        logger "Attempting to install firewalld"
        sudo $lpm install -y firewalld &> /dev/null
        if command -v firewalld &> /dev/null; then
            logger "Package firewalld installed successfully"
            echo "Do you want to add other ports?"
            echo "   Defaults:"
            for item in "${default_ports[@]}"; do
                echo "      - $item"
            done
            read -r -p "(y/n): " option
            option=$(format "$option") #truncates any spaces accidentally put in
            if [ "$option" == "y" ]; then
                l="true"
                while [ "$l" == "true" ]; do
                    read -r -e -p "Enter additional ports (ex. 22/tcp; hit enter to continue script): " userInput
                    if [[ "$userInput" == "" ]]; then
                        l="false"
                    else
                        default_ports+=("$userInput")
                    fi
                done
            fi
            for port in "${default_ports[@]}"; do
                sudo firewall-cmd --add-port="$port"
                logger "Rule added for port $port"
            done
            sudo firewall-cmd --add-service=dns
            sudo firewall-cmd --runtime-to-permanent
            logger "$(sudo firewall-cmd --list-all)"
            sudo firewall-cmd --reload
            sudo systemctl start firewalld
            sudo systemctl enable firewalld
        else
            logger "**Package Firewalld  failed to install. Firewall will need to be configured manually**"
        fi
    fi
}

function setup_splunk {

    var_check
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk_setup/splunk.sh
    sudo chmod +x splunk.sh
    if [ $os == "redhat" ] || [ $os == "centos" ] || [ $os == "suse" ]; then type="rpm"; else type="debian"; fi
    read -r -p "what is the forward server ip? " ip
    ./splunk.sh $type "$ip"
    cleanup_files ./splunk.sh
}

function start_function {
    # Starts the function that is passed in as $1
    # if given $2 which is true or false it will echo letting user know they are in a sub function


    l="true"
    while [ $l == "true" ]; do
        read -r -p "Would you like to execute $1? (y/n): " option
        option=$(format "$option")
        if [ "$option" == "y" ]; then
            echo " "
            echo "#+++++++++++++++++++++++++++++++ Starting $1 ++++++++++++++++++++++++++++++++#"
            echo " "
            "$1" #takes the passed in function and runs it
            echo "#+++++++++++++++++++++++++++++++ Done With $1 +++++++++++++++++++++++++++++++#"
            l="false"
        elif [ "$option" == "n" ]; then
            echo " "
            echo "#+++++++++++++++++++++++++++++++ Skipping $1 ++++++++++++++++++++++++++++++++#"
            echo " "
            l="false"
        else
            echo "Invalid option. Try Again"
        fi
    done
}

function start_script {
    # The main brain for all the script. This function takes in all the main functions listed below and runs them in the order specified
    fx=("locate_services" "disable_users" "change_passwords" "remove_sudoers" "setup_firewall" "full_backup" "setup_splunk" y)
    setup
    for funct in "${fx[@]}"; do
        start_function "$funct"
    done
    echo "#+++++++++++++++++++++++++++++++ Script Executed Successfully +++++++++++++++++++++++++++++++#"
}
####################### End Main Functions ######################
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

if [ "$EUID" == 0 ]; then
    echo "ERROR: Please run script without sudo prefix/not as root"
    exit 1
fi
# user needs sudo privileges to be able to run script
user_groups=$(groups)
if [[ $user_groups != *sudo* && $user_groups != *wheel* ]]; then
    echo "ERROR: User needs sudo privileges. User not found in sudo/wheel group"
    exit 1
fi
if [ $# -lt 1 ]; then
    print_options
    exit 1
fi

case $1 in
    "full")
        start_script
    ;;
    "firewall")
        start_function setup_firewall
    ;;
    "splunk")
        start_function setup_splunk
    ;;
    "full_backup")
        start_function full_backup
    ;;
    "decrypt")
        start_function decrypt_file
    ;;
    "chpass")
        start_function change_passwords
    ;;
    "rmsudoers")
        start_function remove_sudoers
    ;;
    "disable_users")
        start_function disable_users
    ;;
    "help")
        print_options
    ;;
    "debug")
        echo "no debug found"
    ;;
    *)
    print_options
    exit 1
    ;;
esac