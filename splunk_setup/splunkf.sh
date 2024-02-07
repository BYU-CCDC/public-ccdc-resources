#!/bin/bash
rpm="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-linux-2.6-x86_64.rpm"
linux="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-x86_64.tgz"
deb="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-linux-2.6-amd64.deb"
arm="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-armv8.tgz"
s90="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-s390x.tgz"
ppcle="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-ppc64le.tgz"
mac="https://download.splunk.com/products/universalforwarder/releases/9.0.1/osx/splunkforwarder-9.0.1-82c987350fde-darwin-universal2.tgz"
freebsd="https://download.splunk.com/products/universalforwarder/releases/9.0.1/freebsd/splunkforwarder-9.0.1-82c987350fde-FreeBSD11-amd64.tgz"
z="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-SunOS-x86_64.tar.Z"
p5p="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-solaris-intel.p5p"
sparcz="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-SunOS-sparc.tar.Z"
sparcp5p="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-solaris-sparc.p5p"
aix="https://download.splunk.com/products/universalforwarder/releases/9.0.1/aix/splunkforwarder-9.0.1-82c987350fde-AIX-powerpc.tgz"
###################### INDEXES ######################

# In Bash 4.3.8, associative arrays were introduced, but they do not support nested structures directly so we have to be hacky about it to ensure older versions work
# put name of index in the first [0] position
# INDEX NAMES SHOULD CORRESPOND TO LINE 2 IN THE BUILD.SH SCRIPT OTHERWISE THE SPLUNK INDEXER WILL NOT RECIEVE LOGS CORRECTLY
service_monitors=( 'service' '/etc/services/' '/etc/init.d' '/var/log/apache/access.log' '/var/log/apache/error.log' '/var/log/mysql/error' '/var/www/' ) #service
service_auth_monitors=( 'service_auth' '/var/log/auth.log' '/var/log/secure/' '/var/log/audit/audit.log' ) # service_auth
misc_monitors=( 'misc' '/tmp' '/etc/passwd' ) # misc

#####################################################

function print_sources {
    index=("$@")
    isFirst=true
    for value in "${index[@]}"; do
        if [ "$isFirst" = true ]; then
            isFirst=false # ignores the name of the index and only outputs the logs sources
        else
            options+="$value, "
        fi
    done
    options=${options%, }  # Remove the trailing comma and space
    echo "       -- $options"
}

function add_monitors {
    log_sources=("$@")
    isFirst=true
    echo "Would you like to add additional log locations for index: ${log_sources[0]}"
    echo "   -- Default log locations are:"
    print_sources  "${log_sources[@]}"
    read -r -p "(y/n): " option
    option=$(echo "$option" | tr -d ' ') #truncates any spaces accidentally put in
    l="true"
    if [ "$option" == "y" ]; then
        while [ "$l" != "false" ]; do
            read -r -p "Enter additional logs sources for index: ${log_sources[0]} (one entry per line; hit enter to continue): " userInput
            if [[ "$userInput" == "" ]]; then
                l="false"
            else
                log_sources+=("$userInput")
            fi
        done
    fi
    isFirst=true
    for source in "${log_sources[@]}"; do
        if [ "$isFirst" = true ]; then
            isFirst=false # ignores the name of the index and only adds the logs sources
        else
            sudo /opt/splunkforwarder/bin/splunk add monitor "$source" -index "${log_sources[0]}"
        fi
    done
}

function install_forwarder {
    if [[ ! -d /opt/splunkforwarder ]]; then
        case "$1" in
            debian )
                print_banner "Installing forwarder for Debian"
                echo
                sudo wget -O splunkf.deb "$deb"
                sudo dpkg -i ./splunkf.deb
            ;;
            linux )
                print_banner "Installing generic forwarder (.tgz) for linux*"
                echo
                sudo wget -O splunkf.tgz "$linux"
                echo "******* Extracting to /opt/splunkforwarder *******"
                sleep 2
                sudo tar -xvf splunkf.tgz -C /opt/ &> /dev/null
                sudo chown -R "$(whoami):$(whoami)" /opt/splunkforwarder
            ;;
            rpm )
                print_banner "Installing forwarder for rpm based machines"
                echo
                sudo wget -O splunkf.rpm "$rpm"
                sudo yum install ./splunkf.rpm -y
            ;;
            # prints the url in case there are problems with the install
            -p)
                case $2 in
                    debian)
                        echo $deb
                        exit
                    ;;
                    rpm)
                        echo $rpm
                        exit
                    ;;
                    linux)
                        echo $linux
                        exit
                    ;;
                    *)
                        echo "url not found"
                        exit
                    ;;
                esac
            ;;
            # prints urls of the lesser known/used splunk forwarders
            other )
                echo "Linux ARM: $arm"
                echo 
                echo "Linux s390: $s90"
                echo
                echo "Linux PPCLE: $ppcle"
                echo
                echo "OSX M1/Intel: $mac"
                echo
                echo "FreeBSD: $freebsd"
                echo
                echo "Solaris:
                - .Z (64-bit): $z
                - .p5p (64-bit): $p5p
                - Sparc .Z: $sparcz
                - Sparc .p5p: $sparcp5p"
                echo
                echo "AIX: $aix"
                exit
            ;;
            # catch all statement that provides the user with a list of potential command line options
            *)
                print_options
            ;;
        esac
    else
            echo "Install already exists. Proceeding to configure forwarder"
    fi
}



function add_mysql_logs {
    if [ -d "/etc/mysql/my.cnf" ]; then
        MYSQL_CONFIG="/etc/mysql/my.cnf"  # Adjust the path based on your system

        # Log file paths
        GENERAL_LOG="/var/log/mysql/mysql.log"
        ERROR_LOG="/var/log/mysql/error.log"

        # Enable General Query Log
        echo "[mysqld]" >> "$MYSQL_CONFIG"
        echo "general_log = 1" >> "$MYSQL_CONFIG"
        echo "general_log_file = $GENERAL_LOG" >> "$MYSQL_CONFIG"

        # Enable Error Log
        echo "log_error = $ERROR_LOG" >> "$MYSQL_CONFIG"

        # Restart MySQL service
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart mysql
        elif command -v service &> /dev/null; then
            sudo service mysql restart
        else
            echo "Error: Unable to restart MySQL. Please restart the MySQL service manually."
        fi
    else
        echo "ERROR: Could not find correct mysql log"
    fi
}


function setup_forwarder {
    sleep 2
    if [[ $2 == "" ]]; then 
        echo "Error please provide the IP of the central splunk instance"
        echo "Usage: ./splunkf.sh <option> <forward-server-ip>"
        exit
    fi
    install_forwarder "$1" "$2"
    sudo chown -R CCDCUser1 /opt/splunkforwarder #give privs to our user
    sudo chgrp -R CCDCUser1 /opt/splunkforwarder
    sudo /opt/splunkforwarder/bin/splunk start --accept-license
    print_banner "Adding Indexes"
    add_monitors "${misc_monitors[@]}"
    add_monitors "${service_auth_monitors[@]}"
    add_monitors "${service_monitors[@]}"
    add_mysql_logs
    #add forward server
    print_banner "Adding Forwarder server"
    sudo /opt/splunkforwarder/bin/splunk add forward-server $2:9997
    echo "############# Restarting Splunk #############*"
    sleep 3
    sudo /opt/splunkforwarder/bin/splunk restart
    print_banner "End of Script"

}


function print_options {

    echo
    echo "ERROR: Usage: ./splunkf.sh <option> <forward-server-ip>"
    echo "OPTIONS: 
    -> debian
    -> linux (general tgz file)
    -> rpm (red hat distros)
    -> other (shows list of other forwarder urls)
    -> -p (prints the specified url debian, linux or rpm in case something is not working)
            " # trust the indents
    exit 1
}

function print_banner {

    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
    sleep 2

}

function check_prereqs {
    # user should not be root or run `sudo ./splunf.sh` doing so makes the splunk forwarder install be owned by root
    if [ "$EUID" == 0 ]; then
        echo "ERROR: Please run script without sudo prefix/not as root"
        exit 1
    fi

    #user needs sudo privileges to be able to run script
    user_groups=$(groups)
    if [[ $user_groups != *sudo* && $user_groups != *wheel* ]]; then
        echo "ERROR: User needs sudo privileges. User not found in sudo/wheel group"
        exit 1
    fi

    # check if home directory exists for current user. Home directory is needed for running splunk commands since the commands are aliases for http request methods;
    # the .splunk directory contains this auth token so without it splunk fails to install
    if [ ! -d /home/"$(whoami)" ]; then
        echo "No home directory for user $(whoami). Creating home directory"
        sudo mkdir -p /home/"$(whoami)"
    fi
    
    if [ "$#" != 3 ]; then
        echo "ERROR: Usage: $0 <option> <ip_address>"
        print_options
    fi

    if [[ ! $3 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "ERROR: Invalid IP address format: $3"
        exit 1
    fi
    
}

################################# MAIN #################################
echo "Beginning Script"
check_prereqs "$0" "$1" "$2"
setup_forwarder "$1" "$2"
############################### END MAIN ###############################