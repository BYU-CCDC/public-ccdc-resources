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
# index names should correspond to line 1 in the build.sh script otherwise the splunk indexer will not recieve logs correctly
service_indexes=( 'service' '/etc/services/' '/etc/init.d' '/var/log/apache/access.log' '/var/log/apache/error.log' '/var/log/mysql/error' '/var/www/' ) #service
service_auth_indexes=( 'service_auth' '/var/log/auth.log' '/var/log/secure/' '/var/log/audit/audit.log' ) # service_auth
misc_indexes=( 'misc' '/tmp' '/etc/passwd' ) # misc

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
    options=""
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
                echo "******* Installing forwarder for Debian ********"
                echo
                sudo wget -O splunkf.deb "$deb"
                sudo dpkg -i ./splunkf.deb
            ;;
            linux )
                echo "******* Installing generic forwarder(.tgz) for linux *******"
                echo
                sudo wget -O splunkf.tgz "$linux"
                sudo tar -xfvz splunkf.tgz -C /opt/
            ;;
            rpm )
                echo "******* Installing forwarder for rpm based machines *******"
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
                echo "Usage: ./splunkf.sh <option> <forward-server-ip>"
                echo "OPTIONS:
                    -> debian
                    -> linux (general tgz file)
                    -> rpm
                    -> other (shows list of other forwarder urls)
                    -> -p (prints the specified url debian, linux or rpm in case something is not working)
                    "
                exit
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
    echo "Run this script as sudo user, exit and rerun if not sudo user (should be CCDCUser1). Script will begin in 3 seconds"
    sleep 3
    if [[ $2 == "" ]]; then 
        echo "Error please provide the IP of the central splunk instance"
        echo "Usage: ./splunkf.sh <option> <forward-server-ip>"
        exit
    fi
    echo "############# Beginning Forwarder Install #############"
    install_forwarder "$1" "$2"
    sudo chown -R CCDCUser1 /opt/splunkforwarder #give privs to our user
    sudo chgrp -R CCDCUser1 /opt/splunkforwarder
    sudo /opt/splunkforwarder/bin/splunk start --accept-license

    echo "############# Adding Monitors #############"
    add_monitors "${misc_indexes[@]}"
    add_monitors "${service_auth_indexes[@]}"
    add_monitors "${service_indexes[@]}"
    add_mysql_logs

    echo "############# Adding Forward Server #############*"
    sudo /opt/splunkforwarder/bin/splunk add forward-server $2:9997
    echo "############# Restarting Splunk #############*"
    sudo /opt/splunkforwarder/bin/splunk restart

}

function check_user {
    if [[ "$(whoami)" != "CCDCUser1" ]]; then
        echo "Please run this with our privileged user"
        exit 1
    fi
}

################################# MAIN #################################
check_user
setup_forwarder "$1" "$2"
############################### END MAIN ###############################