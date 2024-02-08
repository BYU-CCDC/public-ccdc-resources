#!/bin/bash
# Usage: ./splunk.sh <option> <forward-server-ip>
# Use `indexer` as the forward-server-ip to install the indexer

# Prints script options
function print_options {
    echo
    echo "Usage: ./splunk.sh <option> <forward-server-ip>"
    echo "Use \`indexer\` as the forward-server-ip to install the indexer"
    echo "OPTIONS: 
    -> debian
    -> linux (general tgz file)
    -> rpm (red hat distros)
    -> other (shows list of other forwarder urls)
    -> -p (prints the specified url debian, linux or rpm in case something is not working)
            " # trust the indents
    exit 1
}

if [ "$#" != 2 ]; then
    print_options
fi

###################### DOWNLOAD URLS ######################
IP="$2"
if [ $IP == "indexer" ]; then
    rpm="https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-1fff88043d5f.x86_64.rpm"
    linux="https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-1fff88043d5f-Linux-x86_64.tgz"
    deb="https://download.splunk.com/products/splunk/releases/9.0.1/linux/splunk-9.0.1-82c987350fde-linux-2.6-amd64.deb"
    SPLUNKDIR="/opt/splunk"
else
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
    SPLUNKDIR="/opt/splunkforwarder"
fi
#####################################################

###################### INDEXES ######################
# INDEX NAMES SHOULD CORRESPOND TO LINE 2 IN THE BUILD.SH SCRIPT OTHERWISE THE SPLUNK INDEXER WILL NOT RECIEVE LOGS CORRECTLY
INDEXES=( 'service' 'service_auth' 'network' 'misc' )
#####################################################

# Prints text in a banner
# Arguments:
#   $1: Text to print
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

# Checks that correct arguments were provided to script
function check_prereqs {
    # user should not be root or run `sudo ./splunf.sh` doing so makes the splunk forwarder install be owned by root
    if [ "$EUID" == 0 ]; then
        echo "[*] ERROR: Please run script without sudo prefix/not as root"
        exit 1
    fi

    # user needs sudo privileges to be able to run script
    user_groups=$(groups)
    if [[ $user_groups != *sudo* && $user_groups != *wheel* ]]; then
        echo "[*] ERROR: User needs sudo privileges. User not found in sudo/wheel group"
        exit 1
    fi

    # check if home directory exists for current user. Home directory is needed for running splunk commands since the commands are aliases for http request methods;
    # the .splunk directory contains this auth token so without it splunk fails to install
    if [ ! -d /home/"$(whoami)" ]; then
        echo "[*] No home directory for user $(whoami). Creating home directory"
        sudo mkdir -p /home/"$(whoami)"
    fi

    if ! command -v curl &>/dev/null; then
        echo "[*] ERROR: Please install curl before using this script"
        exit 1
    fi

    if [ "$#" != 3 ]; then
        print_options
    fi
    
    if [ $IP != "indexer" ]; then
        if [[ ! $3 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "[*] ERROR: Invalid IP address format: $3"
            print_options
        fi
    fi
}

# Downloads and installs correct version for distribution
function install_splunk {
    # If splunk does not already exist:
    if [[ ! -d $SPLUNKDIR ]]; then
        # Determine distribution type and install
        case "$1" in
            debian )
                print_banner "Installing for Debian"
                echo
                sudo wget -O splunk.deb "$deb"
                sudo dpkg -i ./splunk.deb
            ;;
            linux )
                print_banner "Installing generic (.tgz) for linux*"
                echo
                sudo wget -O splunk.tgz "$linux"
                echo "******* Extracting to $SPLUNKDIR *******"
                sleep 2
                sudo tar -xvf splunk.tgz -C /opt/ &> /dev/null
            ;;
            rpm )
                print_banner "Installing for rpm based machines"
                echo
                sudo wget -O splunk.rpm "$rpm"
                sudo yum install ./splunk.rpm -y
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
        echo "[*] Install already exists. Proceeding to configure splunk."
    fi
}

# Special function only called when setting up indexer
function setup_indexer {
    print_banner "Configuring Indexer"

    echo "[*] Adding listening port 9997"
    sudo /opt/splunk/bin/splunk enable listen 9997

    echo "[*] Adding Indexes"
    for i in "${INDEXES[@]}"; do
        sudo /opt/splunk/bin/splunk add index "$i"
    done

    echo "[*] Installing Searches"
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk_setup/savedsearches.conf
    sudo mkdir -p /opt/splunk/etc/users/splunk/search/local/
    if sudo cp /opt/splunk/etc/users/splunk/search/local/savedsearches.conf /opt/splunk/etc/users/splunk/search/local/savedsearches.bk &>/dev/null; then
        echo "[*] Successfully backed up old savedsearches.conf as savedsearches.bk"
    fi
    sudo mv ./savedsearches.conf /opt/splunk/etc/users/splunk/search/local/savedsearches.conf
}

# Installs splunk
function setup_splunk {
    sleep 2
    if [[ $2 == "" ]]; then 
        echo "[*] ERROR: Please provide the IP of the central splunk instance"
        echo "Usage: ./splunk.sh <option> <forward-server-ip>"
        exit
    fi
    install_splunk "$1" "$2"
    sudo $SPLUNKDIR/bin/splunk start --accept-license
    if [ $IP == "indexer" ]; then
        setup_indexer
    fi
}

# Checks for existence of a file or directory and add it as a monitor if it exists
# Arguments:
#   $1: Path of log source
#   $2: Index name
function add_monitor {
    source=$1
    index=$2
    if [ -e "${source}" ]; then
        sudo $SPLUNKDIR/bin/splunk add monitor "$source" -index "$index"
        # echo "[*] Added monitor for ${source}"
    else
        echo "[*] ERROR: No file or dir found at ${source}"
    fi
}

# Adds monitors for system logs
function add_system_logs {
    print_banner "Adding various system logs (some of these will fail due to distribution differences)"

    INDEX="service"
    add_monitor "/etc/services" "${INDEX}"
    add_monitor "/etc/systemd/" "${INDEX}"
    add_monitor "/etc/init.d/" "${INDEX}"
    add_monitor "/etc/profile.d/" "${INDEX}"
    add_monitor "/var/log/cron" "${INDEX}"

    INDEX="service_auth"
    add_monitor "/var/log/auth.log" "${INDEX}"
    add_monitor "/var/log/secure" "${INDEX}"
    add_monitor "/var/log/audit/audit.log" "${INDEX}"

    INDEX="misc"
    add_monitor "/tmp/" "${INDEX}"
    add_monitor "/etc/passwd" "${INDEX}"
    add_monitor "/var/log/syslog" "${INDEX}"
    add_monitor "/var/log/messages" "${INDEX}"
}

# Adds monitors for firewall logs
function add_firewall_logs {
    print_banner "Adding firewall logs"
    INDEX="network"
    
    if command -v firewalld &>/dev/null; then
        echo "[*] firewalld detected"
        FIREWALL_LOG="/var/log/firewalld"

        echo "[*] Enabling firewalld logging"
        sudo firewall-cmd --set-log-denied=all

        echo "[*] Adding firewalld error logs"
        add_monitor "${FIREWALL_LOG}" "${INDEX}"
        echo "[*] firewalld access logs contained in /var/log/messages (already added)"
    elif command -v ufw &>/dev/null; then
        echo "[*] ufw detected"
        FIREWALL_LOG="/var/log/ufw.log"

        echo "[*] Enabling ufw logging"
        sudo ufw logging low

        echo "[*] Adding monitors for ufw logs"
        # sudo touch "${FIREWALL_LOG}"
        add_monitor "${FIREWALL_LOG}" "${INDEX}"
        echo "[*] ufw logs also contained in /var/log/syslog"
    elif command -v iptables &>/dev/null; then\
        echo "[*] iptables detected"
        FIREWALL_LOG="/var/log/iptables.log"

        echo "[*] Enabling iptables logging"
        LOGGING_LEVEL=1
        # Not sure if the order of where this rule is placed in the chain matters or not
        sudo iptables -A INPUT -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        #sudo iptables -A OUTPUT -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        #sudo iptables -A FORWARD -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        
        echo "[*] Adding monitors for iptables"
        # sudo touch "${FIREWALL_LOG}"
        add_monitor "${FIREWALL_LOG}" "${INDEX}"
    else
        echo "[*] ERROR: No firewall found. Please forward logs manually."
    fi
}

# Adds monitors for package managers (for monitoring installed packages)
function add_package_logs {
    print_banner "Adding package logs"

    INDEX="misc"
    if command -v dpkg &>/dev/null; then
        echo "[*] Adding monitors for dpkg logs"
        PACKAGE_LOGS="/var/log/dpkg.log"
        add_monitor "${PACKAGE_LOGS}" "${INDEX}"
    fi

    if command -v apt &>/dev/null; then
        echo "[*] Adding monitors for apt logs"
        PACKAGE_LOGS="/var/log/apt/history.log"
        add_monitor "${PACKAGE_LOGS}" "${INDEX}"
    fi

    if command -v dnf &>/dev/null; then
        echo "[*] Adding monitors for dnf logs"
        PACKAGE_LOGS="/var/log/dnf.rpm.log"
        add_monitor "${PACKAGE_LOGS}" "${INDEX}"
    fi

    if command -v yum &>/dev/null; then
        echo "[*] Adding monitors for yum logs"
        PACKAGE_LOGS="/var/log/yum.log"
        add_monitor "${PACKAGE_LOGS}" "${INDEX}"
    fi

    if command -v zypper &>/dev/null; then
        echo "[*] Adding monitors for zypper logs"
        PACKAGE_LOGS="/var/log/zypp/history"
        add_monitor "${PACKAGE_LOGS}" "${INDEX}"
    fi
}

# Adds monitors for ssh keys
function add_ssh_key_logs {
    print_banner "Adding user ssh key logs"
    INDEX="service_auth"
    for dir in /home/*; do
        if [ -d "$dir" ]; then
            if [ -d "$dir/.ssh" ]; then
                echo "[*] Adding ${dir}/.ssh/"
                add_monitor "${dir}" "${INDEX}"
            fi
        fi
    done
}

# Adds monitors for web logs
function add_web_logs {
    print_banner "Adding web logs"

    INDEX="service"
    if [ -d "/var/log/apache2/" ]; then
        echo "Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/apache2/access.log"
        APACHE_ERROR="/var/log/apache2/error.log"
        add_monitor "${APACHE_ACCESS}" "${INDEX}"
        add_monitor "${APACHE_ERROR}" "${INDEX}"
    elif [ -d "/var/log/httpd/" ]; then
        echo "[*] Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/httpd/access_log"
        APACHE_ERROR="/var/log/httpd/error_log"
        add_monitor "${APACHE_ACCESS}" "${INDEX}"
        add_monitor "${APACHE_ERROR}" "${INDEX}"
    elif [ -d "/var/log/lighttpd/" ]; then
        echo "[*] Adding monitor for lighttpd error logs"
        # LIGHTTPD_ACCESS="/var/log/lighhtpd/access.log"
        LIGHTTPD_ERROR="/var/log/lighttpd/error.log"
        # add_monitor "${LIGHTTPD_ACCESS}" "${INDEX}"
        add_monitor "${LIGHTTPD_ERROR}" "${INDEX}"
        print_banner "Please manually modify lighttpd config file in /etc/lighttpd/lighttpd.conf."
        echo "[*] Add "mod_accesslog" in server.modules, and at the bottom of the file add \`accesslog.filename = \"/var/log/lighttpd/access.log\"\`"
        echo "[*] Then, add a Splunk monitor for /var/log/lighttpd/access.log"
    elif [ -d "/var/log/nginx" ]; then
        echo "[*] Adding monitors for Nginx logs"
        NGINX_ACCESS="/var/log/nginx/access.log"
        NGINX_ERROR="/var/log/nginx/error.log"
        add_monitor "${NGINX_ACCESS}" "${INDEX}"
        add_monitor "${NGINX_ERROR}" "${INDEX}"
    else
        echo "[*] Did not find webserver (Apache, Nginx, or lighttpd) on this system."
    fi
}

# Adds monitors for MySQL logs
function add_mysql_logs {
    print_banner "Adding MySQL logs"

    INDEX="service"
    MYSQL_CONFIG="/etc/mysql/my.cnf" # Adjust the path based on your system

    if [ -f "${MYSQL_CONFIG}" ]; then
        # Make sure there's actually a MySQL or MariaDB service
        if command -v systemctl &> /dev/null; then
            if ! sudo systemctl status mysql &> /dev/null && ! sudo systemctl status mariadb &> /dev/null; then
                echo "[*] Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
            fi
        elif command -v service &> /dev/null; then
            if ! sudo service mysql status &> /dev/null && ! sudo service mariadb status &> /dev/null; then
                echo "[*] Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
            fi
        else
            echo "[*] Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
        fi
        echo "[*] Adding monitors for MySQL logs"

        # Log file paths
        GENERAL_LOG="/var/log/mysql/mysql.log"
        ERROR_LOG="/var/log/mysql/error.log"

        # Enable General Query Log
        echo "[mysqld]" | sudo tee -a "$MYSQL_CONFIG"
        echo "general_log = 1" | sudo tee -a "$MYSQL_CONFIG"
        echo "general_log_file = $GENERAL_LOG" | sudo tee -a "$MYSQL_CONFIG"

        # Enable Error Log
        echo "log_error = $ERROR_LOG" | sudo tee -a "$MYSQL_CONFIG"

        # Restart MySQL service
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart mysql
        elif command -v service &> /dev/null; then
            sudo service mysql restart
        else
            echo "[*] ERROR: Unable to restart MySQL. Please restart the MySQL service manually."
        fi

        # sudo touch "${GENERAL_LOG}"
        # sudo touch "${ERROR_LOG}"
        add_monitor "${GENERAL_LOG}" "${INDEX}"
        add_monitor "${ERROR_LOG}" "${INDEX}"
    else
        echo "[*] Did not find MySQL on this system."
    fi
}

# Adds monitors for the Splunk indexer service itself
function add_indexer_web_logs {
    print_banner "Adding indexer web logs"

    INDEX="service"
    SPLUNK_WEB_ACCESS="/opt/splunk/var/log/splunk/web_access.log"

    echo "[*] Adding monitors for Splunk web logs"
    add_monitor "${SPLUNK_WEB_ACCESS}" "${INDEX}"
}

# Asks the user to specify additional logs to add
function add_additional_logs {
    print_banner "Adding additional logs"

    echo "[*] Indexes: ${INDEXES[@]}"
    for index in "${INDEXES[@]}"; do
        echo "[*] Would you like to add additional log sources for index '${index}'?"
        read -r -p "(y/n): " option
        option=$(echo "$option" | tr -d ' ') # truncates any spaces accidentally put in

        sources=()
        continue="true"
        if [ "$option" == "y" ]; then
            while [ "$continue" != "false" ]; do
                read -r -p "[*] Enter additional logs sources: (one entry per line; hit enter to continue): " userInput
                if [[ "$userInput" == "" ]]; then
                    continue="false"
                else
                    sources+=("$userInput")
                fi
            done
            for source in "${sources[@]}"; do
                add_monitor "${source}" "${index}"
            done
        fi
    done
}

# Add all monitors and forward server
function setup_monitors {
    # Add monitors
    print_banner "Adding Monitors"
    add_system_logs
    add_firewall_logs
    add_package_logs
    add_ssh_key_logs
    add_web_logs
    add_mysql_logs

    if [ $IP == "indexer" ]; then
        add_indexer_web_logs
    fi

    add_additional_logs
}

# Add forward server
# Arguments:
#   $1: IP address of server
function setup_forward_server {
    print_banner "Adding Forward Server"
    sudo $SPLUNKDIR/bin/splunk add forward-server $1:9997
}

################################# MAIN #################################
echo "[*] Starting script"
check_prereqs "$0" "$1" "$2"
setup_splunk "$1" "$2"
setup_monitors
if [ $IP != "indexer" ]; then
    setup_forward_server "$2"
fi

print_banner "Restarting Splunk"
sleep 3
sudo $SPLUNKDIR/bin/splunk restart

print_banner "End of script"
echo "[*] You can add future additional monitors with 'sudo $SPLUNKDIR/bin/splunk add monitor <PATH> -index <INDEX>'"
echo
############################### END MAIN ###############################
