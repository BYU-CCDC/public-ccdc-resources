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

# Prints script options
function print_options {
    echo
    echo "Usage: ./splunkf.sh <option> <forward-server-ip>"
    echo "OPTIONS: 
    -> debian
    -> linux (general tgz file)
    -> rpm (red hat distros)
    -> other (shows list of other forwarder urls)
    -> -p (prints the specified url debian, linux or rpm in case something is not working)
            " # trust the indents
    exit 1
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

    if ! id "CCDCUser1" &>/dev/null; then
        echo "[*] ERROR: Please add the CCDCUser1 user before using this script"
        exit 1
    fi
    
    if [ "$#" != 3 ]; then
        echo "[*] ERROR: Usage: $0 <option> <ip_address>"
        print_options
    fi

    if [[ ! $3 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "[*] ERROR: Invalid IP address format: $3"
        print_options
    fi
}

# Installs correct forwarder for specific distribution
function install_forwarder {
    # If forwarder does not already exist:
    if [[ ! -d /opt/splunkforwarder ]]; then
        # Determine distribution type and install
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
        echo "[*] Install already exists. Proceeding to configure forwarder."
    fi
}

# Installs forwarder and gives ownership to CCDCUser1
function setup_forwarder {
    sleep 2
    if [[ $2 == "" ]]; then 
        echo "[*] ERROR: Please provide the IP of the central splunk instance"
        echo "Usage: ./splunkf.sh <option> <forward-server-ip>"
        exit
    fi
    install_forwarder "$1" "$2"
    sudo /opt/splunkforwarder/bin/splunk start --accept-license
}

# Checks for existence of a file or directory and add it as a monitor if it exists
# Arguments:
#   $1: Path of log source
#   $2: Index name
function add_monitor {
    source=$1
    index=$2
    if [ -e "${source}" ]; then
        sudo /opt/splunkforwarder/bin/splunk add monitor "$source" -index "$index"
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
        echo "[*] No monitor added; firewalld logs contained in /var/log/messages"
    elif command -v ufw &>/dev/null; then
        echo "[*] Adding monitors for ufw logs"
        FIREWALL_LOG="/var/log/ufw.log"
        sudo touch "${FIREWALL_LOG}"
        sudo ufw logging low
        add_monitor "${FIREWALL_LOG}" "${INDEX}"
    elif command -v iptables &>/dev/null; then
        echo "[*] Adding monitors for iptables"
        FIREWALL_LOG="/var/log/iptables.log"
        LOGGING_LEVEL=1
        sudo touch "${FIREWALL_LOG}"
        sudo iptables -A INPUT -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        #sudo iptables -A OUTPUT -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        #sudo iptables -A FORWARD -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
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

    if command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        echo "[*] Adding monitors for dnf/yum logs"
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
                echo "[*] Adding ${dir}"
                add_monitor "${dir}" "${INDEX}"
            fi
        fi
    done
}

# Adds monitors for web logs
function add_web_logs {
    print_banner "Adding web logs"

    INDEX="service"
    if [ -d "/var/log/apache/" ]; then
        echo "Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/apache/access.log"
        APACHE_ERROR="/var/log/apache/error.log"
        add_monitor "${APACHE_ACCESS}" "${INDEX}"
        add_monitor "${APACHE_ERROR}" "${INDEX}"
    elif [ -d "/var/log/httpd/" ]; then
        echo "[*] Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/httpd/access_log"
        APACHE_ERROR="/var/log/httpd/error_log"
        add_monitor "${APACHE_ACCESS}" "${INDEX}"
        add_monitor "${APACHE_ERROR}" "${INDEX}"
    elif [ -d "/var/log/lighttpd/" ]; then
        echo "[*] Adding monitors for lighttpd logs"
        LIGHTTPD_ACCESS="/var/log/lighhtpd/access_log"
        LIGHTTPD_ERROR="/var/log/lighttpd/error_log"
        add_monitor "${LIGHTTPD_ACCESS}" "${INDEX}"
        add_monitor "${LIGHTTPD_ERROR}" "${INDEX}"
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
        sudo echo "[mysqld]" >> "$MYSQL_CONFIG"
        sudo echo "general_log = 1" >> "$MYSQL_CONFIG"
        sudo echo "general_log_file = $GENERAL_LOG" >> "$MYSQL_CONFIG"

        # Enable Error Log
        sudo echo "log_error = $ERROR_LOG" >> "$MYSQL_CONFIG"

        # Restart MySQL service
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart mysql
        elif command -v service &> /dev/null; then
            sudo service mysql restart
        else
            echo "[*] ERROR: Unable to restart MySQL. Please restart the MySQL service manually."
        fi

        sudo touch "${GENERAL_LOG}"
        sudo touch "${ERROR_LOG}"
        add_monitor "${GENERAL_LOG}" "${INDEX}"
        add_monitor "${ERROR_LOG}" "${INDEX}"
    else
        echo "[*] Did not find MySQL on this system."
    fi
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
    add_additional_logs
}

# Add forward server
# Arguments:
#   $1: IP address of server
function setup_forward_server {
    IP=$1
    print_banner "Adding Forward Server"
    sudo /opt/splunkforwarder/bin/splunk add forward-server $IP:9997
    print_banner "Restarting Splunk"
    sleep 3
    sudo /opt/splunkforwarder/bin/splunk restart
}

################################# MAIN #################################
echo "[*] Starting script"
check_prereqs "$0" "$1" "$2"
setup_forwarder "$1" "$2"
setup_monitors
setup_forward_server "$2"
sudo chown -R CCDCUser1 /opt/splunkforwarder # Give privs to our user
sudo chgrp -R CCDCUser1 /opt/splunkforwarder
print_banner "End of script"
echo "[*] You can add future additional monitors with 'sudo /opt/splunkforwarder/bin/splunk add monitor <PATH> -index <INDEX>'"
echo
############################### END MAIN ###############################