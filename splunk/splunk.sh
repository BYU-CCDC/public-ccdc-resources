#!/bin/bash
# Usage: ./splunk.sh <option> <forward-server-ip>
# Use `indexer` as the forward-server-ip to install the indexer

###################### GLOBALS ######################
DEBUG_LOG='/var/log/ccdc/splunk.log'
GITHUB_URL='https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main'
INDEXES=( 'system' 'web' 'network' 'windows' 'misc' 'snoopy' )

# Download URLs
IP="$2"
if [ "$IP" == "indexer" ] || [ "$IP" == "i" ]; then
    IP="indexer"
    SPLUNKDIR="/opt/splunk"

    # Indexer
    deb="https://download.splunk.com/products/splunk/releases/9.2.4/linux/splunk-9.2.4-c103a21bb11d-linux-2.6-amd64.deb"
    rpm="https://download.splunk.com/products/splunk/releases/9.2.4/linux/splunk-9.2.4-c103a21bb11d.x86_64.rpm"
    tgz="https://download.splunk.com/products/splunk/releases/9.2.4/linux/splunk-9.2.4-c103a21bb11d-Linux-x86_64.tgz"
else
    SPLUNKDIR="/opt/splunkforwarder"
    
    # Forwarder
    deb="https://download.splunk.com/products/universalforwarder/releases/9.2.4/linux/splunkforwarder-9.2.4-c103a21bb11d-linux-2.6-amd64.deb"
    rpm="https://download.splunk.com/products/universalforwarder/releases/9.2.4/linux/splunkforwarder-9.2.4-c103a21bb11d.x86_64.rpm"
    tgz="https://download.splunk.com/products/universalforwarder/releases/9.2.4/linux/splunkforwarder-9.2.4-c103a21bb11d-Linux-x86_64.tgz"
    arm_deb="https://download.splunk.com/products/universalforwarder/releases/9.2.4/linux/splunkforwarder-9.2.4-c103a21bb11d-Linux-armv8.deb"
    arm_rpm="https://download.splunk.com/products/universalforwarder/releases/9.2.4/linux/splunkforwarder-9.2.4-c103a21bb11d.aarch64.rpm"
    arm_tgz="https://download.splunk.com/products/universalforwarder/releases/9.2.4/linux/splunkforwarder-9.2.4-c103a21bb11d-Linux-armv8.tgz"
fi
#####################################################

##################### FUNCTIONS #####################
# Prints script options
function print_options {
    echo "Usage: ./splunk.sh <option> <forward-server-ip>"
    echo "Use \`indexer\` as the forward-server-ip to install the indexer"
    echo "OPTIONS: 
    -> deb (Debian-based distros)
    -> rpm (RHEL-based distros)
    -> tgz (generic .tgz file)
    -> arm_debian (deb for ARM machines)
    -> arm_rpm (rpm for ARM machines)
    -> arm_tgz (tgz for ARM machines)
    -> * (replace * with the name of a variable obtained from print to download any package)
    -> print (prints all URLs)"
    echo
    exit 1
}

# Checks that correct arguments were provided to script
function check_prereqs {
    # user should not be root or run `sudo ./splunk.sh` since doing so makes the splunk forwarder install be owned by root
    if [ "$EUID" == 0 ]; then
        echo "[X] ERROR: Please run script without sudo prefix/not as root"
        exit 1
    fi

    # user needs sudo privileges to be able to run script
    user_groups=$(groups)
    if [[ $user_groups != *sudo* && $user_groups != *wheel* ]]; then
        echo "[X] ERROR: User needs sudo privileges. User not found in sudo/wheel group"
        exit 1
    fi

    # check if home directory exists for current user. Home directory is needed for running splunk commands since the commands are aliases for http request methods;
    # the .splunk directory contains this auth token so without it splunk fails to install
    if [ ! -d /home/"$(whoami)" ]; then
        echo "[*] No home directory for user $(whoami). Creating home directory"
        sudo mkdir -p /home/"$(whoami)"
    fi

    if ! command -v curl &>/dev/null; then
        echo "[X] ERROR: Please install curl before using this script"
        exit 1
    fi

    if ! command -v unzip &>/dev/null; then
        echo "[X] ERROR: Please install unzip before using this script"
        exit 1
    fi

    if ! command -v setfacl &>/dev/null; then
        echo "[X] ERROR: Please install acl before using this script"
        exit 1
    fi

    if [ "$#" != 3 ]; then
        print_options
    fi
    
    if [ "$IP" != "indexer" ]; then
        if [[ ! $3 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "[X] ERROR: Invalid IP address format: $3"
            print_options
        fi
    fi
}

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
}

function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

function download {
    url=$1
    output=$2
    sudo wget -O "$output" --no-check-certificate "$url"
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Failed to download with wget. Trying curl..."
        sudo curl -L -o "$output" -k "$url"
        if [ $? -ne 0 ]; then
            echo "[X] ERROR: Failed to download with curl. Exiting..."
            exit 1
        fi
    fi
}

# Downloads and installs correct version for distribution
function install_splunk {
    # If Splunk does not already exist:
    if sudo [ ! -e "$SPLUNKDIR/bin/splunk" ]; then
        # Determine distribution type and install
        case "$1" in
            deb|debian )
                print_banner "Installing .deb package"
                echo
                download "$deb" splunk.deb
                sudo dpkg -i ./splunk.deb
            ;;
            rpm )
                print_banner "Installing .rpm package"
                echo
                download "$rpm" splunk.rpm
                if command -v zypper &>/dev/null; then
                    sudo zypper install -y ./splunk.rpm
                else
                    sudo yum install ./splunk.rpm -y
                fi
            ;;
            tgz|tar|linux )
                print_banner "Installing generic .tgz package"
                echo
                download "$tgz" splunk.tgz
                echo "******* Extracting to $SPLUNKDIR *******"
                sudo tar -xvf splunk.tgz -C /opt/ &> /dev/null
                #TODO: make sure it actually extracts to $SPLUNKDIR
            ;;
            arm_deb )
                print_banner "Installing ARM .deb package" 
                echo
                download "$arm_deb" splunk.deb
                sudo dpkg -i ./splunk.deb
            ;;
            arm_rpm )
                print_banner "Installing ARM .rpm package"
                echo
                download "$arm_rpm" splunk.rpm
                if command -v zypper &>/dev/null; then
                    sudo zypper install -y ./splunk.rpm
                else
                    sudo yum install ./splunk.rpm -y
                fi
            ;;
            arm_tgz )
                print_banner "Installing generic ARM .tgz package"
                echo
                download "$arm_tgz" splunk.tgz
                echo "******* Extracting to $SPLUNKDIR *******"
                sudo tar -xvf splunk.tgz -C /opt/ &> /dev/null
            ;;
            # catch all statement that either downloads the pkg or provides the user with a list of potential command line options
            *)
                eval "pkg=\$$1"
                if [[ -z $pkg ]]; then
                    print_options
                else
                    print_banner "Downloading $1"
                    echo
                    download "$pkg" splunk.pkg
                    echo "Please install Splunk manually to $SPLUNKDIR, then run the script again to configure it."
                    exit
                fi
            ;;
        esac
    else
        echo "[*] Install already exists. Proceeding to configure splunk."
    fi
}

function create_splunk_user {
    # Create splunk user/group
    if id "splunk" &>/dev/null; then
        echo "[*] Splunk user already exists"
    else
        echo "[*] Creating splunk user"
        sudo useradd splunk -d "$SPLUNKDIR"
        
        # Setting splunk password
        while true; do
            password=""
            confirm_password=""

            # Ask for password
            password=$(get_silent_input_string "Enter password for splunk user: ")
            echo

            # Confirm password
            confirm_password=$(get_silent_input_string "Confirm password: ")
            echo

            if [ "$password" != "$confirm_password" ]; then
                echo "Passwords do not match. Please retry."
                continue
            fi

            if ! echo "splunk:$password" | sudo chpasswd; then
                echo "[X] ERROR: Failed to set password for splunk user"
            else
                echo "[*] Password for splunk user has been set."
                break
            fi
        done
        
        # Add splunk as forwarder/indexer admin
        echo "[*] Adding splunk user to user-seed.conf"
        # This isn't perfectly secure- plaintext password shows up in ps and the temporary seed file
        sudo sh -c "printf '[user_info]\nUSERNAME = splunk\nPASSWORD = $password' > $SPLUNKDIR/etc/system/local/user-seed.conf"

        if ! getent group "splunk" > /dev/null; then
            sudo groupadd splunk
            sudo usermod -aG splunk splunk
        fi

        echo "[*] Please remember these credentials for when Splunk asks for them later during the configuration process"
    fi

    # Set ACL to allow splunk to read any log files (execute needed for directories)
    echo "[*] Giving splunk user access to /var/log/"
    sudo setfacl -R -m u:splunk:rx /var/log/

    # Chowning splunk directory
    sudo chown -R splunk:splunk $SPLUNKDIR
}

# Special function only called when setting up indexer
function setup_indexer {
    print_banner "Configuring Indexer"

    echo "[*] Adding listening port 9997"
    sudo -H -u splunk $SPLUNKDIR/bin/splunk enable listen 9997

    echo "[*] Adding Indexes"
    for i in "${INDEXES[@]}"; do
        sudo -H -u splunk $SPLUNKDIR/bin/splunk add index "$i"
    done

    echo "[*] Installing Searches"
    wget $GITHUB_URL/splunk/indexer/savedsearches.conf
    sudo mkdir -p $SPLUNKDIR/etc/users/splunk/search/local/
    if sudo cp $SPLUNKDIR/etc/users/splunk/search/local/savedsearches.conf $SPLUNKDIR/etc/users/splunk/search/local/savedsearches.bk &>/dev/null; then
        echo "[*] Successfully backed up old savedsearches.conf as savedsearches.bk"
    fi
    sudo mv ./savedsearches.conf $SPLUNKDIR/etc/users/splunk/search/local/savedsearches.conf
}

# Installs splunk
function setup_splunk {
    print_banner "Setup"

    if [[ $2 == "" ]]; then 
        echo "[X] ERROR: Please provide the IP of the central splunk instance"
        echo "Usage: ./splunk.sh <option> <forward-server-ip>"
        exit
    fi

    install_splunk "$1" "$2"

    if sudo [ ! -e "$SPLUNKDIR/bin/splunk" ]; then
        echo "[X] ERROR: Splunk failed to install"
        exit 1
    else
        echo "[*] Splunk installed successfully"
    fi

    create_splunk_user

    echo "[*] Starting splunk"
    sudo -H -u splunk $SPLUNKDIR/bin/splunk start --accept-license --no-prompt

    if [ "$IP" == "indexer" ]; then
        setup_indexer
        # TODO: add firewall rules
        # sudo iptables -I INPUT 1 -p tcp -m multiport --dport 8000,9443 -j ACCEPT
        # sudo iptables -I INPUT 1 -p tcp --dport 9997 -j ACCEPT
    else
        setup_forward_server "$IP"
    fi
    sudo chown -R splunk:splunk $SPLUNKDIR
}

# Checks for existence of a file or directory and add it as a monitor if it exists
# Arguments:
#   $1: Path of log source
#   $2: Index name
function add_monitor {
    source=$1
    index=$2
    if sudo [ -e "$source" ]; then
        sudo -H -u splunk $SPLUNKDIR/bin/splunk add monitor "$source" -index "$index"
        # echo "[*] Added monitor for $source"
    else
        echo "[X] ERROR: No file or dir found at $source"
    fi
}

# Adds a scripted input to Splunk
# Arguments:
#   $1: Path of log source
#   $2: Index name
#   $3: Interval
#   $4: Sourcetype (arbitrary)
function add_script {
    source=$1
    index=$2
    interval=$3
    sourcetype=$4
    sudo -H -u splunk $SPLUNKDIR/bin/splunk add exec "$source" -index "$index" -interval "$interval" -sourcetype "$sourcetype"
}

# Adds monitors for system logs
function add_system_logs {
    print_banner "Adding various system logs"
    echo "[*] Some of these will fail due to distribution differences"

    INDEX="system"
    # add_monitor "/etc/services" "$INDEX"
    # add_monitor "/etc/systemd/" "$INDEX"
    # add_monitor "/etc/init.d/" "$INDEX"
    # add_monitor "/etc/profile.d/" "$INDEX"
    # add_monitor "/var/log/cron" "$INDEX" # this probably won't exist by default
    add_monitor "/var/log/syslog" "$INDEX"
    add_monitor "/var/log/messages" "$INDEX"
    add_monitor "/var/log/auth.log" "$INDEX"
    add_monitor "/var/log/secure" "$INDEX"
    add_monitor "/var/log/audit/audit.log" "$INDEX"

    INDEX="misc"
    # add_monitor "/tmp/" "$INDEX"
}

# Adds monitors for firewall logs
function add_firewall_logs {
    print_banner "Adding firewall logs"
    INDEX="network"
    
    if sudo command -v firewalld &>/dev/null; then
        echo "[*] firewalld detected"
        FIREWALL_LOG="/var/log/firewalld"

        echo "[*] Enabling firewalld logging"
        sudo firewall-cmd --set-log-denied=all

        echo "[*] Adding firewalld error logs"
        add_monitor "$FIREWALL_LOG" "$INDEX"
        echo "[*] firewalld access logs contained in /var/log/messages (already added)"
    elif sudo command -v ufw &>/dev/null; then
        echo "[*] ufw detected"
        FIREWALL_LOG="/var/log/ufw.log"

        echo "[*] Enabling ufw logging"
        sudo ufw logging low
        # Log all existing rules
        sudo ufw status | awk '/^[0-9]/ { print $1 }' | while read -r INPUT; do sudo ufw allow log "$INPUT"; done

        echo "[*] Adding monitors for ufw logs"
        # sudo touch "$FIREWALL_LOG"
        add_monitor "$FIREWALL_LOG" "$INDEX"
        echo "[*] ufw logs also contained in /var/log/syslog"
    elif sudo command -v iptables &>/dev/null; then
        echo "[*] iptables detected"
        FIREWALL_LOG="/var/log/iptables.log"

        echo "[*] Enabling iptables logging"
        LOGGING_LEVEL=1
        # Not sure if the order of where this rule is placed in the chain matters or not
        sudo iptables -A INPUT -j LOG --log-prefix "[iptables] CHAIN=INPUT ACTION=DROP: " --log-level $LOGGING_LEVEL
        # sudo iptables -A OUTPUT -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        # sudo iptables -A FORWARD -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        
        echo "[*] Adding monitors for iptables"
        # sudo touch "$FIREWALL_LOG"
        add_monitor "$FIREWALL_LOG" "$INDEX"
    else
        echo "[X] ERROR: No firewall found. Please forward logs manually."
    fi
}

# Adds monitors for package managers (for monitoring installed packages)
function add_package_logs {
    print_banner "Adding package logs"
    
    INDEX="misc"
    if command -v dpkg &>/dev/null; then
        echo "[*] Adding monitors for dpkg logs"
        PACKAGE_LOGS="/var/log/dpkg.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v apt &>/dev/null; then
        echo "[*] Adding monitors for apt logs"
        PACKAGE_LOGS="/var/log/apt/history.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v dnf &>/dev/null; then
        echo "[*] Adding monitors for dnf logs"
        PACKAGE_LOGS="/var/log/dnf.rpm.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v yum &>/dev/null; then
        echo "[*] Adding monitors for yum logs"
        PACKAGE_LOGS="/var/log/yum.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v zypper &>/dev/null; then
        echo "[*] Adding monitors for zypper logs"
        PACKAGE_LOGS="/var/log/zypp/history"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi
}

# Adds monitors for ssh keys
function add_ssh_key_logs {
    print_banner "Adding user ssh key logs"
    INDEX="system"
    for dir in /home/*; do
        if [ -d "$dir" ]; then
            if [ -d "$dir/.ssh" ]; then
                echo "[*] Adding $dir/.ssh/"
                add_monitor "$dir/.ssh" "$INDEX"
            fi
        fi
    done
}

# Adds monitors for web logs
function add_web_logs {
    print_banner "Adding web logs"

    INDEX="web"
    if [ -d "/var/log/apache2/" ]; then
        echo "Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/apache2/access.log"
        APACHE_ERROR="/var/log/apache2/error.log"
        add_monitor "$APACHE_ACCESS" "$INDEX"
        add_monitor "$APACHE_ERROR" "$INDEX"
    elif [ -d "/var/log/httpd/" ]; then
        echo "[*] Adding monitors for Apache logs"
        APACHE_ACCESS="/var/log/httpd/access_log"
        APACHE_ERROR="/var/log/httpd/error_log"
        add_monitor "$APACHE_ACCESS" "$INDEX"
        add_monitor "$APACHE_ERROR" "$INDEX"
    elif [ -d "/var/log/lighttpd/" ]; then
        echo "[*] Adding monitor for lighttpd error logs"
        # LIGHTTPD_ACCESS="/var/log/lighhtpd/access.log"
        LIGHTTPD_ERROR="/var/log/lighttpd/error.log"
        # add_monitor "$LIGHTTPD_ACCESS" "$INDEX"
        add_monitor "$LIGHTTPD_ERROR" "$INDEX"
        print_banner "Please manually modify lighttpd config file in /etc/lighttpd/lighttpd.conf."
        echo "[*] Add \"mod_accesslog\" in server.modules, and at the bottom of the file add \`accesslog.filename = \"/var/log/lighttpd/access.log\"\`"
        echo "[*] Then, add a Splunk monitor for /var/log/lighttpd/access.log"
    elif [ -d "/var/log/nginx" ]; then
        echo "[*] Adding monitors for Nginx logs"
        NGINX_ACCESS="/var/log/nginx/access.log"
        NGINX_ERROR="/var/log/nginx/error.log"
        add_monitor "$NGINX_ACCESS" "$INDEX"
        add_monitor "$NGINX_ERROR" "$INDEX"
    else
        echo "[*] Did not find webserver (Apache, Nginx, or lighttpd) on this system."
    fi
}

# Adds monitors for MySQL logs
function add_mysql_logs {
    print_banner "Adding MySQL logs"

    INDEX="web"
    MYSQL_CONFIG="/etc/mysql/my.cnf" # Adjust the path based on your system

    if [ -f "$MYSQL_CONFIG" ]; then
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
            echo "[X] ERROR: Unable to restart MySQL. Please restart the MySQL service manually."
        fi

        # sudo touch "$GENERAL_LOG"
        # sudo touch "$ERROR_LOG"
        add_monitor "$GENERAL_LOG" "$INDEX"
        add_monitor "$ERROR_LOG" "$INDEX"
    else
        echo "[*] Did not find MySQL on this system."
    fi
}

# Installs custom CCDC splunk add-on
function install_ccdc_add_on {
    print_banner "Installing CCDC Splunk add-on"
    wget $GITHUB_URL/splunk/ccdc-add-on/ccdc-add-on.spl
    sudo chown splunk:splunk ccdc-add-on.spl
    sudo -H -u splunk $SPLUNKDIR/bin/splunk install app ccdc-add-on.spl
}

# Installs custom CCDC splunk add-on
function install_ccdc_app {
    print_banner "Installing CCDC Splunk app (for indexer)"
    wget $GITHUB_URL/splunk/ccdc-app/ccdc-app.spl
    sudo chown splunk:splunk ccdc-app.spl
    sudo -H -u splunk $SPLUNKDIR/bin/splunk install app ccdc-app.spl
}

# Adds scripted inputs
function add_scripts {
    print_banner "Adding scripted inputs"
    echo "[*] Adding user sessions script"
    add_script "$SPLUNKDIR/etc/apps/ccdc-add-on/bin/sessions.sh" "system" "180" "ccdc-sessions"
}

# Adds monitors for the Splunk indexer service itself
function add_indexer_web_logs {
    print_banner "Adding indexer web logs"

    INDEX="web"
    SPLUNK_WEB_ACCESS="$SPLUNKDIR/var/log/splunk/web_access.log"

    echo "[*] Adding monitors for Splunk web logs"
    add_monitor "$SPLUNK_WEB_ACCESS" "$INDEX"
}

# Asks the user to specify additional logs to add
function add_additional_logs {
    print_banner "Adding additional logs"

    echo "[*] Indexes:" "${INDEXES[@]}"
    echo "[*] Would you like to add any additional monitors?"
    read -r -p "(y/N): " option
    option=$(echo "$option" | tr -d ' ') # truncates any spaces accidentally put in
    if [ "$option" == "y" ]; then
        for index in "${INDEXES[@]}"; do
            echo "[*] Would you like to add additional sources for index '$index'?"
            read -r -p "(y/N): " option
            option=$(echo "$option" | tr -d ' ')

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
                    add_monitor "$source" "$index"
                done
            fi
        done
    fi
}

# Add all monitors and forward server
function setup_monitors {
    print_banner "Adding Monitors"
    echo "[*] Would you like to automatically add monitors?"
    read -r -p "(Y/n): " option

    if [ "$option" != "n" ]; then
        # Add monitors
        add_system_logs
        # add_firewall_logs
        add_package_logs
        add_ssh_key_logs
        add_web_logs
        add_mysql_logs
        install_ccdc_add_on
        add_scripts

        if [ "$IP" == "indexer" ]; then
            add_indexer_web_logs
        fi
    fi
}

# Add forward server
# Arguments:
#   $1: IP address of server
function setup_forward_server {
    print_banner "Adding Forward Server"
    sudo -H -u splunk $SPLUNKDIR/bin/splunk add forward-server "$1":9997
}

# Adds custom dashboard
function add_dashboard {
    print_banner "Adding Homedash dashboard"
    sudo mkdir -p "$SPLUNKDIR/etc/users/splunk/search/local/data/ui/views/"
    sudo wget -O "$SPLUNKDIR/etc/users/splunk/search/local/data/ui/views/homedash.xml" "$GITHUB_URL/splunk/homedash.xml"
    echo "[*] Moved dashboard file to $SPLUNKDIR/etc/users/splunk/search/local/data/ui/views/homedash.xml"
}

# Adds custom configuration files
function add_custom_config {
    print_banner "Adding custom configuration files"
    sudo mkdir -p "$SPLUNKDIR/etc/apps/splunk_ingest_actions/local/"
    sudo wget -O "$SPLUNKDIR/etc/apps/splunk_ingest_actions/local/props.conf" "$GITHUB_URL/splunk/ingest_actions/props.conf"
    sudo wget -O "$SPLUNKDIR/etc/apps/splunk_ingest_actions/local/transforms.conf" "$GITHUB_URL/splunk/ingest_actions/transforms.conf"
    echo "[*] Moved config files to $SPLUNKDIR/etc/apps/splunk_ingest_actions/local/ (props.conf and transforms.conf)"
}

# Install auditd for file monitoring
function install_auditd {
    echo "[*] Would you like to install/setup auditd?"
    read -r -p "(Y/n): " option
    option=$(echo "$option" | tr -d ' ') # truncates any spaces accidentally put in
    
    if [ "$option" != "n" ]; then
        print_banner "Installing auditd (file monitor)"
        wget $GITHUB_URL/splunk/linux/auditd.sh
        chmod +x auditd.sh
        ./auditd.sh
        add_monitor "/var/log/audit/audit.log" "system"
    fi
}

# Install snoopy for bash logging
function install_snoopy {
    # TODO: this needs work
    echo "[*] Would you like to install/setup snoopy?"
    read -r -p "(Y/n): " option
    option=$(echo "$option" | tr -d ' ') # truncates any spaces accidentally put in

    if [ "$option" != "n" ]; then
        print_banner "Installing Snoopy (command logger)"
        wget -O install-snoopy.sh https://github.com/a2o/snoopy/raw/install/install/install-snoopy.sh
        chmod 755 install-snoopy.sh
        if command -v snoopyctl &>/dev/null; then
            echo "[*] Snoopy is already installed"
            return
        fi
        # If on Fedora, install these programs
        if command -v dnf &>/dev/null; then
            sudo dnf install -y gcc gzip make procps socat tar wget
        fi
        if ! sudo ./install-snoopy.sh stable; then
            echo
            echo "[X] ERROR: Install failed. If you would like to try installing an older version, "
            echo "    please run \`./install-snoopy.sh X.Y.Z\` with X.Y.Z being the version number."
            echo ""
            echo "Suggested versions:"
            echo "    - 2.5.1/stable (current, 2022-09-28)"
            echo "    - 2.4.15 (2021-10-17)"
            echo "    - 2.3.2 (2015-05-28)"
            echo ""
        else
            SNOOPY_CONFIG='/etc/snoopy.ini'
            if sudo [ -f $SNOOPY_CONFIG ]; then
                sudo touch /var/log/snoopy.log
                # Unfortunately required by snoopy in order to use file other than syslog/messages
                SNOOPY_LOG='/var/log/snoopy.log'
                sudo chmod 666 $SNOOPY_LOG
                echo "filter_chain = \"exclude_spawns_of:splunkd,btool\"" | sudo tee -a $SNOOPY_CONFIG
                echo "output = file:$SNOOPY_LOG" | sudo tee -a $SNOOPY_CONFIG
                echo
                echo "[*] Set Snoopy output to $SNOOPY_LOG."
                sudo -H -u splunk $SPLUNKDIR/bin/splunk add monitor "$SNOOPY_LOG" -index "snoopy" -sourcetype "snoopy"
            else
                echo "[X] ERROR: Could not find Snoopy config file. Please add \`output = file:/var/log/snoopy.log\` to the end of the config."
            fi
            echo "[*] Snoopy installed successfully."
        fi
    fi
}
#####################################################

######################## MAIN #######################
function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of script"

    if [ "$1" == "print" ]; then
        # prints download urls for Splunk
        echo "Linux deb (deb): $deb"
        echo
        echo "Linux rpm (rpm): $rpm"
        echo
        echo "Linux tgz (tgz): $tgz"
        echo
        if [ "$IP" != "indexer" ]; then
            echo "Linux ARM deb (arm_deb): $arm_deb"
            echo 
            echo "Linux ARM rpm (arm_rpm): $arm_rpm"
            echo 
            echo "Linux ARM tgz (arm_tgz): $arm_tgz"
            echo 
        fi
        echo "A full list of URLs can be found in the markdown page on Github"
        exit
    fi

    check_prereqs "$0" "$1" "$2"
    setup_splunk "$1" "$2"

    setup_monitors
    add_additional_logs

    if command -v systemctl &> /dev/null; then
        sudo -H -u splunk $SPLUNKDIR/bin/splunk stop
        echo "[*] Enabling systemd service"
        sudo $SPLUNKDIR/bin/splunk enable boot-start -systemd-managed 1 -user splunk
        sudo systemctl start Splunkd
    else
        sudo -H -u splunk $SPLUNKDIR/bin/splunk start
    fi

    install_auditd
    install_snoopy

    # if [ "$IP" == "indexer" ]; then
        # TODO: Auto dashboard import doesn't work
        # add_dashboard
        # add_custom_config
    # fi

    print_banner "End of script"
    echo "[*] Add future additional monitors with 'sudo -H -u splunk $SPLUNKDIR/bin/splunk add monitor <PATH> -index <INDEX>'"
    echo "[*] Add future additional scripted inputs with 'sudo -H -u splunk $SPLUNKDIR/bin/splunk add exec $SPLUNKDIR/etc/apps/ccdc-add-on/bin/<SCRIPT> -interval <SECONDS> -index <INDEX>'"
    echo "[*] A debug log is located at $DEBUG_LOG"
    echo
}

DEBUG_LOG_PATH=$(dirname "$DEBUG_LOG")
if [ ! -d "$DEBUG_LOG_PATH" ]; then
    sudo mkdir -p "$DEBUG_LOG_PATH"
    sudo chown root:root "$DEBUG_LOG_PATH"
    sudo chmod 755 "$DEBUG_LOG_PATH"
fi
main "$@" 2>&1 | sudo tee $DEBUG_LOG
#####################################################