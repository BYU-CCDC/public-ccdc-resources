#!/bin/bash

# Copyright (C) 2025 deltabluejay
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

###################### GLOBALS ######################
LOG='/var/log/ccdc/splunk.log'
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
INDEXES=( 'system' 'web' 'network' 'windows' 'misc' 'snoopy' 'ossec' )
PM=""
IP=""
INDEXER=false
REINSTALL=false
NOCOLOR=false
VERBOSE=false
PACKAGE="auto"
LOCAL_PACKAGE=""
SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_ONLY=false
DOWNLOAD_ONLY=false
ADDITIONAL_LOGGING_ONLY=false
LOCAL=false
SYSTEMD_SYSTEM=false

# Special variables recognized by Splunk CLI for authentication
SPLUNK_OWNER="splunkfwd"
SPLUNK_USERNAME="splunkfwd"
SPLUNK_PASSWORD=""

### Latest ###
PACKAGE_TYPES=("indexer_deb" "indexer_rpm" "indexer_tgz" "deb" "rpm" "tgz" "arm_deb" "arm_rpm" "arm_tgz")

# Indexer
indexer_deb="https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.deb"
indexer_rpm="https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9.x86_64.rpm"
indexer_tgz="https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz"

# Forwarder
deb="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
rpm="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm"
tgz="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.tgz"
arm_deb="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-arm64.deb"
arm_rpm="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9.aarch64.rpm"
arm_tgz="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-arm64.tgz"

### 9.2.10 ###
# Indexer
indexer_deb_9_2_10="https://download.splunk.com/products/splunk/releases/9.2.10/linux/splunk-9.2.10-37c0a7e2ccbd-linux-2.6-amd64.deb"
indexer_rpm_9_2_10="https://download.splunk.com/products/splunk/releases/9.2.10/linux/splunk-9.2.10-37c0a7e2ccbd.x86_64.rpm"
indexer_tgz_9_2_10="https://download.splunk.com/products/splunk/releases/9.2.10/linux/splunk-9.2.10-37c0a7e2ccbd-Linux-x86_64.tgz"

# Forwarder
deb_9_2_10="https://download.splunk.com/products/universalforwarder/releases/9.2.10/linux/splunkforwarder-9.2.10-37c0a7e2ccbd-linux-2.6-amd64.deb"
rpm_9_2_10="https://download.splunk.com/products/universalforwarder/releases/9.2.10/linux/splunkforwarder-9.2.10-37c0a7e2ccbd.x86_64.rpm"
tgz_9_2_10="https://download.splunk.com/products/universalforwarder/releases/9.2.10/linux/splunkforwarder-9.2.10-37c0a7e2ccbd-Linux-x86_64.tgz"
arm_deb_9_2_10="https://download.splunk.com/products/universalforwarder/releases/9.2.10/linux/splunkforwarder-9.2.10-37c0a7e2ccbd-Linux-armv8.deb"
arm_rpm_9_2_10="https://download.splunk.com/products/universalforwarder/releases/9.2.10/linux/splunkforwarder-9.2.10-37c0a7e2ccbd.aarch64.rpm"
arm_tgz_9_2_10="https://download.splunk.com/products/universalforwarder/releases/9.2.10/linux/splunkforwarder-9.2.10-37c0a7e2ccbd-Linux-armv8.tgz"

### 9.0.9 ###
deb_9_0_9="https://download.splunk.com/products/universalforwarder/releases/9.0.9/linux/splunkforwarder-9.0.9-6315942c563f-linux-2.6-amd64.deb"
rpm_9_0_9="https://download.splunk.com/products/universalforwarder/releases/9.0.9/linux/splunkforwarder-9.0.9-6315942c563f.x86_64.rpm"
tgz_9_0_9="https://download.splunk.com/products/universalforwarder/releases/9.0.9/linux/splunkforwarder-9.0.9-6315942c563f-Linux-x86_64.tgz"

AUDITD_SUCCESSFUL=false
SNOOPY_SUCCESSFUL=false
SYSMON_SUCCESSFUL=false
OSSEC_SUCCESSFUL=false
SUCCESSFUL_MONITORS=()

# ANSI color codes
NORMAL=0
BOLD=1
UNDERLINE=4
BLACK=30
BLACK_BG=40
RED=31
REG_BG=41
GREEN=32
GREEN_BG=42
YELLOW=33
YELLOW_BG=43
BLUE=34
BLUE_BG=44
MAGENTA=35
MAGENTA_BG=45
CYAN=36
CYAN_BG=46
WHITE=37
WHITE_BG=47
DEFAULT=39
DEFAULT_BG=49
NC='\x1B[0m'

#####################################################

##################### FUNCTIONS #####################
# TODO: switch to local variables
### ANSI color and logging functions ###
function set_ansi {
    color=$1
    mode=$2

    if [ "$NOCOLOR" == true ]; then
        echo -ne "$text"
        return
    fi

    if [ -z "$mode" ]; then
        mode=$NORMAL
    fi

    if [ -z "$color" ]; then
        color=$DEFAULT
    fi

    echo -ne "\x1B[${mode};${color}m"
}

function print_ansi {
    text=$1
    color=$2
    mode=$3

    if [ "$NOCOLOR" == true ]; then
        echo -ne "$text"
        return
    fi

    if [ -z "$mode" ]; then
        mode=$NORMAL
    fi

    if [ -z "$color" ]; then
        color=$DEFAULT
    fi

    echo -ne "\x1B[${mode};${color}m${text}${NC}"
}

__log_level_rank() {
    local level="${1^^}"
    case "$level" in
        ERROR) echo 0 ;;
        WARNING) echo 1 ;;
        SUCCESS|INFO) echo 2 ;;
        VERBOSE) echo 3 ;;
        DEBUG) echo 4 ;;
        *) echo 2 ;;
    esac
}

__log_should_emit() {
    local message_level="${1^^}"
    local current_level="${LOG_LEVEL^^}"

    if [ "$message_level" == "DEBUG" ] && [ "$debug" == "true" ] && [ "$current_level" != "DEBUG" ]; then
        current_level="DEBUG"
    fi

    local message_rank
    local threshold_rank
    message_rank=$(__log_level_rank "$message_level")
    threshold_rank=$(__log_level_rank "$current_level")

    if [ "$message_rank" -le "$threshold_rank" ]; then
        return 0
    fi
    return 1
}

function set_log_level {
    local new_level="${1:-INFO}"
    LOG_LEVEL="${new_level^^}"
    if [ "$LOG_LEVEL" == "DEBUG" ]; then
        debug="true"
    else
        debug="false"
    fi
}

function _log_with_color {
    local level="$1"
    local color="$2"
    shift 2 || true

    if ! __log_should_emit "$level"; then
        return 0
    fi

    printf '%b[%s]%b %s - %s\n' "$color" "$level" "$NC" "$(date +"%Y-%m-%d %H:%M:%S")" "$*"
}

function log_info {
    _log_with_color "INFO" $(set_ansi "$CYAN") "$@"
}

function log_success {
    _log_with_color "SUCCESS" $(set_ansi "$GREEN") "$@"
}

function log_warning {
    _log_with_color "WARNING" $(set_ansi "$YELLOW") "$@"
}

function log_error {
    _log_with_color "ERROR" $(set_ansi "$RED") "$@"
}

function log_verbose {
    _log_with_color "VERBOSE" $(set_ansi "$CYAN") "$@"
}

function log_debug {
    _log_with_color "DEBUG" $(set_ansi "$MAGENTA") "$@"
}

function setup_logging {
    log_path=$(dirname "$LOG")
    log_file=$(basename "$LOG")

    sudo mkdir -p "$log_path"
    sudo chown root:root "$log_path"
    sudo chmod 750 "$log_path"

    sudo touch "$log_file"
    sudo chown root:root "$log_file"
    sudo chmod 640 "$log_file"

    exec 1> >(sudo tee -a "$log_file")
    exec 2>&1
    log_info "Verbose logging initialized at $LOG"
}

function print_banner {
    # Stolen from LinPEAS
    local title=$1
    local title_len=$(echo $title | wc -c)
    local max_title_len=80
    local rest_len=$((($max_title_len - $title_len) / 2))

    echo ""
    printf $(set_ansi $BLUE $BOLD)
    for i in $(seq 1 $rest_len); do printf " "; done
    printf "╔"
    for i in $(seq 1 $title_len); do printf "═"; done; printf "═";
    printf "╗"
    echo ""
    for i in $(seq 1 $rest_len); do printf "═"; done
    printf "╣ $(set_ansi $GREEN $BOLD)${title}$(set_ansi $BLUE $BOLD) ╠"
    for i in $(seq 1 $rest_len); do printf "═"; done
    echo ""
    printf $(set_ansi $BLUE $BOLD)
    for i in $(seq 1 $rest_len); do printf " "; done
    printf "╚"
    for i in $(seq 1 $title_len); do printf "═"; done; printf "═";
    printf "╝"
    printf $(set_ansi)
    echo -e "\n"
}

# function info {
#     print_ansi "[+] " $GREEN $BOLD
#     print_ansi "$1\n" $DEFAULT
# }

# function error {
#     print_ansi "[X] ERROR: " $RED $BOLD
#     print_ansi "$1\n" $DEFAULT
# }

# function warn {
#     print_ansi "[!] WARNING: " $YELLOW $BOLD
#     print_ansi "$1\n" $DEFAULT
# }

# function debug {
#     if [ "$VERBOSE" == true ]; then
#         print_ansi "[*] " $BLUE $BOLD
#         print_ansi "$1\n" $DEFAULT
#     fi
# }

function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

function get_input_string {
    read -r -p "$1" input
    echo "$input"
}

function print_usage {
    echo "$(set_ansi $GREEN $BOLD)Usage:$(set_ansi)"
    echo "  $(set_ansi $BLUE $BOLD)./splunk.sh -f <INDEXER IP> [flags]         $(set_ansi)# Install the forwarder"
    echo "  $(set_ansi $BLUE $BOLD)./splunk.sh -i [flags]                      $(set_ansi)# Install the indexer"
    echo "  $(set_ansi $BLUE $BOLD)./splunk.sh -a <LOG_PATH>                   $(set_ansi)# Add a new monitor"
    echo "  $(set_ansi $BLUE $BOLD)./splunk.sh -D                              $(set_ansi)# Debug installation if it's not working"
    echo
    echo "$(set_ansi $GREEN $BOLD)Flags:$(set_ansi)
  $(set_ansi $YELLOW $BOLD)-h            $(set_ansi)Show this help message
  $(set_ansi $YELLOW $BOLD)-f <ip>       $(set_ansi)Install the forwarder (-f is required unless -i or -a are used)
  $(set_ansi $YELLOW $BOLD)-i            $(set_ansi)Install the indexer
  $(set_ansi $YELLOW $BOLD)-p <type>     $(set_ansi)Package type (defaults to auto - see below)
  $(set_ansi $YELLOW $BOLD)-v <version>  $(set_ansi)Install a specific Splunk version other than the latest (supported old versions: 9.2.10, 9.0.9)
  $(set_ansi $YELLOW $BOLD)-d            $(set_ansi)Download the Splunk package without installing
  $(set_ansi $YELLOW $BOLD)-r            $(set_ansi)Reinstall Splunk
  $(set_ansi $YELLOW $BOLD)-u            $(set_ansi)Print Splunk package URLs
  $(set_ansi $YELLOW $BOLD)-S            $(set_ansi)Install Splunk only (no additional logging)
  $(set_ansi $YELLOW $BOLD)-L            $(set_ansi)Install additional logging sources only (no Splunk)
  $(set_ansi $YELLOW $BOLD)-l <path>     $(set_ansi)Install from a locally cloned GitHub repository (provide filesystem path to repo)
  $(set_ansi $YELLOW $BOLD)-g <url>      $(set_ansi)Change the GitHub URL for downloading files (for local network hosting)
  $(set_ansi $YELLOW $BOLD)-a <path>     $(set_ansi)Add a new monitor (use only after installation)
  $(set_ansi $YELLOW $BOLD)-n            $(set_ansi)Disable colored output
  $(set_ansi $YELLOW $BOLD)-D            $(set_ansi)Debug your installation
  $(set_ansi $YELLOW $BOLD)-V            $(set_ansi)Show verbose output"
    echo
    echo "$(set_ansi $GREEN $BOLD)Available packages:$(set_ansi)
  $(set_ansi $MAGENTA $BOLD)auto $(set_ansi)(default; autodetects best package format based on package manager)
  $(set_ansi $MAGENTA $BOLD)* $(set_ansi)(catch-all; replace with any variable in the script)

  $(set_ansi $GREEN $BOLD)Forwarder:
    $(set_ansi $MAGENTA $BOLD)deb $(set_ansi)(Debian-based distros)
    $(set_ansi $MAGENTA $BOLD)rpm $(set_ansi)(RHEL-based distros)
    $(set_ansi $MAGENTA $BOLD)tgz $(set_ansi)(generic .tgz file)
    $(set_ansi $MAGENTA $BOLD)arm_debian $(set_ansi)(deb for ARM machines)
    $(set_ansi $MAGENTA $BOLD)arm_rpm $(set_ansi)(rpm for ARM machines)
    $(set_ansi $MAGENTA $BOLD)arm_tgz $(set_ansi)(tgz for ARM machines)

  $(set_ansi $GREEN $BOLD)Indexer:
    $(set_ansi $MAGENTA $BOLD)indexer_deb $(set_ansi)(Debian-based distros)
    $(set_ansi $MAGENTA $BOLD)indexer_rpm $(set_ansi)(RHEL-based distros)
    $(set_ansi $MAGENTA $BOLD)indexer_tgz $(set_ansi)(generic .tgz file)
"
    print_ansi ""   
}

### Utility functions ###
function faketty () {
    if command -v script >/dev/null 2>&1; then
        script -qfc "$(printf "%q " "$@")" /dev/null
    else
        "$@"
    fi
    "$@"
}

function download {
    url=$1
    output=$2

    if [[ "$LOCAL" == "true" && "$url" == "$GITHUB_URL"* ]]; then
        # Assume the URL is a local file path
        if [[ ! -f "$url" ]]; then
            log_error "Local file not found: $url"
            return 1
        fi
        cp "$url" "$output"
        log_debug "Copied from local Github to $output"
        return 0
    fi
    
    # TODO: figure out how to fix the progress bar
    if ! wget -O "$output" --no-check-certificate "$url" --progress=dot:mega 2>&1 | grep -Eo ' [0-9]0% ' | uniq; then
        # log_error "Failed to download with wget. Trying wget with older TLS version..."
        # if ! wget -O "$output" --secure-protocol=TLSv1 --no-check-certificate "$url"; then
            log_warning "Failed to download with wget. Trying with curl..."
            if ! curl -L -o "$output" -k "$url"; then
                log_error "Failed to download with curl."
                get_input_string "Download failed. Would you like to continue, retry, or exit? (C/r/e): " option
                case "$option" in
                    R|r )
                        download "$url" "$output"
                    ;;
                    E|e )
                        log_error "Exiting due to download failure."
                        exit 1
                    ;;
                    * )
                        log_info "Continuing despite download failure."
                    ;;
                esac
            fi
        # fi
    fi
}

function autodetect_os {
    log_info "Autodetecting OS / package manager"
    # Borrowed from harden.sh
    sudo which apt-get &> /dev/null
    apt=$?
    sudo which dnf &> /dev/null
    dnf=$?
    sudo which zypper &> /dev/null
    zypper=$?
    sudo which yum &> /dev/null
    yum=$?

    if [ $apt == 0 ]; then
        log_info "apt/apt-get detected (Debian-based OS)"
        log_debug "Updating package list"
        # TODO: pkill unattended-upgrades?
        sudo apt-get update -q
        PM="apt-get"
    elif [ $dnf == 0 ]; then
        log_info "dnf detected (Fedora-based OS)"
        PM="dnf"
    elif [ $zypper == 0 ]; then
        log_info "zypper detected (OpenSUSE-based OS)"
        PM="zypper"
    elif [ $yum == 0 ]; then
        log_info "yum detected (RHEL-based OS)"
        PM="yum"
    else
        log_warning "Could not detect package manager / OS"
        # exit 1
    fi
}

function debug_installation {
    # Check if Splunk is installed
    if ! sudo test -e "$SPLUNK_HOME/bin/splunk"; then
        log_error "Splunk is not installed."
        return 1
    fi
    # Check if owned by correct user
    owner=$(ls -ld "$SPLUNK_HOME" | awk '{print $3}')
    if [ "$owner" != "$SPLUNK_USERNAME" ]; then
        log_warning "Splunk installation is owned by $owner instead of $SPLUNK_USERNAME."
    fi
    # Check if Splunk services are running
    if ! sudo "$SPLUNK_HOME/bin/splunk" status &>/dev/null; then
        log_warning "Splunk services are not running."
    else
        log_info "Splunk services are running."
    fi
    # Check if Splunk can connect to indexer (if forwarder)
    if [ "$INDEXER" == false ]; then
        # Check if forward server is set
        if ! sudo "$SPLUNK_HOME/bin/splunk" list forward-server &>/dev/null; then
            log_warning "Splunk forwarder is not connected to any indexer."
        else
            log_info "Splunk forwarder is connected to an indexer."
        fi

        # Check if indexer is pingable
        ping -u "$IP" -c 3 &>/dev/null
        if [ $? -ne 0 ]; then
            log_warning "Cannot ping indexer at $IP."
        else
            log_info "Indexer at $IP is pingable."
        fi

        # Check if indexer is accessable on port 9997
        nc -zv "$IP" 9997 &>/dev/null
        if [ $? -ne 0 ]; then
            log_warning "Cannot connect to indexer at $IP on port 9997."
        else
            log_info "Can connect to indexer at $IP on port 9997."
        fi
    fi
    # Check if monitors are set up correctly
    if sudo "$SPLUNK_HOME/bin/splunk" list monitor &>/dev/null; then
        log_info "Splunk monitors are set up."
    else
        log_warning "No Splunk monitors are set up."
    fi
}

### Installation functions ###
function install_dependencies {
    log_info "Installing dependencies"

    if [ "$PM" == "" ]; then
        log_warning "No package manager detected."
    else
        sudo "$PM" install -qq -y wget curl acl unzip
        if [ "$PM" == "apt-get" ]; then
            sudo "$PM" install -qq -y debsums
        else
            sudo "$PM" install -qq -y rpm
        fi

        syslog_installed=false
        for f in /var/log/syslog /var/log/auth.log /var/log/secure /var/log/auth.log; do
            if sudo test -e "$f"; then
                syslog_installed=true
                break
            fi
        done

        if ! $syslog_installed; then
            sudo "$PM" install -qq -y rsyslog
        fi
    fi

    if ! command -v wget &>/dev/null; then
        log_error "Please install wget before using this script"
        exit 1
    fi

    # Needed because curl can bypass some wget TLS/SSL errors
    if ! command -v curl &>/dev/null; then
        log_error "Please install curl before using this script"
        exit 1
    fi

    if ! command -v setfacl &>/dev/null; then
        log_error "Please install acl before using this script"
        exit 1
    fi

    if ! command -v unzip &>/dev/null; then
        log_error "Please install unzip before using this script"
        exit 1
    fi
}

function check_prereqs {
    if [ "$INDEXER" != true ]; then
        if [[ $IP == "" ]]; then
            log_error "Please provide the IP of the splunk indexer (-h for help)"
            exit 1
        fi
    fi

    # Check that user has sudo privileges
    if [ "$(id -u)" -eq 0 ]; then
        log_debug "Script is being run as root"
    elif sudo -l &> /dev/null; then
        log_debug "User has sudo privileges"
    else
        log_error "User does not have sudo privileges. Please run script as root or a user that has sudo privileges."
        exit 1
    fi

    # Check if home directory exists for current user. Home directory is needed for running splunk commands
    # since the commands are aliases for http request methods. The .splunk directory contains this auth
    # token, so without it, splunk fails to install.
    if [ ! -d /home/"$(whoami)" ]; then
        log_warn "No home directory for current user $(whoami). Creating home directory"
        sudo mkdir -p /home/"$(whoami)"
        sudo chown "$(whoami)":"$(whoami)" /home/"$(whoami)"
    fi

    # user needs write permissions for current directory
    if [ ! -w . ]; then
        log_error "User does not have write permissions for current directory"
        exit 1
    fi
}

function prep_install {
    link="$1"
    filename="$2"

    log_info "Downloading package from $link. Please wait..."
    download "$link" "./$filename"

    if [ "$DOWNLOAD_ONLY" == true ]; then
        log_info "Download-only flag set. Exiting after download."
        exit 0
    fi

    if [ $REINSTALL == true ]; then
        # TODO: detect existing splunk version
        log_info "Reinstall flag set. Preparing to reinstall..."
        log_info "Backing up existing installation to $SPLUNK_HOME-bak"
        sudo cp -r -p $SPLUNK_HOME $SPLUNK_HOME-bak &>/dev/null

        log_info "Stopping existing Splunk services"
        sudo /opt/splunk/bin/splunk stop -f &>/dev/null
        sudo /opt/splunk/bin/splunkforwarder stop -f &>/dev/null
        sudo /opt/splunk/bin/splunk disable boot-start &>/dev/null
        sudo /opt/splunk/bin/splunkforwarder disable boot-start &>/dev/null

        option=$(get_input_string "Would you like to remove any existing Splunk packages? (Y/n): " | tr -d ' ')
        if [[ $option != "n" ]]; then
            log_info "Removing any existing Splunk packages"
            case "$PM" in
                apt-get )
                    sudo apt purge -y splunk
                    sudo apt purge -y splunkforwarder
                ;;
                dnf|yum|zypper )
                    sudo $PM remove -y splunk
                    sudo $PM remove -y splunkforwarder
                ;;
                * )
                    log_error "Unknown package manager: $PM"
                    exit 1
                ;;
            esac
        fi
        sudo rm -rf $SPLUNK_HOME
    fi
}

function install_package {
    link="$1"

    case "$link" in
        *.deb )
            prep_install "$link" splunk.deb
            log_info "Installing package..."
            sudo dpkg -i ./splunk.deb
        ;;
        *.rpm )
            prep_install "$link" splunk.rpm
            log_info "Installing package..."
            case "$PM" in
                zypper )
                    sudo zypper --no-gpg-checks install -y -qq ./splunk.rpm
                ;;
                dnf )
                    sudo dnf install --nogpgcheck ./splunk.rpm -y -qq
                ;;
                yum )
                    sudo yum install --nogpgcheck ./splunk.rpm -y -qq
                ;;
                *)
                    log_error "Unknown package manager: $PM"
                    exit 1
                ;;
            esac
        ;;
        *.tgz|*.tar.gz )
            prep_install "$link" splunk.tgz
            log_info "Extracting to $SPLUNK_HOME"
            sudo tar -xvf splunk.tgz -C /opt/ &> /dev/null
            # TODO: make sure it actually extracts to $SPLUNK_HOME
            sudo chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME
        ;;
        *)
            log_error "Could not determine package type: $link"
            exit 1
        ;;
    esac
}

function install_splunk {
    # If Splunk does not already exist:
    if ! sudo test -e "$SPLUNK_HOME/bin/splunk" || [[ "$REINSTALL" == true ]]; then
        # Determine package type and install
        case "$PACKAGE" in
            auto )
                log_info "Autodetecting best package format"
                case "$PM" in
                    apt-get )
                        PACKAGE="deb"
                        install_splunk
                    ;;
                    dnf|zypper|yum )
                        PACKAGE="rpm"
                        install_splunk
                    ;;
                    *)
                        log_error "Unknown package manager. Trying .tgz package."
                        PACKAGE="tgz"
                        install_splunk
                    ;;
                esac
                return
            ;;
            deb|debian )
                echo
                if [ "$INDEXER" == true ]; then
                    log_info "Selected .deb for indexer"
                    link="$indexer_deb"
                else
                    log_info "Selected .deb for forwarder"
                    link="$deb"
                fi
            ;;
            rpm )
                echo
                if [ "$INDEXER" == true ]; then
                    log_info "Selected indexer .rpm"
                    link="$indexer_rpm"
                else
                    log_info "Selected forwarder .rpm"
                    link="$rpm"
                fi
            ;;
            tgz|tar|linux )
                log_info "Installing generic .tgz package"
                echo
                if [ "$INDEXER" == true ]; then
                    log_info "Selected indexer .tgz"
                    link="$indexer_tgz"
                else
                    log_info "Selected forwarder .tgz"
                    link="$tgz"
                fi
            ;;
            *)
                # catch-all statement for unknown packages
                eval "link=\$$PACKAGE"
                if [[ -z $link ]]; then
                    log_error "Unknown package: $PACKAGE"
                    print_usage
                    exit 1
                else
                    log_info "Installing $PACKAGE"
                fi
            ;;
        esac

        install_package "$link"
    else
        log_info "Install already exists. Proceeding to configure Splunk."
    fi
}

function create_splunk_user {
    set_pass=true

    # Create splunk user/group
    if id $SPLUNK_USERNAME &>/dev/null; then
        option=$(get_input_string "Splunk user already exists. Would you like to reset the password for the $SPLUNK_USERNAME user? You'll need to do this if you're reinstalling Splunk or setting it up for the first time. (Y/n): " | tr -d ' ')
        if [ "$option" == "n" ]; then
            set_pass=false
        fi
    else
        log_info "Creating $SPLUNK_USERNAME user"
        sudo useradd $SPLUNK_USERNAME -d $SPLUNK_HOME
    fi

    if ! getent group $SPLUNK_USERNAME > /dev/null; then
        sudo groupadd $SPLUNK_USERNAME
        sudo usermod -aG $SPLUNK_USERNAME $SPLUNK_USERNAME
    fi

    if [ "$set_pass" == true ]; then
        # Set splunk password
        log_info "Setting password for the $SPLUNK_USERNAME user"
        while true; do
            password=""
            confirm_password=""

            # Ask for password
            password=$(get_silent_input_string "Enter password for $SPLUNK_USERNAME user: ")
            echo

            # Confirm password
            confirm_password=$(get_silent_input_string "Confirm password: ")
            echo

            if [ "$password" != "$confirm_password" ]; then
                echo "Passwords do not match. Please retry."
                continue
            fi

            if [ "${#password}" -lt 8 ]; then
                echo "Password must be at least 8 characters long. Please retry."
                continue
            fi

            if ! echo "$SPLUNK_USERNAME:$password" | sudo chpasswd; then
                log_error "Failed to set password for $SPLUNK_USERNAME user"
            else
                log_info "Password for $SPLUNK_USERNAME user has been set."
                break
            fi
        done

        SPLUNK_PASSWORD=$password
        
        # Add splunk user as forwarder/indexer admin
        log_info "Adding $SPLUNK_USERNAME user to user-seed.conf"
        sudo sh -c "printf '[user_info]\nUSERNAME = $SPLUNK_USERNAME\nPASSWORD = $password' > $SPLUNK_HOME/etc/system/local/user-seed.conf"
        # log_info "Please remember these credentials for when Splunk asks for them later during the configuration process"
    fi
    # Set ACL to allow splunk to read any log files (execute needed for directories)
    log_info "Giving $SPLUNK_USERNAME user access to /var/log/"
    sudo setfacl -Rm g:$SPLUNK_USERNAME:rx /var/log/
    sudo setfacl -Rdm g:$SPLUNK_USERNAME:rx /var/log/

    # chown splunk installation directory
    sudo chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME
}

function install_app {
    download "$1" /tmp/app.spl
    sudo chown $SPLUNK_USERNAME:$SPLUNK_USERNAME "/tmp/app.spl"
    sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk install app "/tmp/app.spl" -update 1
    sudo rm /tmp/app.spl
}

function install_ccdc_add_on {
    log_info "Installing CCDC Splunk add-on"
    install_app "$GITHUB_URL/splunk/ccdc-add-on.spl"
}

function install_sysmon_add_on {
    log_info "Installing Sysmon Splunk add-on"
    install_app "$GITHUB_URL/splunk/linux/splunk-add-on-for-sysmon-for-linux_100.tgz"

    # Sysmon monitor is included with add-on, but we need to change the index
    log_debug "Setting monitor index to sysmon"
    local dir="$SPLUNK_HOME/etc/apps/Splunk_TA_sysmon-for-linux/local/"
    sudo mkdir $dir
    sudo chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $dir
    download "$GITHUB_URL/splunk/linux/sysmon-inputs.conf" inputs.conf
    sudo chown $SPLUNK_USERNAME:$SPLUNK_USERNAME inputs.conf
    sudo mv inputs.conf "$dir"
}

function install_ccdc_app {
    log_info "Installing CCDC Splunk app"
    install_app "$GITHUB_URL/splunk/ccdc-app.spl"
}

function install_windows_soc_app {
    log_info "Installing Windows SOC Splunk app"
    install_app "$GITHUB_URL/splunk/windows-security-operations-center_20.tgz"
}

function install_sysmon_security_monitoring_app {
    log_info "Installing Sysmon Security Monitoring Splunk app"
    install_app "$GITHUB_URL/splunk/sysmon-security-monitoring-app-for-splunk_4013.tgz"
}

function install_audit_parse_app {
    log_info "Installing Audit Hex Value Decoder app"
    install_app "$GITHUB_URL/splunk/linux-audit-log-hex-value-decoder_100.tgz"
}

function install_palo_alto_apps {
    log_info "Installing Palo Alto apps"
    download "https://github.com/PaloAltoNetworks/Splunk-Apps/archive/refs/tags/v8.1.3.zip" /tmp/palo.zip
    unzip -q /tmp/palo.zip -d /tmp/palo-apps/

    sudo mv /tmp/palo-apps/Splunk-Apps-8.1.3/Splunk_TA_paloalto/ $SPLUNK_HOME/etc/apps/
    sudo mv /tmp/palo-apps/Splunk-Apps-8.1.3/SplunkforPaloAltoNetworks/ $SPLUNK_HOME/etc/apps/
    
    sudo chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME "$SPLUNK_HOME/etc/apps/Splunk_TA_paloalto/"
    sudo chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME "$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/"

    sudo rm /tmp/palo.zip
    sudo rm -rf /tmp/palo-apps/
}

function setup_indexer {
    log_info "Configuring Indexer"

    log_info "Adding listening port 9997"
    sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk enable listen 9997
    # sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk enable deploy-server
    
    log_info "Adding indexes"
    for i in "${INDEXES[@]}"; do
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add index "$i"
    done

    log_info "Giving $SPLUNK_USERNAME user can_delete role"
    sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk edit user $SPLUNK_USERNAME -role admin -role can_delete

    log_info "Creating SSL certs and enabling HTTPS for web interface"
    sudo mkdir -p $SPLUNK_HOME/etc/auth/splunkweb/
    sudo chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME/etc/auth/splunkweb/
    sudo $SPLUNK_HOME/bin/splunk createssl web-cert    # TODO: broken?
    sudo $SPLUNK_HOME/bin/splunk enable web-ssl

    log_info "Installing indexer apps"
    sudo rm /tmp/app.spl &>/dev/null
    install_ccdc_app
    # install_windows_soc_app
    # install_sysmon_security_monitoring_app
    install_audit_parse_app
    install_palo_alto_apps
}

# Installs splunk
function setup_splunk {
    print_banner "Configuring Splunk"

    if [ "$INDEXER" != true ]; then
        if [[ $IP == "" ]]; then 
            log_error "Please provide the IP of the central Splunk instance"
            exit 1
        fi
    fi
    install_splunk

    if sudo [ ! -e $SPLUNK_HOME/bin/splunk ]; then
        log_error "Splunk failed to install"
        exit 1
    else
        log_info "Splunk installed successfully"
    fi

    create_splunk_user

    log_info "Starting splunk"
    # For some reason, splunk start doesn't work on Ubuntu 14 without a tty...
    # faketty sudo -H -u splunk $SPLUNK_HOME/bin/splunk start --accept-license --no-prompt
    sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk start --accept-license --no-prompt

    # Make sure the correct username/password is provided before continuing
    # (this will do nothing if already logged in)
    res=-1
    while [ $res -ne 0 ]; do
        if [ "$SPLUNK_PASSWORD" == "" ]; then
            # TODO: verify this twice
            # TODO: also try passing -auth to every splunk command
            SPLUNK_PASSWORD=$(get_silent_input_string "Enter the password for $SPLUNK_USERNAME user: ")
        fi
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk login -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"
        res=$?
    done

    if [ "$INDEXER" == true ]; then
        setup_indexer
        # TODO: add firewall rules
        # sudo iptables -I INPUT 1 -p tcp -m multiport --dport 8000,9443 -j ACCEPT
        # sudo iptables -I INPUT 1 -p tcp --dport 9997 -j ACCEPT
    else
        setup_forward_server "$IP"
    fi
    sudo chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME
}

# Checks for existence of a file or directory and add it as a monitor if it exists
# Arguments:
#   $1: Path of log source
#   $2: Index name
#   $3: Sourcetype (optional)
function add_monitor {
    source=$1
    index=$2
    sourcetype=$3
    if sudo [ -e "$source" ]; then
        if [ "$sourcetype" != "" ]; then
            sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor "$source" -index "$index" -sourcetype "$sourcetype" &> /dev/null
        else
            sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor "$source" -index "$index" &> /dev/null
        fi
        if [ $? -ne 0 ]; then
            log_error "Failed to add monitor for $source"
            return
        fi
        log_info "Successfully added monitor for $source"
        SUCCESSFUL_MONITORS+=("$source")
    else
        log_error "No file or dir found at $source"
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
    if sudo [ -e "$source" ]; then
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add exec "$source" -index "$index" -interval "$interval" -sourcetype "$sourcetype" &> /dev/null
        if [ $? -ne 0 ]; then
            log_error "Failed to add scripted input for $source"
            return
        fi
        SUCCESSFUL_MONITORS+=("$source")
    else
        log_error "No file or dir found at $source"
    fi
}

function add_system_logs {
    log_info "Adding various system logs"
    log_warning "It is expected for some of these to fail"

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

function add_firewall_logs {
    log_info "Adding firewall logs"
    INDEX="network"
    
    if sudo command -v firewalld &>/dev/null; then
        log_info "firewalld detected"
        FIREWALL_LOG="/var/log/firewalld"

        log_info "Enabling firewalld logging"
        sudo firewall-cmd --set-log-denied=all

        log_info "Adding firewalld error logs"
        add_monitor "$FIREWALL_LOG" "$INDEX"
        log_info "firewalld access logs contained in /var/log/messages (already added)"
    elif sudo command -v ufw &>/dev/null; then
        log_info "ufw detected"
        FIREWALL_LOG="/var/log/ufw.log"

        log_info "Enabling ufw logging"
        sudo ufw logging low
        # Log all existing rules
        sudo ufw status | awk '/^[0-9]/ { print $1 }' | while read -r INPUT; do sudo ufw allow log "$INPUT"; done

        log_info "Adding monitors for ufw logs"
        # sudo touch "$FIREWALL_LOG"
        add_monitor "$FIREWALL_LOG" "$INDEX"
        log_info "ufw logs also contained in /var/log/syslog"
    elif sudo command -v iptables &>/dev/null; then
        # TODO: make this the main option and make it actually work with harden.sh
        log_info "iptables detected"
        FIREWALL_LOG="/var/log/iptables.log"

        log_info "Enabling iptables logging"
        LOGGING_LEVEL=1
        # Not sure if the order of where this rule is placed in the chain matters or not
        sudo iptables -A INPUT -j LOG --log-prefix "[iptables] CHAIN=INPUT ACTION=DROP: " --log-level $LOGGING_LEVEL
        # sudo iptables -A OUTPUT -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        # sudo iptables -A FORWARD -j LOG --log-prefix "iptables: " --log-level $LOGGING_LEVEL
        
        log_info "Adding monitors for iptables"
        # sudo touch "$FIREWALL_LOG"
        add_monitor "$FIREWALL_LOG" "$INDEX"
    else
        log_error "No firewall found. Please forward logs manually."
    fi
}

function add_package_logs {
    log_info "Adding package logs"
    
    INDEX="misc"
    if command -v dpkg &>/dev/null; then
        log_debug "Adding monitors for dpkg logs"
        PACKAGE_LOGS="/var/log/dpkg.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v apt &>/dev/null; then
        log_debug "Adding monitors for apt logs"
        PACKAGE_LOGS="/var/log/apt/history.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v dnf &>/dev/null; then
        log_debug "Adding monitors for dnf logs"
        PACKAGE_LOGS="/var/log/dnf.rpm.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v yum &>/dev/null; then
        log_debug "Adding monitors for yum logs"
        PACKAGE_LOGS="/var/log/yum.log"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi

    if command -v zypper &>/dev/null; then
        log_debug "Adding monitors for zypper logs"
        PACKAGE_LOGS="/var/log/zypp/history"
        add_monitor "$PACKAGE_LOGS" "$INDEX"
    fi
}

# function add_ssh_key_logs {
#     log_info "Adding user ssh key logs"
#     INDEX="system"
#     for dir in /home/*; do
#         if [ -d "$dir" ]; then
#             if [ -d "$dir/.ssh" ]; then
#                 log_debug "Adding $dir/.ssh/"
#                 add_monitor "$dir/.ssh" "$INDEX"
#             fi
#         fi
#     done
# }

function add_web_logs {
    log_info "Looking for web logs"

    INDEX="web"
    if [ -d "/var/log/apache2/" ]; then
        log_debug "Adding monitors for apache logs"
        APACHE_ACCESS="/var/log/apache2/access.log"
        APACHE_ERROR="/var/log/apache2/error.log"
        WAF="/var/log/apache2/modsec_audit.log"
        add_monitor "$APACHE_ACCESS" "$INDEX"
        add_monitor "$APACHE_ERROR" "$INDEX"
        add_monitor "$WAF" "$INDEX"
    elif [ -d "/var/log/httpd/" ]; then
        log_debug "Adding monitors for httpd logs"
        APACHE_ACCESS="/var/log/httpd/access_log"
        APACHE_ERROR="/var/log/httpd/error_log"
        WAF="/var/log/httpd/modsec_audit.log"
        add_monitor "$APACHE_ACCESS" "$INDEX"
        add_monitor "$APACHE_ERROR" "$INDEX"
        add_monitor "$WAF" "$INDEX"
    elif [ -d "/var/log/lighttpd/" ]; then
        log_debug "Adding monitor for lighttpd error logs"
        # LIGHTTPD_ACCESS="/var/log/lighhtpd/access.log"
        LIGHTTPD_ERROR="/var/log/lighttpd/error.log"
        # add_monitor "$LIGHTTPD_ACCESS" "$INDEX"
        add_monitor "$LIGHTTPD_ERROR" "$INDEX"
        log_warning "Please manually modify lighttpd config file in /etc/lighttpd/lighttpd.conf."
        log_warning "Add \"mod_accesslog\" in server.modules, and at the bottom of the file add \`accesslog.filename = \"/var/log/lighttpd/access.log\"\`"
        log_warning "Then, add a Splunk monitor for /var/log/lighttpd/access.log"
    elif [ -d "/var/log/nginx" ]; then
        log_debug "Adding monitors for Nginx logs"
        NGINX_ACCESS="/var/log/nginx/access.log"
        NGINX_ERROR="/var/log/nginx/error.log"
        add_monitor "$NGINX_ACCESS" "$INDEX"
        add_monitor "$NGINX_ERROR" "$INDEX"
    else
        log_info "Did not find webserver (Apache, Nginx, or lighttpd) on this system."
    fi
}

function add_mysql_logs {
    log_info "Looking for MySQL logs"

    INDEX="web"
    MYSQL_CONFIG="/etc/mysql/my.cnf" # Adjust the path based on your system

    if [ -f "$MYSQL_CONFIG" ]; then
        # Make sure there's actually a MySQL or MariaDB service
        if command -v systemctl &> /dev/null; then
            if ! sudo systemctl status mysql &> /dev/null && ! sudo systemctl status mariadb &> /dev/null; then
                log_warning "Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
            fi
        elif command -v service &> /dev/null; then
            if ! sudo service mysql status &> /dev/null && ! sudo service mariadb status &> /dev/null; then
                log_warning "Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
            fi
        else
            log_warning "Found MySQL config file but unable to detect MySQL or MariaDB service; no logs added"
                return
        fi
        log_debug "Adding monitors for MySQL logs"

        # Log file paths
        GENERAL_LOG="/var/log/mysql/mysql.log"
        ERROR_LOG="/var/log/mysql/error.log"

        # Enable General Query Log
        echo "[mysqld]" | sudo tee -a "$MYSQL_CONFIG" > /dev/null
        echo "general_log = 1" | sudo tee -a "$MYSQL_CONFIG" > /dev/null
        echo "general_log_file = $GENERAL_LOG" | sudo tee -a "$MYSQL_CONFIG" > /dev/null

        # Enable Error Log
        echo "log_error = $ERROR_LOG" | sudo tee -a "$MYSQL_CONFIG" > /dev/null

        # Restart MySQL service
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart mysql
        elif command -v service &> /dev/null; then
            sudo service mysql restart
        else
            log_error "Unable to restart MySQL. Please restart the MySQL service manually."
        fi

        # sudo touch "$GENERAL_LOG"
        # sudo touch "$ERROR_LOG"
        add_monitor "$GENERAL_LOG" "$INDEX"
        add_monitor "$ERROR_LOG" "$INDEX"
    else
        log_info "Did not find MySQL on this system."
    fi
}

# Adds scripted inputs
function add_scripts {
    log_info "Adding scripted inputs"
    # TOOD: add this to the add-on inputs.conf instead
    log_debug "Adding user sessions script"
    add_script $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/sessions.sh "system" "180" "ccdc-sessions"
    log_debug "Adding package integrity verification"
    sudo chown root:$SPLUNK_USERNAME $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/package-check.sh
    sudo chmod 750 $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/package-check.sh
    sudo chmod u+s $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/package-check.sh
    add_script $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/package-check.sh "system" "600" "ccdc-package-integrity"
}

# Adds monitors for the Splunk indexer service itself
function add_indexer_web_logs {
    log_info "Adding indexer web logs"

    INDEX="web"
    SPLUNK_WEB_ACCESS="$SPLUNK_HOME/var/log/splunk/web_access.log"

    log_debug "Adding monitors for Splunk web logs"
    add_monitor "$SPLUNK_WEB_ACCESS" "$INDEX"
}

# Asks the user to specify additional logs to add
function add_additional_logs {
    log_info "Adding additional logs"

    log_info "Indexes: ${INDEXES[*]}"
    option=$(get_input_string "Would you like to add any additional monitors? (y/N): " | tr -d ' ')    # truncate any spaces accidentally put in
    if [ "$option" == "y" ]; then
        for index in "${INDEXES[@]}"; do
            option=$(get_input_string "Would you like to add additional sources for index '$index'? (y/N): " | tr -d ' ')

            sources=()
            continue="true"
            if [ "$option" == "y" ]; then
                while [ "$continue" != "false" ]; do
                    userInput=$(get_input_string "Enter additional logs sources: (one entry per line; enter blank line to finish): " | tr -d ' ')
                    if [[ "$userInput" == "" ]]; then
                        continue="false"
                    else
                        sources+=("$userInput")
                    fi
                    # TODO: check that file exists during input loop
                done
                for source in "${sources[@]}"; do
                    add_monitor "$source" "$index"
                done
            fi
        done
    fi
}

function setup_monitors {
    print_banner "Adding Monitors"

    # Add monitors
    add_system_logs
    # add_firewall_logs
    add_package_logs
    # add_ssh_key_logs
    add_web_logs
    add_mysql_logs
    install_ccdc_add_on
    add_scripts

    if [ "$INDEXER" == true ]; then
        add_indexer_web_logs
    fi
}

function setup_forward_server {
    log_info "Adding Forward Server"
    sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add forward-server "$1":9997
    # sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk enable deploy-client
    # sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk set deploy-poll "$1":8089
}

function install_auditd {
    log_info "Installing auditd..."

    if sudo [ -e /etc/audit/ ]; then
        log_info "auditd already installed"
    else
        # Install auditd
        log_debug "Installing auditd package"
        sudo $PM install -qq -y auditd
        if [ $? -ne 0 ]; then
            sudo $PM install -qq -y audit
            if [ $? -ne 0 ]; then
                log_error "auditd installation failed"
                return 1
            fi
        fi
    fi

    # Enable and start auditd service
    if command -v systemctl &> /dev/null; then
        sudo systemctl enable auditd || sudo systemctl enable audit
        sudo systemctl start auditd || sudo systemctl start audit
    elif command -v service &> /dev/null; then
        sudo service auditd start || sudo service audit start
    fi

    # Add custom rules
    log_debug "Adding custom audit rules"
    if ! sudo [ -d "/etc/audit/rules.d/" ]; then
        log_error "Could not locate audit rules directory"
        return 1
    fi
    CUSTOM_RULE_FILE='/etc/audit/rules.d/ccdc.rules'

    # Download custom rule file
    download $GITHUB_URL/splunk/linux/ccdc.rules ./ccdc.rules
    sudo mv ./ccdc.rules $CUSTOM_RULE_FILE
    sudo chown root:root $CUSTOM_RULE_FILE
    sudo chmod 600 $CUSTOM_RULE_FILE

    # Add home directory rules
    # TODO: suppress output?
    echo '' | sudo tee -a $CUSTOM_RULE_FILE > /dev/null
    for dir in /home/*; do
        if [ -d "$dir" ]; then
            echo "-w ${dir}/.ssh/ -p w -k CCDC_modify_ssh_user" | sudo tee -a $CUSTOM_RULE_FILE > /dev/null

            if [ -f "$dir/.bashrc" ]; then
                echo "-w ${dir}/.bashrc -p w -k CCDC_modify_bashrc_user" | sudo tee -a $CUSTOM_RULE_FILE > /dev/null
            fi
        fi
    done

    sudo augenrules --load
    sudo service auditd reload

    if [ "$VERBOSE" == true ]; then
        log_debug "Applied rules:"
        sudo auditctl -l
    fi

    sudo setfacl -Rm g:$SPLUNK_USERNAME:rx /var/log/audit/
    sudo setfacl -Rdm g:$SPLUNK_USERNAME:rx /var/log/audit/
    add_monitor "/var/log/audit/audit.log" "system"
    AUDITD_SUCCESSFUL=true
}

function install_snoopy {
    version="$1"
    SNOOPY_LOG='/var/log/snoopy.log'
    
    log_info "Installing Snoopy (trying version $version)"
    if sudo [ -e /usr/local/lib/libsnoopy.so ]; then
        log_info "Snoopy is already installed"
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor "$SNOOPY_LOG" -index "snoopy" -sourcetype "snoopy"
        return 0
    fi

    download https://github.com/a2o/snoopy/raw/install/install/install-snoopy.sh "install-snoopy.sh"
    chmod 755 install-snoopy.sh
    
    # Install dependencies
    case "$PM" in
        apt )
        ;;
        dnf|zypper|yum )
            if sudo test -f "/etc/centos-release" || sudo test -f "/etc/redhat-release"; then
                sudo "$PM" install -y -qq epel-release
            fi
            sudo "$PM" install -y -qq gcc gzip make procps socat tar wget
        ;;
        * )
        ;;
    esac

    # Try installing Snoopy
    download "https://github.com/a2o/snoopy/releases/download/snoopy-$version/snoopy-$version.tar.gz" "snoopy-$version.tar.gz"
    if ! sudo ./install-snoopy.sh "./snoopy-$version.tar.gz" > /dev/null; then
        # If it fails
        log_error "Snoopy installation for version $version failed"
        return 1
    else
        # If it succeeds
        SNOOPY_CONFIG='/etc/snoopy.ini'
        if sudo [ -f $SNOOPY_CONFIG ]; then
            sudo touch /var/log/snoopy.log
            # Unfortunately required by snoopy in order to use a log file other than syslog/messages
            sudo chmod 622 $SNOOPY_LOG
            sudo setfacl -m g:$SPLUNK_USERNAME:r /var/log/snoopy.log
            echo "filter_chain = \"exclude_spawns_of:splunkd,btool\"" | sudo tee -a $SNOOPY_CONFIG > /dev/null
            echo "output = file:$SNOOPY_LOG" | sudo tee -a $SNOOPY_CONFIG > /dev/null
            echo
            log_debug "Set Snoopy output to $SNOOPY_LOG."
            # Restart snoopy
            # TODO: these commands aren't consistent across all systems
            sudo $(which snoopyctl) disable || sudo /usr/local/sbin/snoopy-disable  
            sudo $(which snoopyctl) enable || sudo /usr/local/sbin/snoopy-enable
        else
            log_error "Could not find Snoopy config file. Please add \`output = file:/var/log/snoopy.log\` to the end of the config."
        fi
        log_info "Snoopy installed successfully."
        log_warning "NOTE: Unless you restart the server, Snoopy may not pick up on commands from existing processes."
        # see https://github.com/a2o/snoopy/issues/212
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor "$SNOOPY_LOG" -index "snoopy" -sourcetype "snoopy"
        SNOOPY_SUCCESSFUL=true
        return 0
    fi
}

function install_sysmon {
    log_info "Installing Sysmon"
    download "$GITHUB_URL/linux/sysmon/sysmon.sh" sysmon.sh
    chmod +x sysmon.sh

    if [[ "$LOCAL" == true ]]; then
        ./sysmon.sh -l "$GITHUB_URL"
    else
        ./sysmon.sh -g "$GITHUB_URL"
    fi

    if [ $? -eq 0 ]; then
        log_info "Sysmon installed successfully"
        install_sysmon_add_on
        SYSMON_SUCCESSFUL=true
    else
        log_error "Sysmon installation failed"
        return 1
    fi
}

function install_ossec {
    log_info "Installing OSSEC"
    download "$GITHUB_URL/splunk/ossec.sh" ossec.sh
    chmod +x ossec.sh

    cmd="./ossec.sh "
    if [[ "$LOCAL" == true ]]; then
        cmd+="-l $GITHUB_URL "
    else
        cmd+="-g $GITHUB_URL "
    fi

    if [[ "$INDEXER" == true ]]; then
        cmd+="-i $IP"
    else
        cmd+="-f $IP"
    fi

    eval $cmd

    if [ $? -eq 0 ]; then
        log_info "OSSEC installed successfully"
        OSSEC_DIR="/var/ossec"
        if [[ "$INDEXER" == true ]]; then
            sudo setfacl -Rm g:$SPLUNK_USERNAME:rx $OSSEC_DIR/
            sudo setfacl -Rm g:$SPLUNK_USERNAME:rx $OSSEC_DIR/logs/
            sudo setfacl -Rm g:$SPLUNK_USERNAME:rx $OSSEC_DIR/logs/alerts/
            sudo setfacl -Rdm g:$SPLUNK_USERNAME:rx $OSSEC_DIR/logs/alerts/
            sudo setfacl -Rm g:$SPLUNK_USERNAME:rx $OSSEC_DIR/logs/firewall/
            sudo setfacl -Rdm g:$SPLUNK_USERNAME:rx $OSSEC_DIR/logs/firewall/
            add_monitor "$OSSEC_DIR/logs/ossec.log" "ossec" "ossec_log"
            add_monitor "$OSSEC_DIR/logs/alerts/alerts.log" "ossec" "ossec_alert"
            add_monitor "$OSSEC_DIR/logs/firewall/firewall.log" "ossec" "ossec_firewall"
        fi
        OSSEC_SUCCESSFUL=true
    else
        log_error "OSSEC installation failed"
        return 1
    fi
}
#####################################################

######################## MAIN #######################
function main {
    # log_info "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    check_prereqs
    setup_logging
    print_banner "Installing dependencies..."
    autodetect_os
    install_dependencies

    if [ "$ADDITIONAL_LOGGING_ONLY" == false ]; then
        setup_splunk

        setup_monitors
        # add_additional_logs

        print_banner "Finalizing Setup"
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk stop
        if command -v systemctl &> /dev/null; then
            log_debug "Enabling start on boot with systemd"
            sudo $SPLUNK_HOME/bin/splunk enable boot-start -systemd-managed 1 -user $SPLUNK_USERNAME
            if [ "$INDEXER" == true ]; then
                sudo systemctl enable Splunkd
                sudo systemctl start Splunkd
            else
                sudo systemctl enable SplunkForwarder
                sudo systemctl start SplunkForwarder
            fi
        else
            log_debug "Not a systemd machine; using splunk start"
            sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk start
        fi

        echo
    fi

    if [ "$SPLUNK_ONLY" == false ]; then
        print_banner "Installing Additional Logging Sources"
        log_info "Installing:"
        echo "   - auditd (file monitor)"
        echo "   - snoopy (command logger)"
        echo "   - sysmon (system and network monitor)"

        install_auditd

        # sudo $PM install -qq -y snoopy 2>/dev/null
        # if [ $? -ne 0 ]; then
            # log_debug "Could not find snoopy in package repos; attempting manual installation"
            if ! install_snoopy "2.5.2"; then
                if ! install_snoopy "2.4.15"; then
                    if ! install_snoopy "2.3.2"; then
                        log_error "Failed to install Snoopy"
                    fi
                fi
            fi
        # else
            # sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor "$SNOOPY_LOG" -index "snoopy" -sourcetype "snoopy"
            # SNOOPY_SUCCESSFUL=true
            # log_info "Snoopy installed successfully from package repos"
        # fi
        # install_sysmon
        # install_ossec
    else
        log_info "Skipping installation of additional logging sources"
    fi

    log_info "Finished!"

    print_banner "Summary"
    log_info "A debug log is located at $LOG"
    log_info "You can add additional monitors with this script."
    echo "   Usage: ./splunk.sh -a <LOG_PATH>"
    # log_info "Add future additional scripted inputs with 'sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add exec $SPLUNK_HOME/etc/apps/ccdc-add-on/bin/<SCRIPT> -interval <SECONDS> -index <INDEX>'"
    echo
    echo "Summary of installation:"
    echo "   Auditd successful? $AUDITD_SUCCESSFUL" # TODO: colors
    echo "   Snoopy successful? $SNOOPY_SUCCESSFUL"
    # echo "   Sysmon successful? $SYSMON_SUCCESSFUL"
    # echo "   OSSEC successful? $OSSEC_SUCCESSFUL"
    echo "   Added monitors for: "
    for item in "${SUCCESSFUL_MONITORS[@]}"; do
        echo "    - $item"
    done
    echo
}

while getopts "hp:P:df:irg:uSa:Ll:Vv:nD" opt; do
    case $opt in
        h)
            print_usage
            exit 0
            ;;
        u)
            # prints download urls for Splunk
            echo "Linux indexer deb (indexer_deb): $indexer_deb"
            echo
            echo "Linux indexer rpm (indexer_rpm): $indexer_rpm"
            echo
            echo "Linux indexer tgz (indexer_tgz): $indexer_tgz"
            echo
            echo "Linux deb (deb): $deb"
            echo
            echo "Linux rpm (rpm): $rpm"
            echo
            echo "Linux tgz (tgz): $tgz"
            echo
            echo "Linux ARM deb (arm_deb): $arm_deb"
            echo
            echo "Linux ARM rpm (arm_rpm): $arm_rpm"
            echo
            echo "Linux ARM tgz (arm_tgz): $arm_tgz"
            echo
            echo "A full list of URLs can be found in the markdown page on Github"
            exit 0
            ;;
        p)
            PACKAGE=$OPTARG
            ;;
        v)
            # Override package variables with provided version
            new_version="${OPTARG//./_}"
            for package in "${PACKAGE_TYPES[@]}"; do
                new_package="${package}_${new_version}"
                printf -v "$package" '%s' "${!new_package}"
                echo "${!new_package}"
            done
            ;;
        P)
            LOCAL_PACKAGE=$OPTARG
            ;;
        d)
            DOWNLOAD_ONLY=true
            ;;
        f)
            IP=$OPTARG
            ;;
        i)
            INDEXER=true
            SPLUNK_HOME="/opt/splunk"
            SPLUNK_OWNER="splunk"
            SPLUNK_USERNAME="splunk"
            # IP=$OPTARG
            ;;
        r)
            REINSTALL=true
            ;;
        g)
            GITHUB_URL=$OPTARG
            ;;
        S)
            SPLUNK_ONLY=true
            ;;
        L)
            ADDITIONAL_LOGGING_ONLY=true
            ;;
        l)
            LOCAL=true
            GITHUB_URL="$(realpath "$OPTARG")"  # Use local path for GITHUB_URL
            ;;
        a)
            # Pass -i before this argument if on the indexer
            while true; do
                log_debug "Indexes: ${INDEXES[*]}"
                index=$(get_input_string "Select an index: " | tr -d ' ')
                matches=false
                for value in "${INDEXES[@]}"
                do
                  [[ "$index" = "$value" ]] && matches=true
                done
                if [ "$matches" = true ]; then
                    break
                fi
                log_error "Invalid index: $index"
            done
            add_monitor "$OPTARG" "$index"
            exit 0
            ;;
        n)
            NOCOLOR=true
            ;;
        V)
            VERBOSE=true
            ;;
        \?)
            log_error "Invalid option: $OPTARG"
            print_usage
            exit 1
            ;;
        :)
            log_error "Option -$OPTARG requires an argument (-h for help)"
            exit 1
            ;;
        D)
            debug_installation
            exit 0
            ;;
    esac
done

main
#####################################################