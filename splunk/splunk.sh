#!/bin/bash

# Copyright (C) 2026 deltabluejay and BYU CCDC
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
INDEXES=( 'nix' 'windows' 'web' 'network' 'snoopy' 'ossec' 'edr' )
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
indexer_deb="https://download.splunk.com/products/splunk/releases/10.4.2/linux/splunk-10.4.2-33c3bf42cd73-linux-amd64.deb"
indexer_rpm="https://download.splunk.com/products/splunk/releases/10.4.2/linux/splunk-10.4.2-33c3bf42cd73.x86_64.rpm"
indexer_tgz="https://download.splunk.com/products/splunk/releases/10.4.2/linux/splunk-10.4.2-33c3bf42cd73-linux-amd64.tgz"

# Forwarder
deb="https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.deb"
rpm="https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73.x86_64.rpm"
tgz="https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.tgz"
arm_deb="https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73-linux-arm64.deb"
arm_rpm="https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73.aarch64.rpm"
arm_tgz="https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73-linux-arm64.tgz"
docker_image="splunk/universalforwarder:10.4.2"

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
GETOPT_SPEC="hp:P:df:irg:RuSa:Ll:Vv:nD"

# ANSI color codes
NORMAL=0
BOLD=1
UNDERLINE=4
BLACK=30
BLACK_BG=40
RED=31
RED_BG=41
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
function source_libsh {
    # If run from a cloned GitHub repo, source lib.sh from the repo
    local script_path="$(realpath "$0")"
    if [[ "$script_path" == *public-ccdc-resources* ]]; then
        resources_path="$(dirname "$(dirname "$(realpath "$0")")")"
        source "$resources_path/linux/lib.sh"
    # If downloaded in current directory, source it
    elif [ -f "lib.sh" ]; then
        source lib.sh
    # Otherwise, source it from GitHub
    else
        echo "Attempting to fetch lib.sh from GitHub..."
        libsh=$(curl -fsSL "$GITHUB_URL/linux/lib.sh")
        if [ $? -ne 0 ]; then
            libsh=$(wget -qO- "$GITHUB_URL/linux/lib.sh")
            if [ $? -ne 0 ]; then
                echo "ERROR: Failed to fetch lib.sh"
                exit 1
            fi
        fi
        source <(echo "$libsh")
        echo "$libsh" > lib.sh
    fi

    # Check that lib.sh was sourced successfully
    if ! declare -F get_os_info >/dev/null; then
        echo "ERROR: lib.sh source failed"
        exit 1
    fi
}

### ANSI color and logging functions ###
function enable_script_logs {
    local log_path=$(dirname "$LOG")

    mkdir -p "$log_path"
    chown root:root "$log_path"
    chmod 750 "$log_path"

    touch "$LOG"
    chown root:root "$LOG"
    chmod 640 "$LOG"

    exec 1> >(tee -a "$LOG")
    exec 2>&1
    log_info "Verbose logging initialized at $LOG"
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
  $(set_ansi $YELLOW $BOLD)-R            $(set_ansi)Reset Splunk user password
  $(set_ansi $YELLOW $BOLD)-u            $(set_ansi)Print Splunk package URLs
  $(set_ansi $YELLOW $BOLD)-l <path>     $(set_ansi)Install from a locally cloned GitHub repository (provide filesystem path to repo)
  $(set_ansi $YELLOW $BOLD)-g <url>      $(set_ansi)Change the GitHub URL for downloading files (for local network hosting)
  $(set_ansi $YELLOW $BOLD)-a <path>     $(set_ansi)Add a new monitor (use only after installation)
  $(set_ansi $YELLOW $BOLD)-n            $(set_ansi)Disable colored output
  $(set_ansi $YELLOW $BOLD)-D            $(set_ansi)Debug your installation
  $(set_ansi $YELLOW $BOLD)-V            $(set_ansi)Show verbose output"
    echo
    echo "$(set_ansi $GREEN $BOLD)Available packages:$(set_ansi)
  $(set_ansi $MAGENTA $BOLD)auto $(set_ansi)(default; autodetects best package format based on OS)
  $(set_ansi $MAGENTA $BOLD)deb $(set_ansi)(Debian-based distros)
  $(set_ansi $MAGENTA $BOLD)rpm $(set_ansi)(RHEL-based distros)
  $(set_ansi $MAGENTA $BOLD)tgz $(set_ansi)(generic .tgz file)
  $(set_ansi $MAGENTA $BOLD)docker $(set_ansi)(Docker container - good for Alpine)
  $(set_ansi $MAGENTA $BOLD)* $(set_ansi)(Provide any Splunk package download link)

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

function download_or_local {
    local resource=$1
    local output=$2

    if [[ -z "${resource:-}" ]]; then
        log_error "Resource is required"
        return 1
    fi

    if [[ -z "${output:-}" ]]; then
        log_error "Output is required"
        return 1
    fi

    if [[ "$LOCAL" == "true" && "$resource" == "$GITHUB_URL"* ]]; then
        # Assume the URL is a local file path
        if [[ ! -f "$resource" ]]; then
            log_error "Local file not found: $resource"
            return 1
        fi
        cp "$resource" "$output"
        log_debug "Copied from local Github to $output"
        return 0
    fi

    download "$resource" "$output"
    if [ $? -ne 0 ]; then
        log_error "Failed to download $resource"
        return 1
    fi
}

function check_os_compatibility {
    log_info "Autodetecting OS / package manager"
    get_os_info || { log_error "Failed to detect OS information"; exit 1; }
    
    if [[ "$OS_FAMILY" == *alpine* ]]; then
        log_error "Alpine/Docker installation not implemented yet"
        exit 1
        # log_debug "Setting package type to docker for Alpine"
        # PACKAGE="docker"
    fi

    log_debug "Detected OS: $OS_FAMILY, Package Manager: $PM"
}

function debug_installation {
    # Check if Splunk is installed
    if ! test -e "$SPLUNK_HOME/bin/splunk"; then
        log_error "Splunk is not installed."
        return 1
    fi
    # Check if owned by correct user
    local owner=$(ls -ld "$SPLUNK_HOME" | awk '{print $3}')
    if [ "$owner" != "$SPLUNK_USERNAME" ]; then
        log_warning "Splunk installation is owned by $owner instead of $SPLUNK_USERNAME."
    fi
    # Check if Splunk services are running
    if ! "$SPLUNK_HOME/bin/splunk" status &>/dev/null; then
        log_warning "Splunk services are not running."
    else
        log_info "Splunk services are running."
    fi
    # Check if Splunk can connect to indexer (if forwarder)
    if [ "$INDEXER" == false ]; then
        # Check if forward server is set
        if ! "$SPLUNK_HOME/bin/splunk" list forward-server &>/dev/null; then
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
    if "$SPLUNK_HOME/bin/splunk" list monitor &>/dev/null; then
        log_info "Splunk monitors are set up."
    else
        log_warning "No Splunk monitors are set up."
    fi
}

### Installation functions ###
function install_dependencies {
    log_info "Installing dependencies. Please be patient..."

    # TODO: install and configure aide
    install_package wget curl acl unzip
    if [ "$PM" == "apt-get" ]; then
        install_package debsums
    else
        install_package rpm
    fi

    # TODO: check could be improved
    local syslog_installed=false
    for f in /var/log/syslog /var/log/auth.log /var/log/secure /var/log/auth.log; do
        if test -e "$f"; then
            syslog_installed=true
            break
        fi
    done

    if ! $syslog_installed; then
        install_package rsyslog
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
    if [ "$INDEXER" != true ] && [ "$ADDITIONAL_LOGGING_ONLY" == false ]; then
        if [[ $IP == "" ]]; then
            log_error "Please provide the IP of the splunk indexer (-h for help)"
            exit 1
        fi
    fi

    # Check that script is being run as root
    if [ "$EUID" -eq 0 ]; then
        log_debug "Script is being run as root"
    else
        log_error "Please run this script as root"
        exit 1
    fi

    # Check if home directory exists for current user. Splunk commands 
    # are aliases for http request methods, and ~/.splunk contains the 
    # auth tokens, so without it, Splunk fails to install.
    if [ ! -d "$HOME" ]; then
        log_warning "No home directory for current user $(whoami). Creating home directory"
        mkdir -p /home/"$(whoami)"
        chown "$(whoami)":"$(whoami)" /home/"$(whoami)"
    fi
}

function prep_install {
    local link="$1"
    local filename="$2"

    log_info "Downloading package from $link. Please wait..."
    download_or_local "$link" "./$filename"

    if [ "$DOWNLOAD_ONLY" == true ]; then
        log_info "Download-only flag set. Exiting after download."
        exit 0
    fi

    if [ $REINSTALL == true ]; then
        # TODO: this needs to be revisited
        # TODO: detect existing splunk version
        log_info "Reinstall flag set. Preparing to reinstall..."
        log_info "Backing up existing installation to $SPLUNK_HOME-bak"
        cp -r -p $SPLUNK_HOME $SPLUNK_HOME-bak &>/dev/null

        log_info "Stopping existing Splunk services"
        /opt/splunk/bin/splunk stop -f &>/dev/null
        /opt/splunk/bin/splunkforwarder stop -f &>/dev/null
        /opt/splunk/bin/splunk disable boot-start &>/dev/null
        /opt/splunk/bin/splunkforwarder disable boot-start &>/dev/null

        local option=$(get_input_string "Would you like to remove any existing Splunk packages? (Y/n): " | tr -d ' ')
        if [[ $option != "n" ]]; then
            log_info "Removing any existing Splunk packages"
            remove_package splunk
            remove_package splunkforwarder
        fi
        rm -rf $SPLUNK_HOME
    fi
}

function install_splunk_package {
    local link="$1"

    case "$link" in
        *.deb )
            prep_install "$link" splunk.deb
            log_info "Installing package..."
            log_info "Even though it may look hung, please be patient - this may take several minutes"
            install_package ./splunk.deb
        ;;
        *.rpm )
            prep_install "$link" splunk.rpm
            log_info "Installing package..."
            log_info "Even though it may look hung, please be patient - this may take several minutes"
            install_package ./splunk.rpm
        ;;
        *.tgz|*.tar.gz )
            prep_install "$link" splunk.tgz
            log_info "Extracting to $SPLUNK_HOME"
            tar -xvf splunk.tgz -C /opt/ &> /dev/null
            # TODO: make sure it actually extracts to $SPLUNK_HOME
            chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME
        ;;
        *)
            log_error "Could not determine package type: $link"
            exit 1
        ;;
    esac
}

function install_splunk {
    # If Splunk does not already exist:
    if ! test -e "$SPLUNK_HOME/bin/splunk" || [[ "$REINSTALL" == true ]] || [[ "$DOWNLOAD_ONLY" == true ]]; then
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
                    local link="$indexer_deb"
                else
                    log_info "Selected .deb for forwarder"
                    local link="$deb"
                fi
            ;;
            rpm )
                echo
                if [ "$INDEXER" == true ]; then
                    log_info "Selected indexer .rpm"
                    local link="$indexer_rpm"
                else
                    log_info "Selected forwarder .rpm"
                    local link="$rpm"
                fi
            ;;
            tgz|tar|linux )
                log_info "Installing generic .tgz package"
                echo
                if [ "$INDEXER" == true ]; then
                    log_info "Selected indexer .tgz"
                    local link="$indexer_tgz"
                else
                    log_info "Selected forwarder .tgz"
                    local link="$tgz"
                fi
            ;;
            docker )
                log_error "Docker installation not implemented yet"
                exit 1
                # log_info "Installing Docker image"
                # echo
                # if [ "$INDEXER" == true ]; then
                #     log_error "Docker image for indexer is not yet supported. Please use a different package type."
                #     exit 1
                # else
                #     log_info "Selected forwarder Docker image"
                #     local image="$docker_image"
                # fi

                # mkdir splunk-docker
                # cd splunk-docker

                # # Create docker container
                # download_or_local "$GITHUB_URL/splunk/docker-compose.yaml" ./docker-compose.yaml
                # echo "SPLUNK_IMAGE=$image" > .env
                # SPLUNK_PASSWORD=$(get_password 8)
                # echo "SPLUNK_PASSWORD=$SPLUNK_PASSWORD" >> .env
                # docker compose up -d

                # # Install add-ons
                # docker cp $0 splunk:/tmp
                # docker exec -it -u root splunk /tmp/splunk.sh -S
                # return
            ;;
            *)
                # catch-all statement for unknown packages
                eval "local link=\$$PACKAGE"
                if [[ -z $link ]]; then
                    log_error "Unknown package: $PACKAGE"
                    print_usage
                    exit 1
                else
                    log_info "Installing $PACKAGE"
                fi
            ;;
        esac

        install_splunk_package "$link"
    else
        log_info "Install already exists. Proceeding to configure Splunk."
    fi
}

function reset_splunk_password {
    # Set splunk password
    log_info "Enter a password for the $SPLUNK_USERNAME user"
    local min_length=8
    local password=""
    local confirm_password=""

    while true; do
        # Ask for password
        password=$(get_silent_input_string "Password: ")
        echo

        # Confirm password
        confirm_password=$(get_silent_input_string "Confirm password: ")
        echo

        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
            continue
        fi

        if [ "${#password}" -lt $min_length ]; then
            echo "Password must be at least $min_length characters long. Please retry."
            continue
        fi

        break
    done
    SPLUNK_PASSWORD="$password"

    if ! echo "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" | chpasswd; then
        log_error "Failed to set password for $SPLUNK_USERNAME user. Please try again."
        reset_splunk_password
        return
    fi
    log_info "Password for $SPLUNK_USERNAME user has been set."
    log_info "Please restart Splunk to apply the changes."
    # Add splunk user as forwarder/indexer admin
    log_info "Adding $SPLUNK_USERNAME user to user-seed.conf"
    sh -c "printf '[user_info]\nUSERNAME = $SPLUNK_USERNAME\nPASSWORD = $SPLUNK_PASSWORD' > $SPLUNK_HOME/etc/system/local/user-seed.conf"
    rm "$SPLUNK_HOME/etc/passwd" &>/dev/null

    # log_info "Please remember these credentials for when Splunk asks for them later during the configuration process"
}

function create_splunk_user {
    local set_pass=true

    # Create splunk user/group
    if id $SPLUNK_USERNAME &>/dev/null; then
        log_info "$SPLUNK_USERNAME user exists"

        if [ -f "$SPLUNK_HOME/etc/passwd" ]; then
            log_debug "Splunk passwd file exists"
            option=$(get_input_string "$SPLUNK_USERNAME user already exists. Would you like to reset the password for the $SPLUNK_USERNAME user? You'll need to do this if you're reinstalling Splunk or setting it up for the first time. (Y/n): " | tr -d ' ')
            if [ "$option" == "n" ]; then
                set_pass=false
            fi
        fi
    else
        log_info "Creating $SPLUNK_USERNAME user"
        useradd $SPLUNK_USERNAME -d $SPLUNK_HOME
    fi

    if ! getent group $SPLUNK_USERNAME > /dev/null; then
        groupadd $SPLUNK_USERNAME
        usermod -aG $SPLUNK_USERNAME $SPLUNK_USERNAME
    fi

    if [ "$set_pass" == true ]; then
        reset_splunk_password
    fi
    # Set ACL to allow splunk to read any log files (execute needed for directories)
    log_info "Giving $SPLUNK_USERNAME user access to /var/log/"
    setfacl -Rm g:$SPLUNK_USERNAME:rx /var/log/
    setfacl -Rdm g:$SPLUNK_USERNAME:rx /var/log/

    # chown splunk installation directory
    chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME
}

function install_app {
    local temp_location="/tmp/$(basename $1)"
    download_or_local "$1" "$temp_location"
    chown $SPLUNK_USERNAME:$SPLUNK_USERNAME "$temp_location"
    sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk install app "$temp_location" -update 1
    rm "$temp_location"
}

function install_palo_alto_apps {
    log_info "Installing Palo Alto apps"
    download_or_local "https://github.com/PaloAltoNetworks/Splunk-Apps/archive/refs/tags/v8.1.3.zip" /tmp/palo.zip
    unzip -q /tmp/palo.zip -d /tmp/palo-apps/

    mv /tmp/palo-apps/Splunk-Apps-8.1.3/Splunk_TA_paloalto/ $SPLUNK_HOME/etc/apps/
    mv /tmp/palo-apps/Splunk-Apps-8.1.3/SplunkforPaloAltoNetworks/ $SPLUNK_HOME/etc/apps/
    
    chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME "$SPLUNK_HOME/etc/apps/Splunk_TA_paloalto/"
    chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME "$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/"

    rm /tmp/palo.zip
    rm -rf /tmp/palo-apps/
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
    mkdir -p $SPLUNK_HOME/etc/auth/splunkweb/
    chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME/etc/auth/splunkweb/
    $SPLUNK_HOME/bin/splunk createssl web-cert
    $SPLUNK_HOME/bin/splunk enable web-ssl

    log_info "Disabling KVSTORE (causes issues on old systems with new versions of Splunk)"
    sh -c "printf '\n[kvstore]\ndisabled=true\n' >> $SPLUNK_HOME/etc/system/local/server.conf"

    log_info "Fixing domain list error"
    sudo -H -u $SPLUNK_USERNAME sh -c "echo allowedDomainList = allow_all >> $SPLUNK_HOME/etc/system/local/alert_actions.conf"

    log_info "Disabling new UI"
    sudo -H -u $SPLUNK_USERNAME sh -c "printf '[feature:modern-nav]\nenable_nav_vnext = false\n' > /opt/splunk/etc/system/local/web-features.conf"

    log_info "Installing indexer apps"
    rm /tmp/app.spl &>/dev/null

    log_info "Installing CCDC Splunk app"
    install_app "$GITHUB_URL/splunk/ccdc-app.spl"

    # log_info "Installing Windows SOC Splunk app"
    # install_app "$GITHUB_URL/splunk/windows-security-operations-center_20.tgz"

    # log_info "Installing Sysmon Security Monitoring Splunk app"
    # install_app "$GITHUB_URL/splunk/sysmon-security-monitoring-app-for-splunk_4013.tgz"

    log_info "Installing Audit Hex Value Decoder app"
    install_app "$GITHUB_URL/splunk/TA-LinuxAuditDecoder.spl"

    install_palo_alto_apps
}

# Checks for existence of a file or directory and add it as a monitor if it exists
# Arguments:
#   $1: Path of log source
#   $2: Index name
#   $3: Sourcetype (optional)
function add_monitor {
    local source=$1
    local index=$2
    local sourcetype=$3
    if [ -e "$source" ]; then
        if [ "$sourcetype" != "" ]; then
            sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor "$source" -index "$index" -sourcetype "$sourcetype" &> /dev/null
        else
            sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add monitor "$source" -index "$index" &> /dev/null
        fi
        if [ $? -eq 24 ]; then
            log_error "Failed to login; please try again"
            add_monitor "$source" "$index" "$sourcetype"
            return
        fi
        if [ $? -ne 0 ]; then
            log_error "Failed to add monitor for $source"
            return
        fi
        log_info "Successfully added monitor for $source"
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
    local source=$1
    local index=$2
    local interval=$3
    local sourcetype=$4
    if [ -e "$source" ]; then
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

function setup_forwarder {
    log_info "Configuring forwarder"
    sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk add forward-server "$1":9997
    # sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk enable deploy-client
    # sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk set deploy-poll "$1":8089
}

function setup_splunk {
    print_banner "Setting Up Splunk"
    
    # Install Splunk package
    install_splunk

    # Check if Splunk installed successfully
    if [ ! -e $SPLUNK_HOME/bin/splunk ]; then
        log_error "Splunk failed to install"
        exit 1
    else
        log_info "Splunk installed successfully"
    fi

    # Create splunk system user and splunk service user
    create_splunk_user

    # TODO: set default hostname to fix windows name mistmatch errors
    # sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk set default-hostname $(hostname)
    # sh -c "echo '\$PreserveFQDN on' > /etc/rsyslog.d/19-fqdn.conf"
    # systemctl restart rsyslog
    # sh -c "printf '[default]\nhost = $(hostname -s)\n' > $SPLUNK_HOME/etc/system/local/server.conf"
    # $SPLUNK_HOME/etc/system/local/inputs.conf

    log_info "Starting splunk"
    # For some reason, splunk start doesn't work on Ubuntu 14 without a tty...
    # faketty sudo -H -u splunk $SPLUNK_HOME/bin/splunk start --accept-license --no-prompt
    until sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk restart --accept-license --no-prompt; do
        log_error "Splunk failed to start, retrying..."
        sleep 1
    done

    # Make sure the correct username/password is provided before continuing
    # (this will do nothing if already logged in)
    local res=-1
    while [ $res -ne 0 ]; do
        if [ "$SPLUNK_PASSWORD" == "" ]; then
            # TODO: verify this twice
            # TODO: also try passing -auth to every splunk command
            SPLUNK_PASSWORD=$(get_silent_input_string "Enter the password for $SPLUNK_USERNAME user: ")
        fi
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk login -auth "$SPLUNK_USERNAME:$SPLUNK_PASSWORD"
        res=$?
    done

    # Setup indexer or forwarder-specific configurations
    if [ "$INDEXER" == true ]; then
        setup_indexer
    else
        setup_forwarder "$IP"
    fi

    # Addresses a bug where Splunk may not have the correct permissions
    chown -R $SPLUNK_USERNAME:$SPLUNK_USERNAME $SPLUNK_HOME

    # Create alias
    log_info "Creating alias in PATH for splunk executable"
    local bin_dir=$(dirname $(which yes))
    ln -s $SPLUNK_HOME/bin/splunk $bin_dir/splunk

    # Install Add-ons - these provide monitors for the logs we want to collect
    log_info "Installing Nix Add-on"
    install_app "$GITHUB_URL/splunk/linux/Splunk_TA_nix.spl"

    log_info "Installing CCDC Add-on"
    install_app "$GITHUB_URL/splunk/linux/ccdc-add-on.spl"

    if [ "$INDEXER" == true ]; then
        log_info "Adding monitors for Splunk web logs"
        add_monitor "$SPLUNK_HOME/var/log/splunk/web_access.log" "web"
    fi
}

function final_restart_splunk {
    print_banner "Finalizing Splunk Setup"
    until sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk stop; do
        log_error "Splunk failed to stop, retrying..."
        sleep 1
    done
    if command -v systemctl &> /dev/null; then
        log_debug "Enabling start on boot with systemd"
        $SPLUNK_HOME/bin/splunk enable boot-start -systemd-managed 1 -user $SPLUNK_USERNAME
        if [ "$INDEXER" == true ]; then
            systemctl enable Splunkd
            systemctl start Splunkd
        else
            systemctl enable SplunkForwarder
            systemctl start SplunkForwarder
        fi
    else
        log_debug "Not a systemd machine; using splunk start"
        log_warning "Splunk will not start automatically on boot"
        sudo -H -u $SPLUNK_USERNAME $SPLUNK_HOME/bin/splunk start
    fi

    echo
}

function install_additional_logging {
    print_banner "Installing Additional Logging Sources"
    log_info "Installing:"
    echo "   - auditd (file monitor)"
    echo "   - snoopy (command logger)"
    
    # Install auditd
    log_info "Installing auditd..."
    download_or_local "$GITHUB_URL/log/auditd/auditd.sh" "auditd.sh"
    chmod +x auditd.sh
    ./auditd.sh
    if [ $? -ne 0 ]; then
        log_error "Auditd failed to install; please rerun ./auditd.sh later"
    else
        AUDITD_SUCCESSFUL=true
    fi
    # Give splunk group read permissions to audit logs
    # TODO: switch to splunk group instead of splunk user
    setfacl -Rm g:$SPLUNK_USERNAME:rx /var/log/audit/
    setfacl -Rdm g:$SPLUNK_USERNAME:rx /var/log/audit/

    # Install snoopy
    log_info "Installing Snoopy..."
    download_or_local "$GITHUB_URL/log/snoopy/snoopy.sh" "snoopy.sh"
    chmod +x snoopy.sh
    ./snoopy.sh
    if [ $? -ne 0 ]; then
        log_error "Snoopy failed to install; please rerun ./snoopy.sh later"
    else
        SNOOPY_SUCCESSFUL=true
    fi
    # Give splunk group read permissions to snoopy log
    setfacl -m g:$SPLUNK_USERNAME:r /var/log/snoopy.log
}
#####################################################

######################## MAIN #######################
function main {
    # TODO: revisit when splunk is stopped/started for efficiency
    # log_info "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    check_prereqs
    enable_script_logs
    check_os_compatibility
    print_banner "Installing dependencies..."
    install_dependencies

    setup_splunk
    install_additional_logging
    final_restart_splunk
    
    log_info "Finished!"

    print_banner "Summary"
    log_info "A debug log is located at $LOG"
    echo
    echo "Summary of installation:"
    echo "   Auditd successful? $(print_true_false $AUDITD_SUCCESSFUL)"
    echo "   Snoopy successful? $(print_true_false $SNOOPY_SUCCESSFUL)"
    # echo "   Sysmon successful? $SYSMON_SUCCESSFUL"
    echo
}

# Have to process -g first so that $GITHUB_URL is set before lib.sh is sourced
while getopts "$GETOPT_SPEC" opt; do
    case "$opt" in
        g)
            # Trim trailing slash if present
            GITHUB_URL="${OPTARG%/}"
            ;;
    esac
done
OPTIND=1

# Get library functions
source_libsh

# Process the rest of the command line arguments
while getopts "$GETOPT_SPEC" opt; do
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
        R)
            reset_splunk_password
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