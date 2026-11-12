#!/bin/bash
set -o pipefail
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
GETOPT_SPEC="g:l:"

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

function install_snoopy {
    local version="$1"
    local snoopy_config='/etc/snoopy.ini'
    local snoopy_log='/var/log/snoopy.log'


    log_info "Installing Snoopy (trying version $version)"
    if [ -e /usr/local/lib/libsnoopy.so ]; then
        log_info "Snoopy is already installed"
        SNOOPY_SUCCESSFUL=true
        return 0
    fi

    if ! download \
      "https://github.com/a2o/snoopy/raw/install/install/install-snoopy.sh" \
      "install-snoopy.sh"; then
      log_error "Failed to download Snoopy installer"
      return 1
    fi
    chmod 755 install-snoopy.sh

    # Run install script
    ./install-snoopy.sh "$version" > /dev/null

    if [ $? -ne 0 ]; then
        # If it fails
        log_error "Snoopy installation for version $version failed"
        return 1
    fi


    # If it succeeds
    # Download config
    if ! download \
        "$GITHUB_URL/log/snoopy/snoopy.ini" \
        "$snoopy_config"; then
        log_error "Failed to download Snoopy configuration"
        return 1
    fi
    chown root:root "$snoopy_config"
    chmod 644 "$snoopy_config"

    # Unfortunately required by snoopy in order to use a log file other than syslog/messages
    touch "$snoopy_log"
    chmod 622 "$snoopy_log"
    log_debug "Set Snoopy output to $snoopy_log."

    # Restart snoopy
    # TODO: these commands aren't consistent across all systems
    if [ -x "/usr/local/sbin/snoopyctl" ]; then
        /usr/local/sbin/snoopyctl disable
        /usr/local/sbin/snoopyctl enable
    elif [ -x "/usr/local/sbin/snoopy-enable" ] && [ -x "/usr/local/sbin/snoopy-disable" ]; then
        /usr/local/sbin/snoopy-disable
        /usr/local/sbin/snoopy-enable
    elif command -v snoopyctl >/dev/null 2>&1; then
        snoopyctl disable
        snoopyctl enable
    else
        log_warning "Could not find snoopyctl or snoopy-enable/snoopy-disable scripts to restart snoopy. You may need to restart the server to apply changes."
    fi

    log_info "Snoopy installed successfully."
    # See https://github.com/a2o/snoopy/issues/212
    log_warning "NOTE: Unless you restart the server, Snoopy may not pick up on commands from existing processes."
}

# Execution starts here
if [ "$EUID" -ne 0 ]; then
    echo "Error: please run this script as root"
    return 1
fi

# Have to process -g and -l first so that $GITHUB_URL is set before lib.sh is sourced
while getopts "$GETOPT_SPEC" opt; do
    case "$opt" in
        g)
            # Trim trailing slash if present
            GITHUB_URL="${OPTARG%/}"
            ;;
        l)
            LOCAL=true
            GITHUB_URL="$(realpath "$OPTARG")"  # Use local path for GITHUB_URL
            ;;
    esac
done
OPTIND=1

# Get library functions
source_libsh
get_os_info || { log_error "Failed to detect OS information"; exit 1; }

# Install snoopy dependencies
# TODO: test this
if [[ "$OS_FAMILY" == *rhel* ]] || [[ "$OS_FAMILY" == *centos* ]]; then
    install_package epel-release
fi
install_package gcc gzip make procps socat tar wget

# Try installing the lastest snoopy
install_snoopy "stable"
if [ $? -ne 0 ]; then
    # Try older versions if stable version fails
    install_snoopy "2.4.15"
    if [ $? -ne 0 ]; then
        install_snoopy "2.3.2"
        if [ $? -ne 0 ]; then
            return 1
        fi
    fi
fi