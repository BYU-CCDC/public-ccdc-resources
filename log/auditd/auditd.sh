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

# Execution starts here
if [ "$EUID" -ne 0 ]; then
    echo "Error: please run this script as root"
    exit 1
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

# Install auditd package
log_info "Installing auditd package"
install_package auditd 2>/dev/null
if [ $? -ne 0 ]; then
    install_package audit 2>/dev/null
    if [ $? -ne 0 ]; then
        log_error "Failed to install auditd or audit package"
        exit 1
    fi
fi

# Add custom rules
log_info "Adding custom audit rules"
if ! [ -d "/etc/audit/rules.d/" ]; then
    log_error "Could not locate audit rules directory"
    exit 1
fi

# Download custom rule file
custom_rule_file="/etc/audit/rules.d/ccdc.rules"
if ! download_or_local "$GITHUB_URL/log/auditd/ccdc.rules" "$custom_rule_file"; then
    log_error "Failed to retrieve custom audit rules"
    exit 1
fi
chown root:root "$custom_rule_file"
chmod 600 "$custom_rule_file"

# Add home directory rules
# TODO: suppress output?
echo '' | tee -a "$custom_rule_file" > /dev/null
for dir in /home/*; do
    if [ -d "$dir" ]; then
        echo "-w ${dir}/.ssh/ -p w -k CCDC_modify_ssh_user" | tee -a "$custom_rule_file" > /dev/null

        if [ -f "$dir/.bashrc" ]; then
            echo "-w ${dir}/.bashrc -p w -k CCDC_modify_bashrc_user" | tee -a "$custom_rule_file" > /dev/null
        fi
    fi
done

# Reload auditd
augenrules --load > /dev/null 2>&1

# Enable/start auditd
enable_start_service auditd
if [ $? -ne 0 ]; then
    enable_start_service audit
fi

# TODO: check that rules were loaded successfully

if [ "$VERBOSE" == true ]; then
    log_debug "Applied rules:"
    auditctl -l
fi