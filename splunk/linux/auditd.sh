#!/bin/bash
###################### GLOBALS ######################
pm=""
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
LOCAL=false
#####################################################

##################### FUNCTIONS #####################
function download {
    url=$1
    output=$2

    if [[ "$LOCAL" == "true" && "$url" == "$GITHUB_URL"* ]]; then
        # Assume the URL is a local file path
        if [[ ! -f "$url" ]]; then
            error "Local file not found: $url"
            return 1
        fi
        cp "$url" "$output"
        info "Copied from local Github to $output"
        return 0
    fi
    
    # TODO: figure out how to fix the progress bar
    if ! wget -O "$output" --no-check-certificate "$url"; then
        # error "Failed to download with wget. Trying wget with older TLS version..."
        # if ! wget -O "$output" --secure-protocol=TLSv1 --no-check-certificate "$url"; then
            error "Failed to download with wget. Trying with curl..."
            if ! curl -L -o "$output" -k "$url"; then
                error "Failed to download with curl."
            fi
        # fi
    fi
}

function detect_package_manager {
    if command -v apt &>/dev/null; then
        echo "[*] apt detected (Debian-based OS)"
        pm="apt"
        return
    fi

    if command -v dnf &>/dev/null; then
        echo "[*] dnf detected (Fedora-based OS)"
        pm="dnf"
        return
    fi

    if command -v yum &>/dev/null; then
        echo "[*] yum detected (RHEL-based OS)"
        pm="yum"
        return
    fi

    if command -v zypper &>/dev/null; then
        echo "[*] zypper detected (OpenSUSE-based OS)"
        pm="zypper"
        return
    fi
}

function install_auditd {
    echo "[*] Installing auditd package"
    sudo $pm install -y auditd
    if command -v systemctl &> /dev/null; then
        sudo systemctl enable auditd
        sudo systemctl start auditd
    elif command -v service &> /dev/null; then
        sudo service auditd start
    fi
}

function add_audit_rules {
    echo "[*] Adding custom audit rules"
    if ! sudo [ -d "/etc/audit/rules.d/" ]; then
        echo "[x] ERROR: Could not locate audit rules directory"
        return
    fi
    CUSTOM_RULE_FILE='/etc/audit/rules.d/ccdc.rules'

    # Download custom rule file
    download $GITHUB_URL/splunk/linux/ccdc.rules ./ccdc.rules
    sudo chown root:root ./ccdc.rules
    sudo chmod 600 $CUSTOM_RULE_FILE
    sudo mv ./ccdc.rules $CUSTOM_RULE_FILE

    # Add home directory rules
    echo '' | sudo tee -a $CUSTOM_RULE_FILE
    for dir in /home/*; do
        if [ -d "$dir" ]; then
            echo "-w ${dir}/.ssh/ -p w -k CCDC_modify_ssh_user" | sudo tee -a $CUSTOM_RULE_FILE

            if [ -f "$dir/.bashrc" ]; then
                echo "-w ${dir}/.bashrc -p w -k CCDC_modify_bashrc_user" | sudo tee -a $CUSTOM_RULE_FILE
            fi
        fi
    done

    sudo augenrules --load
    sudo service auditd reload

    echo "[*] Applied rules:"
    sudo auditctl -l
}
#####################################################

####################### START #######################
while getopts "hg:l:" opt; do
    case $opt in
        h)
            print_options
            exit 0
            ;;
        g)
            GITHUB_URL=$OPTARG
            ;;
        l)
            LOCAL=true
            GITHUB_URL="$(realpath "$OPTARG")"  # Use local path for GITHUB_URL
            ;;
        \?)
            error "Invalid option: $OPTARG"
            print_usage
            exit 1
            ;;
        :)
            error "Option -$OPTARG requires an argument (-h for help)"
            exit 1
            ;;
    esac
done

detect_package_manager
install_auditd
add_audit_rules