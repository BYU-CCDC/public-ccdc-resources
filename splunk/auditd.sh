#!/bin/bash
###################### GLOBALS ######################
pm=""
GITHUB_URL='https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main'
#####################################################

##################### FUNCTIONS #####################
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
    sudo wget $GITHUB_URL/splunk/ccdc.rules
    sudo mv ./ccdc.rules $CUSTOM_RULE_FILE
    sudo chown root:root $CUSTOM_RULE_FILE
    sudo chmod 600 $CUSTOM_RULE_FILE

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
echo "[*] Beginning of script"
detect_package_manager
install_auditd
add_audit_rules
echo "[*] End of script"