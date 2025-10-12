function change_root_password {
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Skipping root password change."
        return 0
    fi
    print_banner "Changing Root Password"
    while true; do
        root_password=$(get_silent_input_string "Enter new root password: ")
        echo
        root_password_confirm=$(get_silent_input_string "Confirm new root password: ")
        echo
        if [ "$root_password" != "$root_password_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done
    if echo "root:$root_password" | sudo chpasswd; then
        log_info "Root password updated successfully."
    else
        log_error "ERROR: Failed to update root password."
    fi
}

function create_ccdc_users {
    if [ "$ANSIBLE" == "true" ]; then
        print_banner "Creating ccdc users (Ansible mode: Non-interactive)"
        default_password="ChangeMe123!"
        for user in "${ccdc_users[@]}"; do
            if ! id "$user" &>/dev/null; then
                if [ -f "/bin/bash" ]; then
                    sudo useradd -m -s /bin/bash "$user"
                else
                    sudo useradd -m -s /bin/sh "$user"
                fi
                log_info "Creating $user with default password."
                echo "$user:$default_password" | sudo chpasswd
                sudo usermod -aG $sudo_group "$user"
            else
                log_info "$user exists. Skipping interactive password update."
            fi
        done
        return 0
    fi
    print_banner "Creating ccdc users"
    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
            if [[ "$user" == "ccdcuser1" ]]; then
                log_info "$user already exists. Do you want to update the password? (y/N): "
                read -r update_choice
                if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
                    while true; do
                        password=$(get_silent_input_string "Enter new password for $user: ")
                        echo
                        password_confirm=$(get_silent_input_string "Confirm new password for $user: ")
                        echo
                        if [ "$password" != "$password_confirm" ]; then
                            echo "Passwords do not match. Please retry."
                        else
                            if ! echo "$user:$password" | sudo chpasswd; then
                                log_error "ERROR: Failed to update password for $user"
                            else
                                log_info "Password for $user updated."
                                break
                            fi
                        fi
                    done
                fi
            elif [[ "$user" == "ccdcuser2" ]]; then
                log_info "$user already exists. Do you want to update the password? (y/N): "
                read -r update_choice
                if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
                    while true; do
                        password=$(get_silent_input_string "Enter new password for $user: ")
                        echo
                        password_confirm=$(get_silent_input_string "Confirm new password for $user: ")
                        echo
                        if [ "$password" != "$password_confirm" ]; then
                            echo "Passwords do not match. Please retry."
                        else
                            if ! echo "$user:$password" | sudo chpasswd; then
                                log_error "ERROR: Failed to update password for $user"
                            else
                                log_info "Password for $user updated."
                                break
                            fi
                        fi
                    done
                fi
                log_info "Would you like to change the root password? (y/N): "
                read -r root_choice
                if [[ "$root_choice" == "y" || "$root_choice" == "Y" ]]; then
                    change_root_password
                fi
            else
                log_info "$user already exists. Skipping..."
            fi
        else
            log_info "$user not found. Creating user..."
            if [ -f "/bin/bash" ]; then
                sudo useradd -m -s /bin/bash "$user"
            elif [ -f "/bin/sh" ]; then
                sudo useradd -m -s /bin/sh "$user"
            else
                log_error "ERROR: Could not find valid shell"
                exit 1
            fi
            if [[ "$user" == "ccdcuser1" ]]; then
                log_info "Enter the password for $user:"
                while true; do
                    password=$(get_silent_input_string "Enter password for $user: ")
                    echo
                    password_confirm=$(get_silent_input_string "Confirm password for $user: ")
                    echo
                    if [ "$password" != "$password_confirm" ]; then
                        echo "Passwords do not match. Please retry."
                    else
                        if ! echo "$user:$password" | sudo chpasswd; then
                            log_error "ERROR: Failed to set password for $user"
                        else
                            log_info "Password for $user has been set."
                            break
                        fi
                    fi
                done
                log_info "Adding $user to $sudo_group group"
                sudo usermod -aG $sudo_group "$user"
            elif [[ "$user" == "ccdcuser2" ]]; then
                log_info "Enter the password for $user:"
                while true; do
                    password=$(get_silent_input_string "Enter password for $user: ")
                    echo
                    password_confirm=$(get_silent_input_string "Confirm password for $user: ")
                    echo
                    if [ "$password" != "$password_confirm" ]; then
                        echo "Passwords do not match. Please retry."
                    else
                        if ! echo "$user:$password" | sudo chpasswd; then
                            log_error "ERROR: Failed to set password for $user"
                        else
                            log_info "Password for $user has been set."
                            break
                        fi
                    fi
                done
                log_info "Would you like to change the root password? (y/N): "
                read -r root_choice
                if [[ "$root_choice" == "y" || "$root_choice" == "Y" ]]; then
                    change_root_password
                fi
            else
                if echo "$user:$default_password" | sudo chpasswd; then
                    log_info "$user created with the default password."
                else
                    log_error "ERROR: Failed to set default password for $user"
                fi
            fi
        fi
        echo
    done
}

function change_passwords {
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Skipping bulk password change."
        return 0
    fi
    print_banner "Changing user passwords"
    exclusions=("root" "${ccdc_users[@]}")
    log_info "Currently excluded users: ${exclusions[*]}"
    log_info "Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '$1 != "nobody" {print $1}' "${exclusions[*]}")
    log_info "Enter the new password to be used for all users."
    while true; do
        password=""
        confirm_password=""
        password=$(get_silent_input_string "Enter password: ")
        echo
        confirm_password=$(get_silent_input_string "Confirm password: ")
        echo
        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done
    echo
    log_info "Changing passwords..."
    for user in $targets; do
        if ! echo "$user:$password" | sudo chpasswd; then
            log_error "ERROR: Failed to change password for $user"
        else
            log_info "Password for $user has been changed."
        fi
    done
}

function disable_users {
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Skipping user disabling."
        return 0
    fi
    print_banner "Disabling users"
    exclusions=("${ccdc_users[@]}")
    exclusions+=("root")
    log_info "Currently excluded users: ${exclusions[*]}"
    log_info "Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '/\/bash$|\/sh$|\/ash$|\/zsh$/{print $1}' "${exclusions[*]}")
    echo
    log_info "Disabling user accounts using usermod -L and setting shell to nologin..."
    for user in $targets; do
        if sudo usermod -L "$user"; then
            log_info "Account for $user has been locked (usermod -L)."
            if sudo usermod -s /usr/sbin/nologin "$user"; then
                log_info "Login shell for $user set to nologin."
            else
                log_error "ERROR: Failed to set nologin shell for $user."
            fi
        else
            log_error "ERROR: Failed to lock account for $user using usermod -L."
        fi
    done
}

function remove_sudoers {
    print_banner "Removing sudoers"
    log_info "Removing users from the $sudo_group group"
    exclusions=("ccdcuser1")
    log_info "Currently excluded users: ${exclusions[*]}"
    log_info "Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '{print $1}' "${exclusions[*]}")
    echo
    log_info "Removing sudo users..."
    for user in $targets; do
        if groups "$user" | grep -q "$sudo_group"; then
            log_info "Removing $user from $sudo_group group"
            sudo gpasswd -d "$user" "$sudo_group"
        fi
    done
}
