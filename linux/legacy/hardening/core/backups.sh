#!/usr/bin/env bash

function backup_directories {
    if [ "$ANSIBLE" == "true" ]; then
        log_warning "Ansible mode: Skipping encrypted backup creation."
        return 0
    fi

    print_banner "Backup Directories"

    local default_dirs=(
        "/var/www/html" "/etc/apache2" "/etc/mysql" "/var/lib/apache2" "/var/lib/mysql"
    )
    local detected_dirs=()

    log_info "Scanning for critical directories..."
    local d
    for d in "${default_dirs[@]}"; do
        if [ -d "$d" ]; then
            detected_dirs+=("$d")
        fi
    done

    local backup_list=()
    if [ ${#detected_dirs[@]} -gt 0 ]; then
        log_info "The following critical directories were detected:"
        for d in "${detected_dirs[@]}"; do
            log_info "  $d"
        done
        local detected_choice
        detected_choice=$(get_input_string "Would you like to back these up? (y/N): ")
        if [[ "$detected_choice" == "y" || "$detected_choice" == "Y" ]]; then
            backup_list=("${detected_dirs[@]}")
        fi
    else
        log_info "No critical directories detected."
    fi

    local additional_choice
    additional_choice=$(get_input_string "Would you like to backup any additional files or directories? (y/N): ")
    if [[ "$additional_choice" == "y" || "$additional_choice" == "Y" ]]; then
        log_info "Enter additional directories/files to backup (one per line; hit ENTER on a blank line to finish):"
        local additional_dirs
        additional_dirs=$(get_input_list)
        local item
        for item in $additional_dirs; do
            local path
            path=$(readlink -f "$item")
            if [ -e "$path" ]; then
                backup_list+=("$path")
            else
                log_error "${path} does not exist."
            fi
        done
    fi

    if [ ${#backup_list[@]} -eq 0 ]; then
        log_warning "No directories or files selected for backup. Exiting backup workflow."
        return 0
    fi

    local backup_name=""
    while true; do
        backup_name=$(get_input_string "Enter a name for the backup archive (without extension .zip): ")
        if [ -n "$backup_name" ]; then
            [[ "$backup_name" != *.zip ]] && backup_name="${backup_name}.zip"
            break
        else
            log_error "Backup name cannot be blank."
        fi
    done

    log_info "Creating archive..."
    if ! zip -r "$backup_name" "${backup_list[@]}" >/dev/null 2>&1; then
        log_error "Failed to create archive."
        return 1
    fi
    log_success "Archive created: $backup_name"

    log_info "Encrypting the archive."
    local enc_password=""
    while true; do
        enc_password=$(get_silent_input_string "Enter encryption password: ")
        printf '\n'
        local enc_confirm
        enc_confirm=$(get_silent_input_string "Confirm encryption password: ")
        printf '\n'
        if [ "$enc_password" != "$enc_confirm" ]; then
            log_error "Passwords do not match. Please retry."
        else
            break
        fi
    done

    local enc_archive="${backup_name}.enc"
    if ! openssl enc -aes-256-cbc -salt -in "$backup_name" -out "$enc_archive" -k "$enc_password"; then
        log_error "Encryption failed."
        return 1
    fi
    log_success "Archive encrypted: $enc_archive"

    log_info "Provide directories where you'd like to COPY the encrypted backup."
    log_info "Enter one directory path per line. Press ENTER on a blank line to finish."
    while true; do
        local user_dir
        user_dir=$(get_input_string "Directory to store the encrypted backup (blank to finish): ")
        if [ -z "$user_dir" ]; then
            log_info "Done storing the encrypted backup in specified directories."
            break
        fi

        user_dir=$(readlink -f "$user_dir")
        if [ ! -d "$user_dir" ]; then
            log_info "Directory '$user_dir' does not exist. Creating it..."
            if ! sudo mkdir -p "$user_dir"; then
                log_error "Could not create directory '$user_dir'. Skipping..."
                continue
            fi
        fi

        if cp "$enc_archive" "$user_dir/"; then
            log_success "Encrypted archive copied to $user_dir/"
        else
            log_error "Failed to copy encrypted archive to $user_dir/"
        fi
    done

    rm -f "$backup_name"
    log_info "Cleanup complete. Only the encrypted archive remains (in the current directory unless removed)."
}

function unencrypt_backups {
    if [ "$ANSIBLE" == "true" ]; then
        log_warning "Ansible mode: Skipping backup decryption."
        return 0
    fi

    print_banner "Decrypt Backup"

    local enc_base_name
    enc_base_name=$(get_input_string "Enter the base name of the encrypted backup (do NOT include '.zip.enc'): ")
    if [ -z "$enc_base_name" ]; then
        log_error "No backup name provided. Aborting."
        return 1
    fi

    local enc_file="${enc_base_name}.zip.enc"
    if [ ! -f "$enc_file" ]; then
        log_error "File '$enc_file' does not exist."
        return 1
    fi

    local dec_zip="${enc_base_name}.zip"
    local max_attempts=3
    local attempt=1
    local success=0

    while [ $attempt -le $max_attempts ]; do
        printf '\n'
        local dec_password
        dec_password=$(get_silent_input_string "Enter decryption password (Attempt $attempt of $max_attempts): ")
        printf '\n'
        if ! openssl enc -d -aes-256-cbc -in "$enc_file" -out "$dec_zip" -k "$dec_password" 2>/dev/null; then
            log_error "Decryption failed. Check your password."
            attempt=$((attempt + 1))
            continue
        fi
        success=1
        break
    done

    if [ $success -eq 0 ]; then
        log_error "Too many failed attempts. Aborting decryption."
        rm -f "$dec_zip" 2>/dev/null || true
        return 1
    fi

    log_success "Decrypted archive saved as '$dec_zip'."

    local folder_name
    folder_name=$(get_input_string "Enter the folder name to place the entire extracted backup (default: wazuh): ")
    if [ -z "$folder_name" ]; then
        folder_name="wazuh"
    fi

    local temp_extraction_dir
    temp_extraction_dir="$(mktemp -d)"
    if ! unzip -q "$dec_zip" -d "$temp_extraction_dir"; then
        log_error "Failed to unzip decrypted archive."
        rm -f "$dec_zip"
        rm -rf "$temp_extraction_dir"
        return 1
    fi
    log_success "Decrypted archive extracted to temporary location: $temp_extraction_dir"

    log_info "Provide directories where you'd like to store the fully extracted backup."
    log_info "Enter one directory path per line. Press ENTER on a blank line to finish."
    while true; do
        local user_dir
        user_dir=$(get_input_string "Directory to store extracted backup (blank to finish): ")
        if [ -z "$user_dir" ]; then
            log_info "Done placing the extracted backup."
            break
        fi

        user_dir=$(readlink -f "$user_dir")
        if [ ! -d "$user_dir" ]; then
            log_info "Directory '$user_dir' does not exist. Creating it..."
            if ! sudo mkdir -p "$user_dir"; then
                log_error "Could not create directory '$user_dir'. Skipping..."
                continue
            fi
        fi

        local final_path="$user_dir/$folder_name"
        if ! sudo mkdir -p "$final_path"; then
            log_error "Could not create subdirectory '$final_path'. Skipping..."
            continue
        fi

        if sudo cp -R "$temp_extraction_dir/"* "$final_path/"; then
            log_success "Extracted backup copied into '$final_path/'"
        else
            log_error "Failed to copy extracted backup into '$final_path/'."
        fi
    done

    rm -f "$dec_zip"
    rm -rf "$temp_extraction_dir"
    log_success "Decryption process completed."
}

function backups {
    if [ "$ANSIBLE" == "true" ]; then
        log_warning "Ansible mode: Skipping backups menu."
        return 0
    fi

    while true; do
        print_banner "Backups"
        echo "1) Create encrypted backup"
        echo "2) Decrypt encrypted backup"
        echo "3) Return to previous menu"
        local choice
        choice=$(get_input_string "Select an option: ")
        case "$choice" in
            1)
                backup_directories
                ;;
            2)
                unencrypt_backups
                ;;
            3|"" )
                log_info "Exiting backups menu."
                break
                ;;
            *)
                log_warning "Invalid selection. Please try again."
                ;;
        esac
    done
}
