# ---------- minimal helpers ----------
function print_banner {
    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
}

# Non-silent prompt
function get_input_string {
    read -r -p "$1" input
    echo "$input"
}

# Silent prompt for secrets
function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

# Multiline list input until blank line
function get_input_list {
    local input_list=()
    local continue="true"
    while [ "$continue" != "false" ]; do
        input=$(get_input_string "Enter input: (one entry per line; hit enter to continue): ")
        if [ "$input" == "" ]; then
            continue="false"
        else
            input_list+=("$input")
        fi
    done
    echo "${input_list[@]}"
}

# ---------- backup: select, zip, encrypt, stage copies ----------
function backup_directories {
    print_banner "Backup Directories"

    # Detect common web/db paths present on many CCDC targets
    local default_dirs=( "/var/www/html" "/etc/apache2" "/etc/mysql" "/var/lib/apache2" "/var/lib/mysql" )

    local detected_dirs=()
    echo "[*] Scanning for critical directories..."
    for d in "${default_dirs[@]}"; do
        if [ -d "$d" ]; then
            detected_dirs+=("$d")
        fi
    done

    local backup_list=()
    if [ ${#detected_dirs[@]} -gt 0 ]; then
        echo "[*] The following critical directories were detected:"
        for d in "${detected_dirs[@]}"; do echo "   $d"; done
        read -r -p "Would you like to back these up? (y/N): " detected_choice
        if [[ "$detected_choice" == "y" || "$detected_choice" == "Y" ]]; then
            backup_list=("${detected_dirs[@]}")
        fi
    else
        echo "[*] No critical directories detected."
    fi

    echo
    read -r -p "Would you like to backup any additional files or directories? (y/N): " additional_choice
    if [[ "$additional_choice" == "y" || "$additional_choice" == "Y" ]]; then
        echo "[*] Enter additional directories/files to backup (one per line; hit ENTER on a blank line to finish):"
        additional_dirs=$(get_input_list)
        for item in $additional_dirs; do
            path=$(readlink -f "$item")
            if [ -e "$path" ]; then
                backup_list+=("$path")
            else
                echo "[X] ERROR: $path does not exist."
            fi
        done
    fi

    if [ ${#backup_list[@]} -eq 0 ]; then
        echo "[*] No directories or files selected for backup. Exiting backup."
        return
    fi

    # Name archive
    local backup_name=""
    while true; do
        backup_name=$(get_input_string "Enter a name for the backup archive (without extension .zip): ")
        if [ -n "$backup_name" ]; then
            [[ "$backup_name" != *.zip ]] && backup_name="${backup_name}.zip"
            break
        else
            echo "[X] ERROR: Backup name cannot be blank."
        fi
    done

    echo "[*] Creating archive..."
    zip -r "$backup_name" "${backup_list[@]}" >/dev/null 2>&1 || {
        echo "[X] ERROR: Failed to create archive."
        return
    }
    echo "[*] Archive created: $backup_name"

    # Encrypt archive with AES-256-CBC + salt, PBKDF via openssl default
    echo "[*] Encrypting the archive."
    local enc_password=""
    while true; do
        enc_password=$(get_silent_input_string "Enter encryption password: "); echo
        local enc_confirm=$(get_silent_input_string "Confirm encryption password: "); echo
        if [ "$enc_password" != "$enc_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    local enc_archive="${backup_name}.enc"
    openssl enc -aes-256-cbc -salt -in "$backup_name" -out "$enc_archive" -k "$enc_password" || {
        echo "[X] ERROR: Encryption failed."
        return
    }
    echo "[*] Archive encrypted: $enc_archive"

    # Optionally place copies of encrypted archive to multiple locations
    echo
    echo "[*] Provide directories where you'd like to COPY the encrypted backup."
    echo "[*] Enter one directory path per line. Press ENTER on a blank line to finish."
    while true; do
        local user_dir
        user_dir=$(get_input_string "Directory to store the encrypted backup (blank to finish): ")
        if [ -z "$user_dir" ]; then
            echo "[*] Done storing the encrypted backup in specified directories."
            break
        fi

        user_dir=$(readlink -f "$user_dir")
        if [ ! -d "$user_dir" ]; then
            echo "[*] Directory '$user_dir' does not exist. Creating it..."
            sudo mkdir -p "$user_dir" || { echo "[X] ERROR: Could not create directory '$user_dir'. Skipping..."; continue; }
        fi

        cp "$enc_archive" "$user_dir/" && \
            echo "[*] Encrypted archive copied to $user_dir/" || \
            echo "[X] ERROR: Failed to copy encrypted archive to $user_dir/"
    done

    # Remove plaintext
    rm -f "$backup_name"
    echo "[*] Cleanup complete. Only the encrypted archive remains (in the current directory unless removed)."
}

# ---------- restore: decrypt, extract, deploy ----------
function unencrypt_backups {
    print_banner "Decrypt Backup"

    echo "Enter the base name of the encrypted backup (do NOT include '.zip.enc'):"
    read -r enc_base_name
    if [ -z "$enc_base_name" ]; then
        echo "[X] No backup name provided. Aborting."
        return
    fi

    local enc_file="${enc_base_name}.zip.enc"
    if [ ! -f "$enc_file" ]; then
        echo "[X] ERROR: File '$enc_file' does not exist."
        return
    fi

    local dec_zip="${enc_base_name}.zip"
    local max_attempts=3
    local attempt=1
    local success=0

    while [ $attempt -le $max_attempts ]; do
        echo
        read -r -s -p "Enter decryption password (Attempt $attempt of $max_attempts): " dec_password
        echo
        openssl enc -d -aes-256-cbc -in "$enc_file" -out "$dec_zip" -k "$dec_password" 2>/dev/null || {
            echo "[X] ERROR: Decryption failed. Check your password."
            attempt=$((attempt+1))
            continue
        }
        success=1
        break
    done

    if [ $success -eq 0 ]; then
        echo "[X] Too many failed attempts. Aborting decryption."
        rm -f "$dec_zip" 2>/dev/null || true
        return
    fi

    echo "[*] Decrypted archive saved as '$dec_zip'."

    local folder_name
    read -r -p "Enter the folder name to place the entire extracted backup (default: wazuh): " folder_name
    if [ -z "$folder_name" ]; then folder_name="wazuh"; fi

    local temp_extraction_dir
    temp_extraction_dir="$(mktemp -d)"
    unzip -q "$dec_zip" -d "$temp_extraction_dir"
    echo "[*] Decrypted archive extracted to temporary location: $temp_extraction_dir"

    echo
    echo "[*] Provide directories where you'd like to store the fully extracted backup."
    echo "[*] Enter one directory path per line. Press ENTER on a blank line to finish."
    while true; do
        local user_dir
        user_dir=$(get_input_string "Directory to store extracted backup (blank to finish): ")
        if [ -z "$user_dir" ]; then
            echo "[*] Done placing the extracted backup."
            break
        fi

        user_dir=$(readlink -f "$user_dir")
        if [ ! -d "$user_dir" ]; then
            echo "[*] Directory '$user_dir' does not exist. Creating it..."
            sudo mkdir -p "$user_dir" || { echo "[X] ERROR: Could not create directory '$user_dir'. Skipping..."; continue; }
        fi

        local final_path="$user_dir/$folder_name"
        sudo mkdir -p "$final_path" || { echo "[X] ERROR: Could not create subdirectory '$final_path'. Skipping..."; continue; }
        sudo cp -R "$temp_extraction_dir/"* "$final_path/"
        echo "[*] Extracted backup copied into '$final_path/'"
    done

    rm -f "$dec_zip"
    rm -rf "$temp_extraction_dir"
    echo "[*] Decryption process completed."
}
