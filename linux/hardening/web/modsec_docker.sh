#!/usr/bin/env bash

function install_modsecurity_docker {
    print_banner "Dockerized ModSecurity Installation (Strict Mode)"
    
    # Ensure Docker is installed (auto-install if necessary)
    if ! ensure_docker_installed; then
        log_error "Could not install Docker automatically. Aborting."
        return 1
    fi

    # Determine the recommended ModSecurity Docker image tag based on the OS.
    local default_image
    default_image=$(get_modsecurity_image)
    
    # In Ansible mode, use the recommended image automatically; otherwise allow user override.
    local image
    if [ "$ANSIBLE" == "true" ]; then
        image="$default_image"
        log_info "Ansible mode: Using recommended ModSecurity Docker image: $image"
    else
        read -p "Enter ModSecurity Docker image to use [default: $default_image]: " user_image
        if [ -n "$user_image" ]; then
            image="$user_image"
        else
            image="$default_image"
        fi
    fi

    # Generate the strict configuration file for ModSecurity.
    local modsec_conf
    modsec_conf=$(generate_strict_modsec_conf)

    echo "[INFO] Pulling Docker image: $image"
    sudo docker pull "$image"

    echo "[INFO] Running Dockerized ModSecurity container with strict configuration..."
    # Run the container with port mapping (adjust if needed) and mount the strict config file as read-only.
    sudo docker run -d --name dockerized_modsec -p 80:80 \
         -v "$modsec_conf":/etc/modsecurity/modsecurity.conf:ro \
         "$image"

    if sudo docker ps | grep -q dockerized_modsec; then
        log_info "Dockerized ModSecurity container 'dockerized_modsec' is running with strict settings."
        return 0
    else
        log_error "Dockerized ModSecurity container failed to start."
        return 1
    fi
}
