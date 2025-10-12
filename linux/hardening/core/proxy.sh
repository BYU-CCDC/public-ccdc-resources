function setup_proxy_certificates_and_config {
    print_banner "Proxy and Certificate Configuration Setup"

    # Prompt the user for required URLs
    read -p "Enter the Proxy URL (e.g., http://192.168.1.107:8000): " user_proxy
    if [ -z "$user_proxy" ]; then
        log_error "No proxy URL provided. Aborting configuration."
        return 1
    fi
    PROXY="$user_proxy"

    read -p "Enter the Certificate CRT URL (e.g., http://192.168.1.107:9000/mitmproxy-ca-cert.crt): " user_patch_url
    if [ -z "$user_patch_url" ]; then
        log_error "No certificate CRT URL provided. Aborting configuration."
        return 1
    fi
    PATCH_URL="$user_patch_url"

    read -p "Enter the Certificate PEM URL (e.g., http://192.168.1.107:9000/mitmproxy-ca-cert.pem): " user_pem_url
    if [ -z "$user_pem_url" ]; then
        log_error "No certificate PEM URL provided. Aborting configuration."
        return 1
    fi
    PEM_URL="$user_pem_url"

    log_info "Proxy is set to: $PROXY"
    log_info "CRT will be downloaded from: $PATCH_URL"
    log_info "PEM will be downloaded from: $PEM_URL"

    # Now, detect which OS we’re running and call the corresponding helper.
    if command -v yum &>/dev/null ; then
        RHEL_proxy_setup
    elif command -v apt-get &>/dev/null ; then
        if grep -qi Ubuntu /etc/os-release; then
            UBUNTU_proxy_setup
        else
            DEBIAN_proxy_setup
        fi
    elif command -v apk &>/dev/null ; then
        ALPINE_proxy_setup
    elif command -v slapt-get &>/dev/null || grep -qi Slackware /etc/os-release ; then
        SLACK_proxy_setup
    else
        log_error "Unsupported or unknown OS for proxy/certificate configuration."
        return 1
    fi

    log_info "Proxy and certificate configuration completed."
}

function RHEL_proxy_setup {
    log_info "Setting up proxy and installing certificate for RHEL-based systems..."
    yum install -y ca-certificates curl
    # Download the certificate files via the proxy
    curl -o cert.crt --proxy "$PROXY" "$PATCH_URL"
    curl -o cert.pem --proxy "$PROXY" "$PEM_URL"
    # Copy certificates to the system's anchor directory
    cp cert.crt /etc/pki/ca-trust/source/anchors/
    cp cert.pem /etc/pki/ca-trust/source/anchors/
    # Set permissions (644 is typical for certificates)
    chmod 644 /etc/pki/ca-trust/source/anchors/cert.crt
    chmod 644 /etc/pki/ca-trust/source/anchors/cert.pem
    # Update the certificate store
    update-ca-trust
    # Configure yum proxy settings
    echo "proxy=$PROXY" | tee -a /etc/yum.conf >/dev/null
    # Optionally, add proxy environment variables to ~/.bashrc
    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc
    source ~/.bashrc
    log_info "RHEL-based proxy and certificate configuration completed."
}

function DEBIAN_proxy_setup {
    log_info "Setting up proxy and installing certificate for Debian-based systems..."
    update_package_cache
    sudo apt-get install -y ca-certificates curl
    # Download certificate files via the proxy
    curl -o cert.crt --proxy "$PROXY" "$PATCH_URL"
    curl -o certPem.pem --proxy "$PROXY" "$PEM_URL"
    # Convert PEM file to CRT format (or simply rename)
    mv certPem.pem certPem.crt
    # Create extra directory if it does not exist
    mkdir -p /usr/share/ca-certificates/extra
    cp cert.crt /usr/share/ca-certificates/extra/cert.crt
    cp certPem.crt /usr/share/ca-certificates/extra/certPem.crt
    # Update certificates using dpkg and update-ca-certificates
    dpkg-reconfigure ca-certificates
    update-ca-certificates
    # Configure apt to use the proxy
    echo "Acquire::http::Proxy \"$PROXY\";" | tee /etc/apt/apt.conf.d/proxy.conf >/dev/null
    echo "Acquire::https::Proxy \"$PROXY\";" | tee -a /etc/apt/apt.conf.d/proxy.conf >/dev/null
    # Set proxy environment variables for current session
    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc
    source ~/.bashrc
    log_info "Debian-based proxy and certificate configuration completed."
}

function UBUNTU_proxy_setup {
    log_info "Detected Ubuntu. Using Debian configuration..."
    DEBIAN_proxy_setup
}

function ALPINE_proxy_setup {
    log_info "Setting up proxy and installing certificate for Alpine Linux..."
    apk add --no-cache ca-certificates curl
    # Download the certificate file (using the CRT URL)
    curl -o cert.pem --proxy "$PROXY" "$PATCH_URL"
    cp cert.pem /usr/local/share/ca-certificates/
    update-ca-certificates
    # Configure repository proxy settings (if desired)
    # Here, you might add proxy URLs to /etc/apk/repositories if required.
    echo "export http_proxy=\"$PROXY\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY\"" >> ~/.bashrc
    source ~/.bashrc
    log_info "Alpine Linux proxy and certificate configuration completed."
}
