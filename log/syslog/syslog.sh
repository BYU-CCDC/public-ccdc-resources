#!/bin/bash
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
PORT=514

# Check that the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root"
    exit 1
fi

function print_usage {
    echo "Usage: $0 -f <central_logging_server_ip> [-g <github_url>] [-p <port>]"
    echo "  -f <central_logging_server_ip> : IP address of the central logging server"
    echo "  -g <github_url>                : URL of the GitHub repository"
    echo "  -p <port>                      : Port to send logs to (default: $PORT)"
}

# Get arguments
while getopts "hf:g:p:" opt; do
    case $opt in
        h)
            print_usage
            exit 0
            ;;
        f)
            CENTRAL_SERVER="$OPTARG"
            ;;
        g)
            # Trim trailing slash if present
            GITHUB_URL="${OPTARG%/}"
            ;;
        p)
            PORT="$OPTARG"
            ;;
        *)
            echo "Invalid option: $opt"
            print_usage
            exit 1
            ;;
    esac
done

# Get library
source lib.sh > /dev/null 2>&1 || \
    source <(curl -fsSL "$GITHUB_URL/linux/lib.sh")  > /dev/null 2>&1 || \
    source <(wget -qO- "$GITHUB_URL/linux/lib.sh")  > /dev/null 2>&1 || \
    { echo "Failed to load lib.sh"; exit 1; }
get_os_info || { log_error "Failed to detect OS information"; exit 1; }

# Check that the CENTRAL_SERVER variable is set
if [ -z "$CENTRAL_SERVER" ]; then
    log_error "Central logging server IP address is required."
    print_usage
    exit 1
fi

# Download and run splunk.sh in logging only mode
download "$GITHUB_URL/splunk/splunk.sh" splunk.sh || { log_error "Failed to download splunk.sh"; exit 1; }

# Install additional logging sources only with -L
chmod +x splunk.sh
./splunk.sh -L -g $GITHUB_URL

# Make sure rsyslog is installed
log_info "Installing dependencies..."
detect_package rsyslog || install_package rsyslog || { log_error "Failed to install rsyslog"; exit 1; }
# Make sure audisp auditd plugin is installed
detect_package audispd-plugins || install_package audispd-plugins || { log_error "Failed to install audispd-plugins"; exit 1; }

# Giving rsyslog access
if [[ "$OS_FAMILY" == *debian* ]]; then
    log_info "Giving rsyslog access to /var/log/snoopy.log and /var/log/redbaronedr/detections.log..."
    [ -f /var/log/snoopy.log ] && setfacl -m g:syslog:r /var/log/snoopy.log
    [ -f /var/log/redbaronedr/detections.log ] && setfacl -m g:syslog:r /var/log/redbaronedr/detections.log
fi

# Configuring audisp
log_info "Configuring audisp plugin..."
mkdir -p /etc/audit/plugins.d
chmod 750 /etc/audit/plugins.d
cat > /etc/audit/plugins.d/syslog.conf <<'EOF'
active = yes
direction = out
path = /sbin/audisp-syslog
type = builtin
args = LOG_LOCAL6 LOG_INFO 1
format = string
EOF

# Configure rsyslog
log_info "Configuring rsyslog to forward logs to $CENTRAL_SERVER:$PORT..."

# Download the 50-grafana.conf file from GitHub
download "$GITHUB_URL/log/syslog/50-grafana.conf" 50-grafana.conf || { log_error "Failed to download 50-grafana.conf"; exit 1; }

# Install config file
mv 50-grafana.conf /etc/rsyslog.d/50-grafana.conf
sed -i "s|<CENTRAL_LOGGING_SERVER_IP>|$CENTRAL_SERVER|g" /etc/rsyslog.d/50-grafana.conf
sed -i "s|<PORT>|$PORT|g" /etc/rsyslog.d/50-grafana.conf

# Restart rsyslog to apply the new configuration
log_info "Restarting rsyslog to apply the new configuration..."
systemctl restart rsyslog || rc-service rsyslog restart || service rsyslog restart || { log_error "Failed to restart rsyslog"; exit 1; }

log_info "Done!"