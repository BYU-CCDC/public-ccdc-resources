#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi
    print_info "Detected distribution: $DISTRO $VERSION"
}

install_chrony() {
    print_info "Installing Chrony..."
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            apt-get install -y chrony
            CHRONY_CONF="/etc/chrony/chrony.conf"
            CHRONY_SERVICE="chrony"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf install -y chrony
            else
                yum install -y chrony
            fi
            CHRONY_CONF="/etc/chrony.conf"
            CHRONY_SERVICE="chronyd"
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm chrony
            CHRONY_CONF="/etc/chrony.conf"
            CHRONY_SERVICE="chronyd"
            ;;
        *)
            print_error "Unsupported distribution: $DISTRO"
            exit 1
            ;;
    esac
    
    print_info "Chrony installed successfully"
}

backup_config() {
    if [ -f "$CHRONY_CONF" ]; then
        BACKUP="${CHRONY_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$CHRONY_CONF" "$BACKUP"
        print_info "Backed up existing config to $BACKUP"
    fi
}

configure_server() {
    print_info "Configuring Chrony as NTP server..."
    
    print_warn "Enter the network subnet to allow clients (e.g., 192.168.1.0/24 or 10.0.0.0/8):"
    read -r ALLOWED_SUBNET
    
    if [ -z "$ALLOWED_SUBNET" ]; then
        print_error "Subnet cannot be empty"
        exit 1
    fi
    
    cat > "$CHRONY_CONF" <<EOF
pool 2.pool.ntp.org iburst
pool 1.pool.ntp.org iburst
pool 0.pool.ntp.org iburst

allow $ALLOWED_SUBNET
local stratum 10

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync

logdir /var/log/chrony
log measurements statistics tracking
EOF

    configure_firewall_server
    print_info "Server configuration complete"
}

configure_client() {
    if [ -z "$NTP_SERVER" ]; then
        print_error "NTP server IP/hostname not provided"
        exit 1
    fi
    
    print_info "Configuring Chrony as NTP client pointing to $NTP_SERVER..."
    
    cat > "$CHRONY_CONF" <<EOF
server $NTP_SERVER iburst
pool 2.pool.ntp.org iburst

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync

logdir /var/log/chrony
log measurements statistics tracking
EOF

    print_info "Client configuration complete"
}

configure_firewall_server() {
    print_info "Configuring iptables firewall..."
    
    if ! command -v iptables &> /dev/null; then
        print_warn "iptables not found, skipping firewall configuration"
        return
    fi
    
    print_info "Adding iptables rule to allow NTP from $ALLOWED_SUBNET..."
    
    if ! iptables -C INPUT -p udp --dport 123 -s "$ALLOWED_SUBNET" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p udp --dport 123 -s "$ALLOWED_SUBNET" -j ACCEPT
        print_info "Added iptables rule: allow UDP 123 from $ALLOWED_SUBNET"
    else
        print_info "iptables rule already exists"
    fi
    
    save_iptables_rules
}

save_iptables_rules() {
    print_info "Saving iptables rules..."
    
    case $DISTRO in
        ubuntu|debian)
            if ! dpkg -l | grep -q iptables-persistent; then
                print_info "Installing iptables-persistent..."
                DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
            fi
            
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            print_info "iptables rules saved to /etc/iptables/rules.v4"
            ;;
            
        fedora|rhel|centos|rocky|almalinux)
            if ! rpm -q iptables-services &> /dev/null; then
                print_info "Installing iptables-services..."
                if command -v dnf &> /dev/null; then
                    dnf install -y iptables-services
                else
                    yum install -y iptables-services
                fi
                systemctl enable iptables
            fi
            
            service iptables save 2>/dev/null || iptables-save > /etc/sysconfig/iptables
            print_info "iptables rules saved to /etc/sysconfig/iptables"
            ;;
            
        arch|manjaro)
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/iptables.rules
            
            if systemctl list-unit-files | grep -q iptables.service; then
                systemctl enable iptables.service
            fi
            print_info "iptables rules saved to /etc/iptables/iptables.rules"
            ;;
    esac
}

show_iptables_rules() {
    print_info "Current iptables rules for NTP:"
    iptables -L INPUT -n -v | grep -E "dpt:123|Chain INPUT"
    echo ""
}

start_chrony() {
    print_info "Starting and enabling Chrony service..."
    
    systemctl restart "$CHRONY_SERVICE"
    systemctl enable "$CHRONY_SERVICE"
    
    if systemctl is-active --quiet "$CHRONY_SERVICE"; then
        print_info "Chrony service is running"
    else
        print_error "Failed to start Chrony service"
        exit 1
    fi
}

show_status() {
    print_info "Chrony Status:"
    echo ""
    
    systemctl status "$CHRONY_SERVICE" --no-pager | head -n 10
    echo ""
    
    print_info "NTP Sources:"
    chronyc sources
    echo ""
    
    print_info "Time Synchronization Status:"
    chronyc tracking
    echo ""
    
    if [ "$MODE" = "server" ]; then
        print_info "Server Information:"
        echo "  - Listening on UDP port 123"
        echo "  - Allowed subnet: $ALLOWED_SUBNET"
        echo "  - Clients can use this server at: $(hostname -I | awk '{print $1}')"
    else
        print_info "Client Information:"
        echo "  - Syncing from server: $NTP_SERVER"
    fi
}

main() {
    MODE=$1
    NTP_SERVER=$2
    
    if [ "$MODE" != "server" ] && [ "$MODE" != "client" ]; then
        print_error "Usage: $0 {server|client} [server-ip]"
        echo ""
        echo "Examples:"
        echo "  Server: sudo $0 server"
        echo "  Client: sudo $0 client 192.168.1.100"
        exit 1
    fi
    
    if [ "$MODE" = "client" ] && [ -z "$NTP_SERVER" ]; then
        print_error "Client mode requires server IP/hostname"
        echo "Usage: sudo $0 client <server-ip>"
        exit 1
    fi
    
    print_info "Starting Chrony setup in $MODE mode..."
    
    detect_distro
    install_chrony
    backup_config
    
    if [ "$MODE" = "server" ]; then
        configure_server
    else
        configure_client
    fi
    
    start_chrony
    sleep 3
    show_status
    
    if [ "$MODE" = "server" ]; then
        show_iptables_rules
    fi
    
    echo ""
    print_info "Chrony setup completed successfully!"
    echo ""
    print_info "Useful commands:"
    echo "  - Check sources:     chronyc sources -v"
    echo "  - Check tracking:    chronyc tracking"
    echo "  - Force sync:        chronyc makestep"
    echo "  - View clients:      chronyc clients (server only)"
    echo "  - Service status:    systemctl status $CHRONY_SERVICE"
    if [ "$MODE" = "server" ]; then
        echo "  - View firewall:     iptables -L INPUT -n -v | grep 123"
    fi
}

main "$@"
