#!/usr/bin/env bash
set -e

###############################################################################
# GLOBAL VARIABLES FOR OS DETECTION (used by DB/WAF logic)
###############################################################################
OS_ID=""
OS_VERSION=""
OS_MAJOR=""
recommended_image=""

###############################################################################
# UTILITY: print_banner
###############################################################################
print_banner() {
    echo "======================================"
    echo "$1"
    echo "======================================"
}

###############################################################################
# 1) DETECT LINUX PACKAGE MANAGER
#    (Mirrors the Python snippet's detect_linux_package_manager)
###############################################################################
detect_linux_package_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt-get"
    elif command -v apt &>/dev/null; then
        # Some systems use 'apt' instead of apt-get
        echo "apt-get"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    else
        return 1
    fi
}

###############################################################################
# 2) CHECK DOCKER GROUP AND FIX IF NEEDED (BEFORE INSTALLATION)
###############################################################################
fix_docker_group() {
    local current_user
    current_user="$(whoami 2>/dev/null || echo "$USER")"

    # Check if docker group exists
    if ! getent group docker >/dev/null; then
        echo "[INFO] Docker group does not exist. Creating docker group."
        sudo groupadd docker
    fi

    # Check if user is in docker group
    if id -nG "$current_user" | grep -qw "docker"; then
        echo "[INFO] User '$current_user' is already a member of the 'docker' group."
        return 0
    else
        echo "[INFO] Adding user '$current_user' to the 'docker' group."
        if ! sudo usermod -aG docker "$current_user"; then
            echo "[WARN] Could not add user to docker group."
            echo "[HINT] You may need to install the 'usermod' command. (e.g., 'apt install shadow-utils')"
            return 1 # Indicate failure to add user to group
        fi
    fi

    echo "[INFO] New permissions will be applied after a re-login or running 'newgrp docker'."

    # Attempt to apply group changes without requiring a full logout/login
    if command -v newgrp >/dev/null; then
        sudo newgrp docker
        echo "[INFO] 'newgrp docker' command executed to attempt to apply group changes."
    else
        echo "[WARN] 'newgrp' command not found.  Log out and back in to ensure group membership is updated."
    fi

    return 0 # Indicate success (though relogin is still needed)
}

###############################################################################
# 3) ATTEMPT INSTALL DOCKER (Mirrors your Python snippet, but in Bash)
###############################################################################
attempt_install_docker_linux() {
    local pm
    pm="$(detect_linux_package_manager)" || {
        echo "[ERROR] No recognized package manager found on Linux. Cannot auto-install Docker."
        return 1
    }

    echo "[INFO] Attempting to install Docker using '${pm}' on Linux..."
    case "${pm}" in
        apt-get)
            sudo apt-get update -y
            # Use the official Docker repository - Corrected way to add repo
            sudo apt-get install -y apt-transport-https ca-certificates curl gnupg > /dev/null 2>&1 # Suppress key-related warnings
            # Add Docker GPG key (more robust method)
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            # Add the Docker repository to APT sources
            DOCKER_APT_REPO="deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
            echo "$DOCKER_APT_REPO" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update -y
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        yum)
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            sudo systemctl enable docker
            sudo systemctl start docker
            ;;
        dnf)
            sudo dnf install -y dnf-plugins-core
            sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            sudo systemctl enable docker
            sudo systemctl start docker
            ;;
        zypper)
            sudo zypper refresh
            # Add the official Docker repository
            sudo zypper addrepo https://download.docker.com/linux/opensuse/docker-ce.repo
            sudo zypper --non-interactive install docker-ce docker-ce-cli containerd.io docker-compose-plugin
            sudo systemctl enable docker
            sudo systemctl start docker
            ;;
        *)
            echo "[ERROR] Package manager '${pm}' is not fully supported for auto-installation."
            return 1
            ;;
    esac

    echo "[INFO] Docker installation attempt completed. Checking if Docker is now available..."
    if command -v docker &>/dev/null; then
        sudo systemctl enable docker || echo "[WARN] Could not enable docker service."
        sudo systemctl start docker || echo "[WARN] Could not start docker service."
        return 0
    else
        return 1
    fi
}

###############################################################################
# 4) ATTEMPT INSTALL DOCKER COMPOSE (Mirrors your Python snippet, but in Bash)
###############################################################################
attempt_install_docker_compose_linux() {
    # Docker Compose is now a plugin, so this function is mostly for ensuring it's available
    if command -v docker-compose &>/dev/null; then
        echo "[INFO] Docker Compose is already installed."
        return 0
    elif command -v docker compose &>/dev/null; then
         echo "[INFO] Docker Compose is already installed (as docker compose)."
         return 0
    else
        echo "[WARN] Docker Compose not found, please install docker-compose-plugin"
        return 1
    fi
}

###############################################################################
# 5) can_run_docker
#    Return 0 if 'docker ps' runs without error; else non-zero.
###############################################################################
can_run_docker() {
    if command -v docker &>/dev/null; then
        if docker ps &>/dev/null; then
            return 0
        fi
    fi
    return 1
}

###############################################################################
# 6) ENSURE DOCKER IS RUNNABLE
###############################################################################
ensure_docker_is_runnable() {
    if can_run_docker; then
        echo "[INFO] Docker is running and accessible."
        return 0
    else
       echo "[WARN] Docker is installed, but not accessible.  Attempting to fix permissions..."

        # Attempt to fix socket permissions
        if [[ -S /var/run/docker.sock ]]; then
            sudo chown root:docker /var/run/docker.sock
            sudo chmod 660 /var/run/docker.sock
            echo "[INFO] Attempted to fix /var/run/docker.sock permissions."
        else
            echo "[WARN] /var/run/docker.sock not found.  Ensure Docker daemon is running."
        fi

        echo "[WARN] Docker is installed, but not accessible. Fixing docker group..."
        if fix_docker_group; then
            echo "[INFO] Docker group fixed. Please log out/in or run 'newgrp docker' and try again."
             # Give Docker a chance to start and the user a chance to log out/in
             sleep 5
        else
            echo "[ERROR] Failed to fix Docker group. Docker may not be runnable."
            return 1
        fi

       if can_run_docker; then
            echo "[INFO] Docker is now accessible."
            return 0
        else
            echo "[ERROR] Docker is still not accessible.  Log out/in or run 'newgrp docker'."
            return 1
        fi
    fi
}

###############################################################################
# 7) ensure_docker_installed
#    Checks if Docker is installed & user can run it. If missing, tries auto-install.
#    If user isn't in docker group, fix that.
###############################################################################
ensure_docker_installed() {
    # First, try fixing the docker group *before* attempting installation.
    fix_docker_group

    if can_run_docker; then
        echo "[INFO] Docker is already installed and accessible."
        return 0
    fi

    echo "[INFO] Docker not found or not accessible. Attempting installation..."
    if attempt_install_docker_linux; then
         # Give Docker a chance to start and the user a chance to log out/in
         sleep 5
        if ensure_docker_is_runnable; then
            echo "[INFO] Docker is installed and accessible on Linux now."
            return 0
        else
            echo "[WARN] Docker was installed, but is not accessible."
            return 1
        fi
    else
        echo "[ERROR] Could not auto-install Docker on Linux. Please install it manually."
        exit 1
    fi
}

###############################################################################
# 8) check_docker_compose
#    Checks if Docker Compose is installed. If not, suggests manual install.
###############################################################################
check_docker_compose() {
    if command -v docker-compose &>/dev/null; then
        echo "[INFO] Docker Compose is already installed."
        return 0
    elif command -v docker compose &>/dev/null; then
         echo "[INFO] Docker Compose is already installed (as docker compose)."
         return 0
    else
        echo "[WARN] Docker Compose not found.  Please install docker-compose-plugin or docker compose manually."
        return 1
    fi
}

###############################################################################
# 9) check_dependencies
#    Calls ensure_docker_installed + check_docker_compose.
###############################################################################
check_dependencies() {
    print_banner "Checking Docker and Docker Compose"
    ensure_docker_installed "$@"
    check_docker_compose
}

###############################################################################
# 10) detect_os_and_recommend_image
#    Reads /etc/os-release to map OS to a recommended Docker base image.
###############################################################################
detect_os_and_recommend_image() {
    print_banner "OS Detection & Docker Base Image Recommendation"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        OS_VERSION=$(echo "$VERSION_ID" | tr -d '"')
        OS_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)
    else
        echo "[WARN] Cannot detect OS information from /etc/os-release."
        OS_ID="ubuntu"
        OS_VERSION="latest"
        OS_MAJOR="latest"
        recommended_image="ubuntu:latest"
        echo "[INFO] Recommended Docker base image: $recommended_image"
        return
    fi

    case "$OS_ID" in
        ubuntu)
            case "$OS_MAJOR" in
                14) recommended_image="ubuntu:14.04" ;;
                16) recommended_image="ubuntu:16.04" ;;
                18) recommended_image="ubuntu:18.04" ;;
                20) recommended_image="ubuntu:20.04" ;;
                22) recommended_image="ubuntu:22.04" ;;
                *) recommended_image="ubuntu:latest" ;;
            esac
            ;;
        debian)
            case "$OS_MAJOR" in
                7) recommended_image="debian:7" ;;
                8) recommended_image="debian:8" ;;
                9) recommended_image="debian:9" ;;
                10) recommended_image="debian:10" ;;
                11) recommended_image="debian:11" ;;
                12) recommended_image="debian:12" ;;
                *) recommended_image="debian:latest" ;;
            esac
            ;;
        centos)
            case "$OS_MAJOR" in
                6) recommended_image="centos:6" ;;
                7) recommended_image="centos:7" ;;
                8) recommended_image="centos:8" ;;
                9) recommended_image="centos:stream9" ;;
                *) recommended_image="centos:latest" ;;
            esac
            ;;
        fedora)
            case "$OS_MAJOR" in
                25) recommended_image="fedora:25" ;;
                26) recommended_image="fedora:26" ;;
                27) recommended_image="fedora:27" ;;
                28) recommended_image="fedora:28" ;;
                29) recommended_image="fedora:29" ;;
                30) recommended_image="fedora:30" ;;
                31) recommended_image="fedora:31" ;;
                35) recommended_image="fedora:35" ;;
                *) recommended_image="fedora:latest" ;;
            esac
            ;;
        opensuse*)
            if [[ "$PRETTY_NAME" == *"Tumbleweed"* ]]; then
                recommended_image="opensuse/tumbleweed"
            elif [[ "$PRETTY_NAME" == *"Leap"* ]]; then
                case "$OS_MAJOR" in
                    15) recommended_image="opensuse/leap:15" ;;
                    *) recommended_image="opensuse/leap:latest" ;;
                esac
            else
                recommended_image="opensuse:latest"
            fi
            ;;
        *)
            recommended_image="ubuntu:latest"
            ;;
    esac

    echo "[INFO] Detected OS: ${PRETTY_NAME:-Unknown}"
    echo "[INFO] Recommended Docker base image: $recommended_image"
}

###############################################################################
# 11) setup_docker_database
#     Example DB container logic, mapping OS to MySQL versions
###############################################################################
setup_docker_database() {
    print_banner "Setting Up Dockerized Database"

    local db_image
    if [[ "$OS_ID" == "centos" ]]; then
        case "$OS_MAJOR" in
            6) db_image="mysql:5.5" ;;
            7) db_image="mysql:5.7" ;;
            *) db_image="mysql:8.0" ;;
        esac
    elif [[ "$OS_ID" == "ubuntu" ]]; then
        if [ "$OS_MAJOR" -lt 20 ]; then
            db_image="mysql:5.7"
        else
            db_image="mysql:8.0"
        fi
    elif [[ "$OS_ID" == "debian" ]]; then
        if [ "$OS_MAJOR" -lt 10 ]; then
            db_image="mysql:5.7"
        else
            db_image="mysql:8.0"
        fi
    else
        db_image="mysql:8.0"
    fi

	# Attempt to work around permission issues by running the pull command with sudo
	echo "[INFO] Pulling the database image..."
    sudo docker pull "$db_image"

    echo "[INFO] Running the Dockerized Database container..."
    sudo docker run -d --name dockerized_db -e MYSQL_ROOT_PASSWORD=my-secret-pw -p 3306:3306 "$db_image"
    echo "[INFO] Database container 'dockerized_db' is running."
}

###############################################################################
# 12) setup_docker_modsecurity
#     Example WAF container logic, mapping OS to ModSecurity versions
###############################################################################
setup_docker_modsecurity() {
    print_banner "Setting Up Dockerized ModSecurity WAF"

    local waf_image
    if [[ "$OS_ID" == "centos" ]]; then
        case "$OS_MAJOR" in
            6) waf_image="modsecurity/modsecurity:2.8.0" ;;
            7) waf_image="modsecurity/modsecurity:2.9.3" ;;
            *) waf_image="modsecurity/modsecurity:latest" ;;
        esac
    elif [[ "$OS_ID" == "ubuntu" ]]; then
        if [ "$OS_MAJOR" -lt 20 ]; then
            waf_image="modsecurity/modsecurity:2.9.2"
        else
            waf_image="modsecurity/modsecurity:latest"
        fi
    else
        waf_image="modsecurity/modsecurity:latest"
    fi

	# Attempt to work around permission issues by running the pull command with sudo
    echo "[INFO] Pulling the ModSecurity image..."
    sudo docker pull "$waf_image"

    echo "[INFO] Running the Dockerized ModSecurity WAF container..."
    sudo docker run -d --name dockerized_waf -p 80:80 "$waf_image"
    echo "[INFO] ModSecurity WAF container 'dockerized_waf' is running."
}

###############################################################################
# 13) display_menu
#     Menu-based approach to choose steps or do everything
###############################################################################
display_menu() {
    echo "======================================"
    echo "Dockerization Script Menu"
    echo "======================================"
    echo "1) Check & Install Docker and Docker Compose"
    echo "2) OS Detection and Recommended Base Image"
    echo "3) Setup Dockerized Database"
    echo "4) Setup Dockerized ModSecurity WAF"
    echo "5) Full Automatic Installation (all steps)"
    echo "6) Exit"
    echo -n "Enter your choice (1-6): "
    read -r choice
    case "$choice" in
        1)
            check_dependencies
            ;;
        2)
            detect_os_and_recommend_image
            ;;
        3)
            detect_os_and_recommend_image
            setup_docker_database
            ;;
        4)
            detect_os_and_recommend_image
            setup_docker_modsecurity
            ;;
        5)
            check_dependencies
            detect_os_and_recommend_image
            setup_docker_database
            setup_docker_modsecurity
            ;;
        6)
            echo "Exiting."
            exit 0
            ;;
        *)
            echo "Invalid option. Exiting."
            exit 1
            ;;
    esac
}

###############################################################################
# MAIN EXECUTION
###############################################################################
if [[ "$1" == "--menu" ]]; then
    display_menu
else
    # Full automatic installation mode if no flag is provided
    check_dependencies
    detect_os_and_recommend_image
    setup_docker_database
    setup_docker_modsecurity
fi

echo "[INFO] All tasks completed successfully."
