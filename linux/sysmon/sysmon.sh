#!/bin/bash
# Usage: ./sysmon.sh <distro> <version>
#
# Supported OS versions:
# - Ubuntu 18-23
# - Debian 9-12
# - Fedora 33-34, 36-38
# - RHEL 7-9
# - CentOS 7-8
# - SLES 12, 15
# - OpenSUSE (Leap) 15

###################### GLOBALS ######################
DISTRO=""
VERSION=""
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
LOCAL=false

centos_7_sysmon="https://packages.microsoft.com/centos/7/prod/Packages/s/sysmonforlinux-1.3.3-0.el8.x86_64.rpm"
centos_7_sysinternals="https://packages.microsoft.com/centos/7/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
centos_8_sysmon="https://packages.microsoft.com/centos/8/prod/Packages/s/sysmonforlinux-1.0.2-1.x86_64.rpm"
centos_8_sysinternals="https://packages.microsoft.com/centos/8/prod/Packages/s/sysinternalsebpf-1.0.2-1.x86_64.rpm"
debian_10_sysmon="https://packages.microsoft.com/debian/10/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.1.0-0_amd64.deb"
debian_10_sysinternals="https://packages.microsoft.com/debian/10/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.1.0-0_amd64.deb"
debian_11_sysmon="https://packages.microsoft.com/debian/11/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.3.5_amd64.deb"
debian_11_sysinternals="https://packages.microsoft.com/debian/11/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.4.0_amd64.deb"
debian_12_sysmon="https://packages.microsoft.com/debian/12/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.3.5_amd64.deb"
debian_12_sysinternals="https://packages.microsoft.com/debian/12/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.4.0_amd64.deb"
debian_9_sysmon="https://packages.microsoft.com/debian/9/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.0.2-1_amd64.deb"
debian_9_sysinternals="https://packages.microsoft.com/debian/9/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.0.2-1_amd64.deb"
fedora_33_sysmon="https://packages.microsoft.com/fedora/33/prod/Packages/s/sysmonforlinux-1.0.2-1.x86_64.rpm"
fedora_33_sysinternals="https://packages.microsoft.com/fedora/33/prod/Packages/s/sysinternalsebpf-1.0.2-1.x86_64.rpm"
fedora_34_sysmon="https://packages.microsoft.com/fedora/34/prod/Packages/s/sysmonforlinux-1.0.2-1.x86_64.rpm"
fedora_34_sysinternals="https://packages.microsoft.com/fedora/34/prod/Packages/s/sysinternalsebpf-1.0.2-1.x86_64.rpm"
fedora_36_sysmon="https://packages.microsoft.com/fedora/36/prod/Packages/s/sysmonforlinux-1.3.0-0.el8.x86_64.rpm"
fedora_36_sysinternals="https://packages.microsoft.com/fedora/36/prod/Packages/s/sysinternalsebpf-1.2.0-0.el8.x86_64.rpm"
fedora_37_sysmon="https://packages.microsoft.com/fedora/37/prod/Packages/s/sysmonforlinux-1.3.3-0.el8.x86_64.rpm"
fedora_37_sysinternals="https://packages.microsoft.com/fedora/37/prod/Packages/s/sysinternalsebpf-1.3.0-0.el8.x86_64.rpm"
fedora_38_sysmon="https://packages.microsoft.com/fedora/38/prod/Packages/s/sysmonforlinux-1.3.3-0.el8.x86_64.rpm"
fedora_38_sysinternals="https://packages.microsoft.com/fedora/38/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
fedora_40_sysmon="https://packages.microsoft.com/fedora/40/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
fedora_40_sysinternals="https://packages.microsoft.com/fedora/40/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
opensuse_15_sysmon="https://packages.microsoft.com/opensuse/15/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
opensuse_15_sysinternals="https://packages.microsoft.com/opensuse/15/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_0_sysmon="https://packages.microsoft.com/rhel/7.0/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_0_sysinternals="https://packages.microsoft.com/rhel/7.0/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_1_sysmon="https://packages.microsoft.com/rhel/7.1/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_1_sysinternals="https://packages.microsoft.com/rhel/7.1/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_2_sysmon="https://packages.microsoft.com/rhel/7.2/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_2_sysinternals="https://packages.microsoft.com/rhel/7.2/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_3_sysmon="https://packages.microsoft.com/rhel/7.3/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_3_sysinternals="https://packages.microsoft.com/rhel/7.3/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_4_sysmon="https://packages.microsoft.com/rhel/7.4/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_4_sysinternals="https://packages.microsoft.com/rhel/7.4/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_5_sysmon="https://packages.microsoft.com/rhel/7.5/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_5_sysinternals="https://packages.microsoft.com/rhel/7.5/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_8_sysmon="https://packages.microsoft.com/rhel/7.8/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_8_sysinternals="https://packages.microsoft.com/rhel/7.8/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_9_sysmon="https://packages.microsoft.com/rhel/7.9/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_9_sysinternals="https://packages.microsoft.com/rhel/7.9/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_7_sysmon="https://packages.microsoft.com/rhel/7/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_7_sysinternals="https://packages.microsoft.com/rhel/7/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_8_0_sysmon="https://packages.microsoft.com/rhel/8.0/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_8_0_sysinternals="https://packages.microsoft.com/rhel/8.0/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_8_1_sysmon="https://packages.microsoft.com/rhel/8.1/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_8_1_sysinternals="https://packages.microsoft.com/rhel/8.1/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_8_2_sysmon="https://packages.microsoft.com/rhel/8.2/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_8_2_sysinternals="https://packages.microsoft.com/rhel/8.2/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_8_sysmon="https://packages.microsoft.com/rhel/8/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_8_sysinternals="https://packages.microsoft.com/rhel/8/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_9_0_sysmon="https://packages.microsoft.com/rhel/9.0/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_9_0_sysinternals="https://packages.microsoft.com/rhel/9.0/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
rhel_9_sysmon="https://packages.microsoft.com/rhel/9/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
rhel_9_sysinternals="https://packages.microsoft.com/rhel/9/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
sles_12_sysmon="https://packages.microsoft.com/sles/12/prod/Packages/s/sysmonforlinux-1.3.3-0.el8.x86_64.rpm"
sles_12_sysinternals="https://packages.microsoft.com/sles/12/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
sles_15_sysmon="https://packages.microsoft.com/sles/15/prod/Packages/s/sysmonforlinux-1.3.5-0.el8.x86_64.rpm"
sles_15_sysinternals="https://packages.microsoft.com/sles/15/prod/Packages/s/sysinternalsebpf-1.4.0-0.el8.x86_64.rpm"
ubuntu_18_04_sysmon="https://packages.microsoft.com/ubuntu/18.04/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.1.0-0_amd64.deb"
ubuntu_18_04_sysinternals="https://packages.microsoft.com/ubuntu/18.04/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.1.0-0_amd64.deb"
ubuntu_20_04_sysmon="https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.3.5_amd64.deb"
ubuntu_20_04_sysinternals="https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.4.0_amd64.deb"
ubuntu_21_04_sysmon="https://packages.microsoft.com/ubuntu/21.04/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.0.2-1_amd64.deb"
ubuntu_21_04_sysinternals="https://packages.microsoft.com/ubuntu/21.04/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.0.2-1_amd64.deb"
ubuntu_22_04_sysmon="https://packages.microsoft.com/ubuntu/22.04/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.3.5_amd64.deb"
ubuntu_22_04_sysinternals="https://packages.microsoft.com/ubuntu/22.04/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.4.0_amd64.deb"
ubuntu_23_04_sysmon="https://packages.microsoft.com/ubuntu/23.04/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.3.3_amd64.deb"
ubuntu_23_04_sysinternals="https://packages.microsoft.com/ubuntu/23.04/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.3.0_amd64.deb"
ubuntu_24_04_sysmon="https://packages.microsoft.com/ubuntu/24.04/prod/pool/main/s/sysmonforlinux/sysmonforlinux_1.3.5_amd64.deb"
ubuntu_24_04_sysinternals="https://packages.microsoft.com/ubuntu/24.04/prod/pool/main/s/sysinternalsebpf/sysinternalsebpf_1.4.0_amd64.deb"
#####################################################

##################### FUNCTIONS #####################
function print_banner {
    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
}

function info {
    echo "[*] $1"
}

function error {
    echo "[X] $1"
}

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

function print_os_options {
    echo "Officially supported distros and versions: 
    -> ubuntu (18, 20, 21, 22, 23, 24)
    -> debian (9, 10, 11, 12)
    -> fedora (33, 34, 36, 37, 38, 40)
    -> rhel (7, 7.0 - 7.9, 8, 8.0 - 8.2, 9, 9.0)
    -> centos (7, 8)
    -> sles (12, 15)
    -> opensuse (15)"
    echo "If your distro/version isn't on here, try the most similar one"
}

function print_options {
    # TODO: update this
    echo "Usage: ./sysmon.sh <distro> <version>"
    print_os_options
    echo
    exit 1
}

function ask_for_os_info {
    if [ -z $DISTRO ] || [ -z $VERSION ]; then
        echo "What OS are you using?"
        print_os_options
        read -p "Distro: " DISTRO
        read -p "Version: " VERSION
        echo
    fi
}

function install_from_repo {
    # TODO: update this to use download function
    case $DISTRO in
        "ubuntu")
            if [ $VERSION -ge 18 ]; then
                print_banner "Ubuntu $VERSION"
                wget --no-check-certificate -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
                sudo dpkg -i packages-microsoft-prod.deb
                sudo apt-get update
                sudo apt-get install -y sysmonforlinux
            else
                error "Unsupported Ubuntu version"
                print_options
            fi
            ;;
        "debian")
            if [ $VERSION -ge 9 ]; then
                print_banner "Debian $VERSION"
                if [ $VERSION -lt 11 ]; then
                    wget --no-check-certificate -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
                    sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
                    wget --no-check-certificate -q https://packages.microsoft.com/config/debian/$VERSION/prod.list
                    sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
                    sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
                    sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
                else
                    wget --no-check-certificate -q https://packages.microsoft.com/config/debian/$VERSION/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
                    sudo dpkg -i packages-microsoft-prod.deb
                fi
                sudo apt-get update
                sudo apt-get install -y apt-transport-https
                sudo apt-get update
                sudo apt-get install -y sysmonforlinux
            else
                error "Unsupported Debian version"
                print_options
            fi
            ;;
        "fedora")
            if [ $VERSION -ge 33 ]; then
                print_banner "Fedora $VERSION"
                if [ $VERSION -lt 37 ]; then
                    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                    sudo wget --no-check-certificate -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/fedora/$VERSION/prod.repo
                else
                    sudo rpm -Uvh https://packages.microsoft.com/config/fedora/$VERSION/packages-microsoft-prod.rpm
                fi
                sudo dnf install -y sysmonforlinux
            else
                error "Unsupported Fedora version"
                print_options
            fi
            ;;
        "rhel")
            if [ $VERSION -ge 7 ]; then
                print_banner "RHEL $VERSION"
                if [ $VERSION -lt 8 ]; then
                    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                    sudo wget --no-check-certificate -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/7/prod.repo
                    sudo yum install -y sysmonforlinux
                else
                    sudo rpm -Uvh https://packages.microsoft.com/config/rhel/$VERSION/packages-microsoft-prod.rpm
                    sudo dnf install -y sysmonforlinux
                fi
            else
                error "Unsupported RHEL version"
                print_options
            fi
            ;;
        "centos")
            if [ $VERSION -ge 7 ]; then
                print_banner "CentOS $VERSION"
                sudo rpm -Uvh https://packages.microsoft.com/config/centos/$VERSION/packages-microsoft-prod.rpm
                sudo yum install -y sysmonforlinux
            else
                error "Unsupported CentOS version"
                print_options
            fi
            ;;
        "sles")
            if [ $VERSION -eq 12 ] || [ $VERSION -eq 15 ]; then
                print_banner "SLES $VERSION"
                sudo rpm -Uvh https://packages.microsoft.com/config/sles/$VERSION/packages-microsoft-prod.rpm
                sudo zypper install -y sysmonforlinux
            else
                error "Unsupported SLES version"
                print_options
            fi
            ;;
        "opensuse")
            if [ $VERSION -eq 15 ]; then
                print_banner "OpenSUSE $VERSION"
                sudo zypper install -y libicu
                sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                wget --no-check-certificate -q https://packages.microsoft.com/config/opensuse/15/prod.repo
                sudo mv prod.repo /etc/zypp/repos.d/microsoft-prod.repo
                sudo chown root:root /etc/zypp/repos.d/microsoft-prod.repo
                sudo zypper install -y sysmonforlinux
            else
                error "Unsupported OpenSUSE version"
                print_options
            fi
            ;;
        *)
            error "Unknown distro"
            print_options
            ;;
    esac
}

function install_from_package {
    # Determine the package type and get the appropriate package URLs
    case $DISTRO in
        "ubuntu")
            package_type="deb"
            case $VERSION in
                18)
                    print_banner "Ubuntu $VERSION"
                    sysmon=$ubuntu_18_04_sysmon
                    sysinternals=$ubuntu_18_04_sysinternals
                    ;;
                20)
                    print_banner "Ubuntu $VERSION"
                    sysmon=$ubuntu_20_04_sysmon
                    sysinternals=$ubuntu_20_04_sysinternals
                    ;;
                21)
                    print_banner "Ubuntu $VERSION"
                    sysmon=$ubuntu_21_04_sysmon
                    sysinternals=$ubuntu_21_04_sysinternals
                    ;;
                22)
                    print_banner "Ubuntu $VERSION"
                    sysmon=$ubuntu_22_04_sysmon
                    sysinternals=$ubuntu_22_04_sysinternals
                    ;;
                23)
                    print_banner "Ubuntu $VERSION"
                    sysmon=$ubuntu_23_04_sysmon
                    sysinternals=$ubuntu_23_04_sysinternals
                    ;;
                24)
                    print_banner "Ubuntu $VERSION"
                    sysmon=$ubuntu_24_04_sysmon
                    sysinternals=$ubuntu_24_04_sysinternals
                    ;;
                # TODO: try newer/older packages for 19 and 25
                *)
                    error "Unsupported Ubuntu version"
                    print_options
                    ;;
            esac
            ;;
        "debian")
            package_type="deb"
            case $VERSION in
                9)
                    print_banner "Debian $VERSION"
                    sysmon=$debian_9_sysmon
                    sysinternals=$debian_9_sysinternals
                    ;;
                10)
                    print_banner "Debian $VERSION"
                    sysmon=$debian_10_sysmon
                    sysinternals=$debian_10_sysinternals
                    ;;
                11)
                    print_banner "Debian $VERSION"
                    sysmon=$debian_11_sysmon
                    sysinternals=$debian_11_sysinternals
                    ;;
                12)
                    print_banner "Debian $VERSION"
                    sysmon=$debian_12_sysmon
                    sysinternals=$debian_12_sysinternals
                    ;;
                *)
                    error "Unsupported Debian version"
                    print_options
                    ;;
            esac
            ;;
        "fedora")
            package_type="rpm"
            case $VERSION in
                33)
                    print_banner "Fedora $VERSION"
                    sysmon=$fedora_33_sysmon
                    sysinternals=$fedora_33_sysinternals
                    ;;
                34)
                    print_banner "Fedora $VERSION"
                    sysmon=$fedora_34_sysmon
                    sysinternals=$fedora_34_sysinternals
                    ;;
                36)
                    print_banner "Fedora $VERSION"
                    sysmon=$fedora_36_sysmon
                    sysinternals=$fedora_36_sysinternals
                    ;;
                37)
                    print_banner "Fedora $VERSION"
                    sysmon=$fedora_37_sysmon
                    sysinternals=$fedora_37_sysinternals
                    ;;
                38)
                    print_banner "Fedora $VERSION"
                    sysmon=$fedora_38_sysmon
                    sysinternals=$fedora_38_sysinternals
                    ;;
                40)
                    print_banner "Fedora $VERSION"
                    sysmon=$fedora_40_sysmon
                    sysinternals=$fedora_40_sysinternals
                    ;;
                # TODO: try newer/older packages for 35, 39, and 41
                *)
                    error "Unsupported Fedora version"
                    print_options
                    ;;
            esac
            ;;
        "rhel")
            package_type="rpm"
            case $VERSION in
                7)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_sysmon
                    sysinternals=$rhel_7_sysinternals
                    ;;
                7.0)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_0_sysmon
                    sysinternals=$rhel_7_0_sysinternals
                    ;;
                7.1)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_1_sysmon
                    sysinternals=$rhel_7_1_sysinternals
                    ;;
                7.2)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_2_sysmon
                    sysinternals=$rhel_7_2_sysinternals
                    ;;
                7.3)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_3_sysmon
                    sysinternals=$rhel_7_3_sysinternals
                    ;;
                7.4)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_4_sysmon
                    sysinternals=$rhel_7_4_sysinternals
                    ;;
                7.5)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_5_sysmon
                    sysinternals=$rhel_7_5_sysinternals
                    ;;
                7.8)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_8_sysmon
                    sysinternals=$rhel_7_8_sysinternals
                    ;;
                7.9)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_7_9_sysmon
                    sysinternals=$rhel_7_9_sysinternals
                    ;;
                8)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_8_sysmon
                    sysinternals=$rhel_8_sysinternals
                    ;;
                8.0)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_8_0_sysmon
                    sysinternals=$rhel_8_0_sysinternals
                    ;;
                8.1)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_8_1_sysmon
                    sysinternals=$rhel_8_1_sysinternals
                    ;;
                8.2)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_8_2_sysmon
                    sysinternals=$rhel_8_2_sysinternals
                    ;;
                9)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_9_sysmon
                    sysinternals=$rhel_9_sysinternals
                    ;;
                9.0)
                    print_banner "RHEL $VERSION"
                    sysmon=$rhel_9_0_sysmon
                    sysinternals=$rhel_9_0_sysinternals
                    ;;
                *)
                    error "Unsupported RHEL version"
                    print_options
                    ;;
                esac
            ;;
        "centos")
            package_type="rpm"
            case $VERSION in
                7)
                    print_banner "CentOS $VERSION"
                    sysmon=$centos_7_sysmon
                    sysinternals=$centos_7_sysinternals
                    ;;
                8)
                    print_banner "CentOS $VERSION"
                    sysmon=$centos_8_sysmon
                    sysinternals=$centos_8_sysinternals
                    ;;
                *)
                    error "Unsupported CentOS version"
                    print_options
                    ;;
            esac
            ;;
        "sles")
            package_type="rpm"
            case $VERSION in
                12)
                    print_banner "SLES $VERSION"
                    sysmon=$sles_12_sysmon
                    sysinternals=$sles_12_sysinternals
                    ;;
                15)
                    print_banner "SLES $VERSION"
                    sysmon=$sles_15_sysmon
                    sysinternals=$sles_15_sysinternals
                    ;;
                *)
                    error "Unsupported SLES version"
                    print_options
                    ;;
            esac
            ;;
        "opensuse")
            package_type="rpm"
            case $VERSION in
                15)
                    print_banner "OpenSUSE $VERSION"
                    sysmon=$opensuse_15_sysmon
                    sysinternals=$opensuse_15_sysinternals
                    ;;
                *)
                    error "Unsupported OpenSUSE version"
                    print_options
                    ;;
            esac
            ;;
        *)
            error "Unknown distro"
            print_options
            ;;
    esac

    # Download the sysinternals and sysmon packages
    download $sysmon "sysmon.$package_type"
    download $sysinternals "sysinternals.$package_type"
    
    # Install the packages
    case $package_type in
        "deb")
            sudo apt-get install -y -f "./sysinternals.$package_type"
            sudo apt-get install -y -f "./sysmon.$package_type"
            ;;
        "rpm")
            sudo which dnf &> /dev/null
            dnf=$?
            sudo which zypper &> /dev/null
            zypper=$?
            sudo which yum &> /dev/null
            yum=$?
            if [ $dnf == 0 ]; then
                sudo dnf install -y "./sysinternals.$package_type"
                sudo dnf install -y "./sysmon.$package_type"
            elif [ $zypper == 0 ]; then
                sudo zypper install -y "./sysinternals.$package_type"
                sudo zypper install -y "./sysmon.$package_type"
            elif [ $yum == 0 ]; then
                sudo yum install -y "./sysinternals.$package_type"
                sudo yum install -y "./sysmon.$package_type"
            else
                error "No package manager found"
                exit 1
            fi
            ;;
    esac
}

function configure {
    download $GITHUB_URL/linux/sysmon/sysmon-config.xml sysmon-config.xml
    sudo chown root:root sysmon-config.xml
    sudo chmod 600 sysmon-config.xml
    sudo mkdir -p /opt/ccdc/
    sudo mv sysmon-config.xml /opt/ccdc/sysmon-config.xml
    sudo sysmon -accepteula -i /opt/ccdc/sysmon-config.xml
}
#####################################################

######################## MAIN #######################
while getopts "hg:l:d:v:" opt; do
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
        d)
            DISTRO=$OPTARG
            ;;
        v)
            VERSION=$OPTARG
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

ask_for_os_info
install_from_package
configure
#####################################################