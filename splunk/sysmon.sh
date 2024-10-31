#!/bin/bash
DISTRO=$1
VERSION=$2

function print_banner {
    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
}

function error {
    echo "[X] $1"
}

function install {
    case $DISTRO in
        "ubuntu")
            if [ $VERSION -ge 18 ]; then
                print_banner "Ubuntu $VERSION"
                wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
                sudo dpkg -i packages-microsoft-prod.deb
                sudo apt-get update
                sudo apt-get install sysmonforlinux
            else
                error "Unsupported Ubuntu version"
                exit 1
            fi
            ;;
        "debian")
            if [ $VERSION -ge 9 ]; then
                print_banner "Debian $VERSION"
                if [ $VERSION -lt 11 ]; then
                    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
                    sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
                    wget -q https://packages.microsoft.com/config/debian/$VERSION/prod.list
                    sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
                    sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
                    sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
                else
                    wget -q https://packages.microsoft.com/config/debian/$VERSION/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
                    sudo dpkg -i packages-microsoft-prod.deb
                fi
                sudo apt-get update
                sudo apt-get install apt-transport-https
                sudo apt-get update
                sudo apt-get install sysmonforlinux
            else
                error "Unsupported Debian version"
                exit 1
            fi
            ;;
        "fedora")
            if [ $VERSION -ge 33 ]; then
                print_banner "Fedora $VERSION"
                if [ $VERSION -lt 37 ]; then
                    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                    sudo wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/fedora/$VERSION/prod.repo
                else
                    sudo rpm -Uvh https://packages.microsoft.com/config/fedora/$VERSION/packages-microsoft-prod.rpm
                fi
                sudo dnf install sysmonforlinux
            else
                error "Unsupported Fedora version"
                exit 1
            fi
            ;;
        "rhel")
            if [ $VERSION -ge 7 ]; then
                print_banner "RHEL $VERSION"
                if [ $VERSION -lt 8 ]; then
                    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                    sudo wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/7/prod.repo
                    sudo yum install sysmonforlinux
                else
                    sudo rpm -Uvh https://packages.microsoft.com/config/rhel/$VERSION/packages-microsoft-prod.rpm
                    sudo dnf install sysmonforlinux
                fi
            else
                error "Unsupported RHEL version"
                exit 1
            fi
            ;;
        "centos")
            if [ $VERSION -ge 7 ]; then
                print_banner "CentOS $VERSION"
                sudo rpm -Uvh https://packages.microsoft.com/config/centos/$VERSION/packages-microsoft-prod.rpm
                sudo yum install sysmonforlinux
            else
                error "Unsupported CentOS version"
                exit 1
            fi
            ;;
        "sles")
            if [ $VERSION -eq 12 ] || [ $VERSION -eq 15 ]; then
                print_banner "SLES $VERSION"
                sudo rpm -Uvh https://packages.microsoft.com/config/sles/$VERSION/packages-microsoft-prod.rpm
                sudo zypper install sysmonforlinux
            else
                error "Unsupported SLES version"
                exit 1
            fi
            ;;
        "opensuse")
            if [ $VERSION -eq 15 ]; then
                print_banner "OpenSUSE $VERSION"
                sudo zypper install libicu
                sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                wget -q https://packages.microsoft.com/config/opensuse/15/prod.repo
                sudo mv prod.repo /etc/zypp/repos.d/microsoft-prod.repo
                sudo chown root:root /etc/zypp/repos.d/microsoft-prod.repo
                sudo zypper install sysmonforlinux
            else
                error "Unsupported OpenSUSE version"
                exit 1
            fi
            ;;
        *)
            error "Unknown distro"
            exit 1
            ;;
    esac
}

install