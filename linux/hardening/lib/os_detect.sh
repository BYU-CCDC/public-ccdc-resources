#!/usr/bin/env bash

PACKAGE_CACHE_UPDATED="false"

function detect_system_info {
    print_banner "Detecting system info"
    log_info "Detecting package manager"

    if command -v apt-get &>/dev/null; then
        log_info "apt/apt-get detected (Debian-based OS)"
        if [ "${PACKAGE_CACHE_UPDATED:-false}" != "true" ]; then
            log_info "Updating package list"
            sudo apt-get update
            PACKAGE_CACHE_UPDATED="true"
        else
            log_info "Package list already refreshed during this session"
        fi
        pm="apt-get"
    elif command -v dnf &>/dev/null; then
        log_info "dnf detected (Fedora-based OS)"
        pm="dnf"
    elif command -v zypper &>/dev/null; then
        log_info "zypper detected (OpenSUSE-based OS)"
        pm="zypper"
    elif command -v yum &>/dev/null; then
        log_info "yum detected (RHEL-based OS)"
        pm="yum"
    else
        log_error "ERROR: Could not detect package manager"
        exit 1
    fi

    log_info "Detecting sudo group"
    local groups
    groups=$(compgen -g)
    if echo "$groups" | grep -q '^sudo$'; then
        log_info "sudo group detected"
        sudo_group='sudo'
    elif echo "$groups" | grep -q '^wheel$'; then
        log_info "wheel group detected"
        sudo_group='wheel'
    else
        log_error "ERROR: could not detect sudo group"
        exit 1
    fi
}

function install_prereqs {
    print_banner "Installing prerequisites"
    if [ -z "$pm" ]; then
        log_warning "Package manager not detected yet; running detect_system_info first."
        detect_system_info
    fi
    sudo $pm install -y zip unzip wget curl acl
}

function update_package_cache {
    if [ -z "$pm" ]; then
        detect_system_info
    fi

    if [ "${PACKAGE_CACHE_UPDATED:-false}" == "true" ]; then
        return 0
    fi

    case "$pm" in
        apt-get)
            log_info "Refreshing apt package cache"
            sudo apt-get update
            ;;
        yum|dnf)
            log_info "Refreshing $pm metadata"
            sudo "$pm" makecache -y
            ;;
        zypper)
            log_info "Refreshing zypper repositories"
            sudo zypper refresh
            ;;
        *)
            log_warning "Package cache refresh not implemented for package manager: $pm"
            return 1
            ;;
    esac

    PACKAGE_CACHE_UPDATED="true"
}
