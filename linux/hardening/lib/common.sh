#!/usr/bin/env bash

# Color palette (matches verbose logging specification)

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[38;5;208m'
AQUA='\033[38;5;45m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_LEVEL="${LOG_LEVEL:-INFO}"
debug="${debug:-false}"

# Logging helpers

__log_level_rank() {
    local level="${1^^}"
    case "$level" in
        ERROR) echo 0 ;;
        WARNING) echo 1 ;;
        SUCCESS|INFO) echo 2 ;;
        VERBOSE) echo 3 ;;
        DEBUG) echo 4 ;;
        *) echo 2 ;;
    esac
}

__log_should_emit() {
    local message_level="${1^^}"
    local current_level="${LOG_LEVEL^^}"

    if [ "$message_level" == "DEBUG" ] && [ "$debug" == "true" ] && [ "$current_level" != "DEBUG" ]; then
        current_level="DEBUG"
    fi

    local message_rank
    local threshold_rank
    message_rank=$(__log_level_rank "$message_level")
    threshold_rank=$(__log_level_rank "$current_level")

    if [ "$message_rank" -le "$threshold_rank" ]; then
        return 0
    fi
    return 1
}

function set_log_level {
    local new_level="${1:-INFO}"
    LOG_LEVEL="${new_level^^}"
    if [ "$LOG_LEVEL" == "DEBUG" ]; then
        debug="true"
    else
        debug="false"
    fi
}

function _log_with_color {
    local level="$1"
    local color="$2"
    shift 2 || true

    if ! __log_should_emit "$level"; then
        return 0
    fi

    printf '%b[%s]%b %s - %s\n' "$color" "$level" "$NC" "$(date +"%Y-%m-%d %H:%M:%S")" "$*"
}

function init_logging {
    local log_file="$1"
    local log_dir
    log_dir="$(dirname "$log_file")"

    mkdir -p "$log_dir"
    chmod 750 "$log_dir"
    touch "$log_file"
    chmod 640 "$log_file"

    exec 1> >(tee -a "$log_file")
    exec 2>&1
}

function log_info {
    _log_with_color "INFO" "$AQUA" "$@"
}

function log_success {
    _log_with_color "SUCCESS" "$GREEN" "$@"
}

function log_warning {
    _log_with_color "WARNING" "$ORANGE" "$@"
}

function log_error {
    _log_with_color "ERROR" "$RED" "$@"
}

function log_verbose {
    _log_with_color "VERBOSE" "$CYAN" "$@"
}

function log_debug {
    _log_with_color "DEBUG" "$MAGENTA" "$@"
}

function print_banner {
    echo -e "${CYAN}"
    echo "================================================"
    echo "   $1"
    echo "================================================"
    echo -e "${NC}"
}

function debug_print {
    log_debug "$@"
}

function get_input_string {
    if [ "$ANSIBLE" == "true" ]; then
        echo ""
    else
        read -r -p "$1" input
        echo "$input"
    fi
}

function get_silent_input_string {
    if [ "$ANSIBLE" == "true" ]; then
        echo "DefaultPass123!"
    else
        read -r -s -p "$1" input
        echo "$input"
    fi
}

function get_input_list {
    if [ "$ANSIBLE" == "true" ]; then
        echo ""
    else
        local input_list=()
        local continue_prompt="true"
        local input
        while [ "$continue_prompt" != "false" ]; do
            input=$(get_input_string "Enter input: (one entry per line; hit enter to continue): ")
            if [ -z "$input" ]; then
                continue_prompt="false"
            else
                input_list+=("$input")
            fi
        done
        echo "${input_list[@]}"
    fi
}

function exclude_users {
    if [ "$ANSIBLE" == "true" ]; then
        echo "$@"
    else
        local users=()
        local item
        for item in "$@"; do
            users+=("$item")
        done
        local input
        input=$(get_input_list)
        for item in $input; do
            users+=("$item")
        done
        echo "${users[@]}"
    fi
}

function get_users {
    awk_string=$1
    exclude_users=$(sed -e 's/ /\\|/g' <<< "$2")
    users=$(awk -F ':' "$awk_string" /etc/passwd)
    if [ -n "$exclude_users" ]; then
        filtered=$(echo "$users" | grep -v -e "$exclude_users")
    else
        filtered="$users"
    fi
    readarray -t results <<< "$filtered"
    echo "${results[@]}"
}
