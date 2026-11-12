#!/bin/bash
# Common functions and variables to be used in Linux scripts
# Be very cautious editing functions here - make sure to test any changes thoroughly, as they may affect multiple scripts.

# ANSI color codes
NORMAL=0
BOLD=1
UNDERLINE=4
BLACK=30
BLACK_BG=40
RED=31
RED_BG=41
GREEN=32
GREEN_BG=42
YELLOW=33
YELLOW_BG=43
BLUE=34
BLUE_BG=44
MAGENTA=35
MAGENTA_BG=45
CYAN=36
CYAN_BG=46
WHITE=37
WHITE_BG=47
DEFAULT=39
DEFAULT_BG=49
NC='\x1B[0m'

function get_os_info {
    # See https://github.com/chef/os_release for examples of /etc/os-release files
    source /etc/os-release

    if [[ -z "$ID_LIKE" ]]; then
        OS_FAMILY="$ID"
    else
        OS_FAMILY="$ID_LIKE"
    fi

    case "$OS_FAMILY" in
        *debian*|*ubuntu* )
            PM="apt-get"
            function install_package {
                apt-get update
                apt-get install -qq -y "$@"
                return $?
            }
            function remove_package {
                # apt-get remove -y "$@"
                apt-get purge -y "$@"
                return $?
            }
            function detect_package {
                dpkg -s "$@" &> /dev/null
                return $?
            }
        ;;
        *fedora*|*rhel*|*centos* )
            which dnf &> /dev/null
            if [ $? == 0 ]; then
                PM="dnf"
                function install_package {
                    dnf install --nogpgcheck -qq -y "$@"
                    return $?
                }
                function remove_package {
                    dnf remove -y "$@"
                    return $?
                }
                function detect_package {
                    rpm -q "$@" &> /dev/null
                    return $?
                }
            else
                PM="yum"
                function install_package {
                    yum install --nogpgcheck -qq -y "$@"
                    return $?
                }
                function remove_package {
                    yum remove -y "$@"
                    return $?
                }
                function detect_package {
                    rpm -q "$@" &> /dev/null
                    return $?
                }
            fi
        ;;
        *suse*|*opensuse* )
            PM="zypper"
            function install_package {
                zypper --no-gpg-checks install -qq -y "$@"
                return $?
            }
            function remove_package {
                zypper remove -y "$@"
                return $?
            }
            function detect_package {
                rpm -q "$@" &> /dev/null
                return $?
            }
        ;;
        *arch* )
            PM="pacman"
            function install_package {
                pacman -S --noconfirm "$@"
                return $?
            }
            function remove_package {
                pacman -R --noconfirm "$@"
                return $?
            }
            function detect_package {
                pacman -Q "$@" &> /dev/null
                return $?
            }
        ;;
        *alpine* )
            PM="apk"
            function install_package {
                apk add "$@"
                return $?
            }
            function remove_package {
                apk del "$@"
                return $?
            }
            function detect_package {
                apk info "$@" &> /dev/null
                return $?
            }
        ;;
        * )
            return 1
        ;;
    esac
}

function download {
    local url="$1"
    local output="$2"

    if command -v wget > /dev/null 2>&1; then
        wget -O "$output" --no-check-certificate "$url" -q --progress=dot:giga
    elif command -v curl > /dev/null 2>&1; then
        curl -# -L -o "$output" -k "$url"
    else
        return 1
    fi
}

function set_ansi {
    local color=$1
    local mode=$2

    if [ "$NOCOLOR" == true ]; then
        return
    fi

    if [ -z "$mode" ]; then
        mode=$NORMAL
    fi

    if [ -z "$color" ]; then
        color=$DEFAULT
    fi

    echo -ne "\x1B[${mode};${color}m"
}

function print_ansi {
    local text=$1
    local color=$2
    local mode=$3

    if [ "$NOCOLOR" == true ]; then
        echo -ne "$text"
        return
    fi

    if [ -z "$mode" ]; then
        mode=$NORMAL
    fi

    if [ -z "$color" ]; then
        color=$DEFAULT
    fi

    echo -ne "\x1B[${mode};${color}m${text}${NC}"
}

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

function log_info {
    _log_with_color "INFO" $(set_ansi "$CYAN") "$@"
}

function log_success {
    _log_with_color "SUCCESS" $(set_ansi "$GREEN") "$@"
}

function log_warning {
    _log_with_color "WARNING" $(set_ansi "$YELLOW") "$@"
}

function log_error {
    _log_with_color "ERROR" $(set_ansi "$RED") "$@"
}

function log_verbose {
    _log_with_color "VERBOSE" $(set_ansi "$CYAN") "$@"
}

function log_debug {
    _log_with_color "DEBUG" $(set_ansi "$MAGENTA") "$@"
}

function print_banner {
    # Stolen from LinPEAS
    local title=$1
    local title_len=$(echo $title | wc -c)
    local max_title_len=80
    local rest_len=$((($max_title_len - $title_len) / 2))

    echo ""
    printf $(set_ansi $BLUE $BOLD)
    for i in $(seq 1 $rest_len); do printf " "; done
    printf "╔"
    for i in $(seq 1 $title_len); do printf "═"; done; printf "═";
    printf "╗"
    echo ""
    for i in $(seq 1 $rest_len); do printf "═"; done
    printf "╣ $(set_ansi $GREEN $BOLD)${title}$(set_ansi $BLUE $BOLD) ╠"
    for i in $(seq 1 $rest_len); do printf "═"; done
    echo ""
    printf $(set_ansi $BLUE $BOLD)
    for i in $(seq 1 $rest_len); do printf " "; done
    printf "╚"
    for i in $(seq 1 $title_len); do printf "═"; done; printf "═";
    printf "╝"
    printf $(set_ansi)
    echo -e "\n"
}

function print_true_false {
    if [ "$1" == true ]; then
        print_ansi "true" $GREEN_BG $BOLD
    else
        print_ansi "false" $RED_BG $BOLD
    fi
}

function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

function get_input_string {
    read -r -p "$1" input
    echo "$input"
}

function enable_start_service {
    local service="$1"
    if command -v systemctl &> /dev/null; then
        systemctl enable --now "$service"
    elif command -v service &> /dev/null; then
        service "$service" start
    fi
    # TODO: implement for alpine
}
