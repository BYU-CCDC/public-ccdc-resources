#!/usr/bin/bash
NUM_WORDS=5
WORDLIST_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening/wordlist.txt"
EXPORT_USERS="users.txt"
LOG_FILE="/var/log/ccdc/zulu.log"

DO_INITIAL=false
GENERATE_ONLY=false

WORDLIST_FILE="wordlist.txt"
USERS_FILE=""
PCR_FILE=""

USERS=()
EXCLUDED_USERS=("root" "ccdcuser1" "ccdcuser2")

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

function set_ansi {
    color=$1
    mode=$2

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

    echo -ne "\x1B[${mode};${color}m"
}

function print_ansi {
    text=$1
    color=$2
    mode=$3

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

function print_usage {
    echo "$(set_ansi $GREEN $BOLD)Usage: $0 [options]$(set_ansi)"
    echo "Default behavior asks for a seed phrase and changes passwords for all auto-detected users minus excluded users."
    echo
    echo "$(set_ansi $YELLOW $BOLD)Options:$(set_ansi)"
    echo "$(set_ansi $BLUE)  -h                Show this help message$(set_ansi)"
    echo "$(set_ansi $BLUE)  -i                Perform initial setup (change root password and create ccdcuser1/2)$(set_ansi)"
    echo "$(set_ansi $BLUE)  -u <username>     Change password for a single user$(set_ansi)"
    echo "$(set_ansi $BLUE)  -U <users_file>   Change passwords for newline-separated users in a file $(set_ansi)"
    echo "$(set_ansi $BLUE)  -g                Generate/print passwords only, do not change them$(set_ansi)"
    echo "$(set_ansi $BLUE)  -p <pcr_file>     Output generated passwords as 'username,password' to a PCR (CSV) file$(set_ansi)"
}

function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

function download {
    url=$1
    output=$2
    if ! wget -O "$output" --no-check-certificate "$url" --progress=dot:mega 2>&1 | grep -Eo ' [0-9]0% ' | uniq; then
        print_ansi "Failed to download with wget. Trying with curl...\n" $YELLOW $BOLD
        if ! curl -L -o "$output" -k "$url"; then
            print_ansi "Failed to download file from $url\n" $RED $BOLD
            exit 1
        fi
    fi
}

function append_log {
    if [ "$GENERATE_ONLY" == false ]; then
        echo "$1" >> "$LOG_FILE"
    fi
}

function check_prereqs {
    # Check that script is privileged
    if [ "$(id -u)" -ne 0 ]; then
        print_ansi "Please run script as root.\n" $RED $BOLD
        exit 1
    fi

    # Download wordlist if not present
    if ! [ -f "$WORDLIST_FILE" ]; then
        print_ansi "Downloading wordlist file...\n" $GREEN
        download "$WORDLIST_URL" "$WORDLIST_FILE"
    fi
}

# Change root and create ccdc users
function initial_change {
    print_ansi "Changing root password...\n" $GREEN
    passwd root

    print_ansi "\nCreating ccdcuser1 and ccdcuser2...\n" $GREEN
    useradd -m -s /bin/bash ccdcuser1
    useradd -m -s /bin/bash ccdcuser2

    print_ansi "\nSetting passwords for ccdcuser1 and ccdcuser2...\n" $GREEN
    passwd ccdcuser1
    passwd ccdcuser2

    print_ansi "\nAdding ccdcuser1 to sudoers...\n" $GREEN
    groups=$(compgen -g)
    if echo "$groups" | grep -q '^sudo$'; then
        sudo_group='sudo'
    elif echo "$groups" | grep -q '^wheel$'; then
        sudo_group='wheel'
    fi
    usermod -aG "$sudo_group" ccdcuser1
}

function minmax_scale {
    # https://en.wikipedia.org/wiki/Feature_scaling#Rescaling_(min-max_normalization)
    x=$1
    min=0
    max=$((0xFFFF))

    a=0
    b=$(wc -l "$WORDLIST_FILE" | awk '{print $1-1}')

    if [ $b -eq 0 ]; then
        print_ansi "Wordlist file is empty or missing.\n" $RED $BOLD
        exit 1
    fi

    # round down to nearest int (int() rounds down in awk)
    minmax=$(awk -v x="$x" -v min=$min -v max=$max -v a=$a -v b=$b 'BEGIN {
        scaled = (a + (((x - min) * (b - a)) / (max - min)))
        printf(int(scaled))
    }')

    echo "$minmax"    
}

# Check prereqs
while getopts "hiu:U:gp:" opt; do
    case $opt in
        h)
            print_usage
            exit 0
            ;;
        i)
            DO_INITIAL=true
            ;;
        u)
            SINGLE_USER="$OPTARG"
            ;;
        U)
            USERS_FILE="$OPTARG"
            if ! [ -f "$USERS_FILE" ]; then
                print_ansi "Users file '$USERS_FILE' not found.\n" $RED $BOLD
                exit 1
            fi
            ;;
        g)
            GENERATE_ONLY=true
            ;;
        p)
            PCR_FILE="$OPTARG"
            ;;
        \?)
            print_ansi "Invalid option: -$OPTARG\n" $RED $BOLD
            print_usage
            exit 1
            ;;
    esac
done

print_ansi "Starting Zulu Password Generator Script...\n" $GREEN $BOLD
append_log "Script started at $(date)"
print_ansi "The default behavior is to change passwords for all users with a shell except: ${EXCLUDED_USERS[*]}.\n"
check_prereqs

# Setup log directory
if ! [ -e "/var/log/ccdc" ]; then
    mkdir -p /var/log/ccdc
    sudo chown root:root /var/log/ccdc
    sudo chmod 700 /var/log/ccdc
fi

# Initial change if requested
if [ "$DO_INITIAL" == true ]; then
    print_ansi "Performing initial user setup...\n" $GREEN $BOLD
    initial_change
fi

print_ansi "\nPreparing to generate passwords...\n" $GREEN $BOLD
# Get usernames
if [ -n "$SINGLE_USER" ]; then
    RAW_USERS=("$SINGLE_USER")
elif [ -f "$USERS_FILE" ]; then
    readarray -t RAW_USERS < "$USERS_FILE"
else
    readarray -t RAW_USERS < <(cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1)
fi

# Exclude users
for user in "${RAW_USERS[@]}"; do
    [[ "${EXCLUDED_USERS[@]}" == "${user}" ]] || USERS+=("$user")
done

# Ask for seed phrase (twice to confirm)
while true; do
    seed_phrase=""
    confirm_seed_phrase=""

    # Ask for seed phrase
    seed_phrase=$(get_silent_input_string "Enter seed phrase: ")
    echo

    # Confirm seed phrase
    confirm_seed_phrase=$(get_silent_input_string "Confirm seed phrase: ")
    echo

    if [ "$seed_phrase" != "$confirm_seed_phrase" ]; then
        print_ansi "Seed phrases do not match. Please retry.\n" $YELLOW $BOLD
        continue
    fi

    if [ "${#seed_phrase}" -lt 8 ]; then
        print_ansi "Seed phrase must be at least 8 characters long. Please retry.\n" $YELLOW $BOLD
        continue
    fi

    break
done
echo

# Generate each users's password and change it
print_ansi "Generating passwords for ${#USERS[@]} users...\n" $GREEN $BOLD
if [ "$GENERATE_ONLY" == false ]; then
    > "$EXPORT_USERS"
fi
for user in "${USERS[@]}"; do
    # Generate password
    hash=$(echo -n "$seed_phrase$user" | md5sum)

    password=""
    for i in $(seq 0 4 $((NUM_WORDS*4-1))); do
        # Add hyphen between words
        if [ $i -ne 0 ]; then
            password+="-"
        fi

        # Take 4 hex chars at a time
        hex=${hash:$i:4}

        # Convert hex to decimal
        dec=$((16#$hex))

        # Scale to wordlist size
        index=$(minmax_scale $dec)

        # Get word from wordlist and append to password
        word=$(sed -n "$((index + 1))p" "$WORDLIST_FILE")
        password+="$word"
    done
    password+="1"


    # Set or print password
    if [ "$GENERATE_ONLY" == false ]; then
        echo "Changing password for user $user..."

        # Change password
        echo "$user:$password" | chpasswd

        if [ $? -eq 0 ]; then
            print_ansi "Successfully changed password for $user.\n" $GREEN
            append_log "Successfully changed password for $user"
            echo "$user" >> "$EXPORT_USERS"
        else
            print_ansi "Failed to change password for $user.\n" $RED
            append_log "Failed to change password for $user"
        fi
    elif [ "$GENERATE_ONLY" == true ] && ! [ -n "$PCR_FILE" ]; then
        echo "Generated password for user '$user': $password"
    fi

    # If PCR file specified, append username,password
    if [ -n "$PCR_FILE" ]; then
        echo "$user,$password" >> "$PCR_FILE"
    fi
done

print_ansi "Done!\n" $GREEN $BOLD
echo
print_ansi "PLEASE REMEMBER TO CHANGE THE ROOT PASSWORD IF NOT DONE EARLIER.\n" $YELLOW $BOLD