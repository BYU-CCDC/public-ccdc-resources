#Template credit to CPP
RHEL(){
    yum purge -y -q netcat nc gcc cmake make telnet
    
}

DEBIAN(){
    apt-get -y purge netcat nc gcc cmake make telnet
}

UBUNTU(){
    DEBIAN
}

ALPINE(){
    apk remove gcc make
}

SLACK(){
    echo "its fucked"
}

if command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    if $(cat /etc/os-release | grep -qi Ubuntu); then
        UBUNTU
    else
        DEBIAN
    fi
elif command -v apk >/dev/null ; then
    ALPINE
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -i slackware) ; then
    SLACK
fi