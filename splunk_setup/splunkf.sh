#!/bin/bash
rpm="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-linux-2.6-x86_64.rpm"
linux="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-x86_64.tgz"
deb="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-linux-2.6-amd64.deb"
arm="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-armv8.tgz"
s90="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-s390x.tgz"
ppcle="https://download.splunk.com/products/universalforwarder/releases/9.0.1/linux/splunkforwarder-9.0.1-82c987350fde-Linux-ppc64le.tgz"
mac="https://download.splunk.com/products/universalforwarder/releases/9.0.1/osx/splunkforwarder-9.0.1-82c987350fde-darwin-universal2.tgz"
freebsd="https://download.splunk.com/products/universalforwarder/releases/9.0.1/freebsd/splunkforwarder-9.0.1-82c987350fde-FreeBSD11-amd64.tgz"
z="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-SunOS-x86_64.tar.Z"
p5p="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-solaris-intel.p5p"
sparcz="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-SunOS-sparc.tar.Z"
sparcp5p="https://download.splunk.com/products/universalforwarder/releases/9.0.1/solaris/splunkforwarder-9.0.1-82c987350fde-solaris-sparc.p5p"
aix="https://download.splunk.com/products/universalforwarder/releases/9.0.1/aix/splunkforwarder-9.0.1-82c987350fde-AIX-powerpc.tgz"

echo "Run this script as root, exit and rerun if not root user. Script will begin in 3 seconds"
sleep 3
echo "Performing Setup"
# this case statement handles command line arguments
# for example if you wanted to install a forwarder for debian you would input:
# ./splunkf.sh debian
case "$1" in
    debian )
        echo "******* Installing forwarder for Debian ********"
        echo
        sudo wget -O splunk.deb "$deb"
        sudo dpkg -i ./splunk.deb
    ;;
    linux )
        echo "******* Installing forwarder general tgz for linux *******"
        echo
        sudo wget -O splunk.tgz "$linux"
        sudo tar -xfvz splunk.tgz -C /opt/
    ;;
    rpm )
        echo "******* Installing forwarder for rpm based machines *******"
        echo
        sudo wget -O splunk.rpm "$rpm"
        sudo rpm -i splunk.rpm
    ;;
    # prints the url in case there are problems with the install
    -p)
        case $2 in
            debian)
                echo $deb
                exit
            ;;
            rpm)
                echo $rpm
                exit
            ;;
            linux)
                echo $linux
                exit
            ;;
            *)
                echo "url not found"
                exit
            ;;
        esac
    ;;
    # prints urls of the lesser known/used splunk forwarders
    other )
        echo "Linux ARM: $arm"
        echo 
        echo "Linux s390: $s90"
        echo
        echo "Linux PPCLE: $ppcle"
        echo
        echo "OSX M1/Intel: $mac"
        echo
        echo "FreeBSD: $freebsd"
        echo
        echo "Solaris:
        - .Z (64-bit): $z
        - .p5p (64-bit): $p5p
        - Sparc .Z: $sparcz
        - Sparc .p5p: $sparcp5p"
        echo
        echo "AIX: $aix"
        exit
    ;;
    # catch all statement that provides the user with a list of potential command line options
    *)
        echo "OPTIONS:
            -> debian
            -> linux (general tgz file)
            -> rpm
            -> other (shows list of other forwarder urls)
            -> -p (prints the specified url debian, linux or rpm in case something is not working)
            "
        exit
    ;;
esac
echo "****** Starting Splunk ******"
# needed here since we will disable root after the script is run
# and it gives us full access over splunk
sudo chown -R CCDCUser1 /opt/splunkforwarder
sudo chgrp -R CCDCUser1 /opt/splunkforwarder
sudo /opt/splunkforwarder/bin/splunk start --accept-license
