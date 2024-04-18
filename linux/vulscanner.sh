#!/bin/bash

setup_scripts() {
  # get packages
  apt install nmap git -y

  # clone files
  git clone https://github.com/scipag/vulscan scipag_vulscan
  wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/linux/cve.csv.tar.gz
  tar -xzvf cve.csv.tar.gz

  # move files
  cp -r ./scipag_vulscan /usr/share/nmap/scripts/vulscan
  cp cve.csv /usr/share/nmap/scripts/vulscan/cve.csv
}

scan_hosts() {
  time=$(date +%s)
  resultdir=results"$time"
  mkdir "$resultdir"
  cat "$1" | while read line || [[ -n $line ]];
  do
    echo "Scanning $line..."
    nmap -sV --script=vulscan/vulscan.nse --script-args "vulscandb=cve.csv, vulscanoutput='{id} | {product} | {version} | {title}\n'" "$line" > "$resultdir"/results-"$line".txt
  done
  cat "$resultdir"/* > completeresult"$time"
}

print_options() {
  echo "
  Usage: $0 [OPTION] [HOSTS FILE]

  Options:
  full      Sets up scanning utilities and scans using hosts file.
  setup     Sets up scanning utilities without attempting scans.
  scan      Scans using the hosts file.
  help      Displays this help message.

  Note: The HOSTS FILE is a required argument for the full and scan options. The hosts file should have one scannable option (URL, IP Address, CIDR, etc.) per line.
  "
}

if [ $# -lt 1 ]; then
  print_options
  exit 1
fi

case $1 in
  "full")
    if [ $# -lt 2 ]; then
      print_options
      exit 1
    fi
    setup_scripts 
    scan_hosts $2
  ;;
  "setup")
    setup_scripts
  ;;
  "scan")
    if [ $# -lt 2 ]; then
      print_options
      exit 1
    fi
    scan_hosts $2
  ;;
  "help")
    print_options
  ;;
  *)
    print_options
    exit 1
  ;;
esac
