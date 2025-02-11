#!/bin/bash

# Global variable for the package manager
pm=""

# Function to detect the OS package manager
detect_os() {
  echo "[*] Detecting package manager..."
  if command -v apt-get >/dev/null 2>&1; then
      pm="apt"
  elif command -v dnf >/dev/null 2>&1; then
      pm="dnf"
  elif command -v yum >/dev/null 2>&1; then
      pm="yum"
  elif command -v zypper >/dev/null 2>&1; then
      pm="zypper"
  else
      echo "[X] Error: No supported package manager found."
      exit 1
  fi
  echo "[*] Detected package manager: $pm"
}

setup_scripts() {
  # Detect the OS/package manager first.
  detect_os

  echo "[*] Installing required packages..."
  case "$pm" in
    "apt")
      sudo apt install nmap git -y
      ;;
    "dnf")
      sudo dnf install nmap git -y
      ;;
    "yum")
      sudo yum install nmap git -y
      ;;
    "zypper")
      sudo zypper install -y nmap git
      ;;
  esac

  # Clone the vulscan repository if it isn't already present.
  if [ -d "scipag_vulscan" ]; then
    echo "[*] 'scipag_vulscan' directory already exists. Skipping clone."
  else
    echo "[*] Cloning vulscan repository..."
    git clone https://github.com/scipag/vulscan scipag_vulscan
  fi

  # Download cve.csv.tar.gz if cve.csv is not already present.
  if [ -f "cve.csv" ]; then
    echo "[*] 'cve.csv' already exists. Skipping download and extraction."
  else
    if [ -f "cve.csv.tar.gz" ]; then
      echo "[*] 'cve.csv.tar.gz' already exists. Skipping download."
    else
      echo "[*] Downloading cve.csv archive..."
      wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/linux/cve.csv.tar.gz
    fi

    echo "[*] Extracting cve.csv archive..."
    tar -xzvf cve.csv.tar.gz

    # Remove the tarball after successful extraction
    if [ -f "cve.csv" ]; then
      echo "[*] Removing cve.csv.tar.gz after extraction."
      rm cve.csv.tar.gz
    fi
  fi

  # Copy vulscan files into Nmap's script directory if not already present.
  if [ -d "/usr/share/nmap/scripts/vulscan" ]; then
    echo "[*] '/usr/share/nmap/scripts/vulscan' already exists. Skipping file copy."
  else
    echo "[*] Copying vulscan files..."
    sudo cp -r ./scipag_vulscan /usr/share/nmap/scripts/vulscan
    sudo cp cve.csv /usr/share/nmap/scripts/vulscan/cve.csv
  fi
}

scan_hosts() {
  # Create a timestamp in the format MM-DD--HH:MM:SS (e.g., 01-31--23:47:27)
  timestamp=$(date +"%m-%d--%H:%M:%S")
  
  # Determine a global iteration prefix by scanning for existing directories.
  # This will find all directories that match the pattern "*-vulscan-results--*"
  # and then choose the highest prefix number + 1.
  prefix=1
  existing_dirs=( $(ls -d [0-9]*-vulscan-results--* 2>/dev/null) )
  if [ ${#existing_dirs[@]} -gt 0 ]; then
      max=0
      for d in "${existing_dirs[@]}"; do
          # Extract the number before the first hyphen.
          num=$(echo "$d" | cut -d '-' -f1)
          if [[ $num =~ ^[0-9]+$ ]]; then
              if (( num > max )); then
                  max=$num
              fi
          fi
      done
      prefix=$((max+1))
  fi
  
  # Create the main output directory with the unique global prefix.
  outdir="${prefix}-vulscan-results--${timestamp}"
  mkdir "$outdir"
  
  # Create subdirectory for individual results.
  individual_dir="$outdir/individual-results"
  mkdir "$individual_dir"

  echo "[*] Scanning hosts from file: $1"
  
  # Process each line in the provided hosts file.
  while IFS= read -r line || [[ -n "$line" ]]; do
      # Skip blank lines.
      [ -z "$line" ] && continue

      echo "[*] Scanning $line..."
      # Replace any "/" in the host string with "_" for a safe filename.
      host_safe=$(echo "$line" | tr '/' '_')
      output_file="$individual_dir/results-$host_safe.txt"
      
      nmap -sV --script=vulscan/vulscan.nse --script-args "vulscandb=cve.csv, vulscanoutput='{id} | {product} | {version} | {title}\n'" "$line" > "$output_file"
  done < "$1"

  # Combine all individual scan results into a comprehensive file.
  comprehensive_file="$outdir/comprehensive--${timestamp}.txt"
  cat "$individual_dir"/* > "$comprehensive_file"
  echo "[*] Combined scan results saved in '$comprehensive_file'"
}

print_options() {
  echo "
Usage: $0 [OPTION] [HOSTS FILE]

Options:
  full      Sets up scanning utilities and scans using the hosts file.
  setup     Sets up scanning utilities without scanning.
  scan      Scans using the hosts file.
  help      Displays this help message.

Note: The HOSTS FILE is required for the 'full' and 'scan' options. The file should contain one scannable entry (URL, IP Address, CIDR, etc.) per line.
"
}

# Ensure at least one argument is provided.
if [ $# -lt 1 ]; then
  print_options
  exit 1
fi

# Parse command-line options.
case $1 in
  "full")
    if [ $# -lt 2 ]; then
      print_options
      exit 1
    fi
    setup_scripts 
    scan_hosts "$2"
    ;;
  "setup")
    setup_scripts
    ;;
  "scan")
    if [ $# -lt 2 ]; then
      print_options
      exit 1
    fi
    scan_hosts "$2"
    ;;
  "help")
    print_options
    ;;
  *)
    print_options
    exit 1
    ;;
esac
