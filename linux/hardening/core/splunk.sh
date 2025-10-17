function setup_splunk {
    print_banner "Installing Splunk"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping Splunk installation."
        return 0
    fi
    indexer_ip=$(get_input_string "What is the Splunk forward server ip? ")
    wget https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main/splunk/splunk.sh --no-check-certificate
    chmod +x splunk.sh
    ./splunk.sh -f $indexer_ip
}
