#!/bin/bash
sudo mkdir -p /var/lib/loki
sudo chown -R 10001:10001 /var/lib/loki
sudo chmod -R u+rwX /var/lib/loki

docker compose up -d

curl -s https://api.github.com/repos/grafana/loki/releases/tags/v3.7.8 |
  jq -r '.assets[] | select(.name == "logcli-linux-amd64.zip") | .browser_download_url' |
  xargs curl -LO
unzip logcli-linux-amd64.zip
sudo mv logcli-linux-amd64 /usr/local/bin/logcli