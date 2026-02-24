#!/bin/bash
#wget https://releases.mattermost.com/10.5.1/mattermost-10.5.1-linux-amd64.tar.gz
#tar -xvzf mattermost*.gz
#mv mattermost /opt
mkdir /opt/mattermost/data
useradd --system --user-group mattermost
chown -R mattermost:mattermost /opt/mattermost
chmod -R g+w /opt/mattermost
#touch /lib/systemd/system/mattermost.service

cat > /lib/systemd/system/mattermost.service << EOF
[Unit]
Description=Mattermost
After=network.target

[Service]
Type=notify
ExecStart=/opt/mattermost/bin/mattermost
TimeoutStartSec=3600
KillMode=mixed
Restart=always
RestartSec=10
WorkingDirectory=/opt/mattermost
User=mattermost
Group=mattermost
LimitNOFILE=49152

[Install]
WantedBy=multi-user.target
EOF

cp /opt/mattermost/config/config.json /opt/mattermost/config/config.defaults.json

apt install -y postgresql postgresql-contrib

# Start and enable PostgreSQL service
systemctl enable --now postgresql

# Set up the Mattermost database and user
sudo -u postgres psql <<EOF
CREATE DATABASE mattermost;
CREATE USER mmuser WITH PASSWORD 'securepassword';
ALTER ROLE mmuser WITH LOGIN;
GRANT ALL PRIVILEGES ON DATABASE mattermost TO mmuser;
\c mattermost
GRANT ALL ON SCHEMA public to mmuser;
EOF

# Configure PostgreSQL to allow password authentication
PG_HBA_FILE="/etc/postgresql/$(ls /etc/postgresql)/main/pg_hba.conf"
sed -i "s/^local\s*all\s*postgres\s*peer$/local all postgres peer\nlocal mattermost mmuser md5/" "$PG_HBA_FILE"
sed -i "s/^host\s*all\s*all\s*127.0.0.1\/32\s*md5$/host all all 127.0.0.1\/32 md5\nhost mattermost mmuser 127.0.0.1\/32 md5/" "$PG_HBA_FILE"

# Restart PostgreSQL to apply changes
systemctl restart postgresql

echo "PostgreSQL setup complete."
echo "Database: mattermost"
echo "User: mmuser"
echo "Password: securepassword (Change this in production!)"
