#!/bin/bash
set -euo pipefail

# ========================================
# SOFTWARE VERSION VARIABLES
# ========================================
PROMETHEUS_VERSION="3.6.0"
NODE_EXPORTER_VERSION="1.9.1"
ALLOY_VERSION="1.10.2"
LOKI_VERSION="3.5.5"
TEMPO_VERSION="2.8.2"

# ========================================
# INSTALLATION CONFIGURATION
# ========================================
LOG_FILE="/var/log/mithlond-install.log"

INSTALL_DIR="/opt/mithlond"
CONFIG_DIR="/etc/mithlond"

TEMP_DIR="/tmp/mithlond-install"

PROMETHEUS_USER="prometheus"
PROMETHEUS_GROUP="prometheus"
PROMETHEUS_HOME="/var/lib/prometheus"
PROMETHEUS_CONFIG_DIR="/etc/prometheus"
PROMETHEUS_BIN_DIR="/usr/local/bin"
PROMETHEUS_SERVICE_FILE="/etc/systemd/system/prometheus.service"
CONFIG_WRITER_USER="${USER_NAME:-}"

NODE_EXPORTER_USER="node_exporter"
NODE_EXPORTER_GROUP="node_exporter"
NODE_EXPORTER_BIN_DIR="/usr/local/bin"
NODE_EXPORTER_SERVICE_FILE="/etc/systemd/system/node_exporter.service"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

log "Setting ssh hardening..."

log "Updating system packages..."
apt-get update -y
apt-get upgrade -y
apt-get install -y curl wget git jq openssl unzip tar

# 1. ssh hardening

# TODO: configurable
timedatectl set-timezone Europe/Copenhagen

if ! id "$USER_NAME" &>/dev/null; then
    useradd -m -u 1000 -s /bin/bash "$USER_NAME"
fi

log "Updating system user..."
usermod -aG sudo "$USER_NAME"

echo "$USER_NAME:$USER_PASSWORD" | chpasswd

echo "$USER_NAME ALL=(ALL) ALL" > "/etc/sudoers.d/$USER_NAME"
chmod 440 "/etc/sudoers.d/$USER_NAME"

if [ -f "/root/.ssh/authorized_keys" ]; then
    log "Copying root's SSH keys to $USER_NAME..."
    mkdir -p "/home/$USER_NAME/.ssh"
    cp "/root/.ssh/authorized_keys" "/home/$USER_NAME/.ssh/authorized_keys"
    chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.ssh"
    chmod 700 "/home/$USER_NAME/.ssh"
    chmod 600 "/home/$USER_NAME/.ssh/authorized_keys"
    log "SSH keys copied successfully"
else
    log "No SSH keys found in /root/.ssh/authorized_keys - user will use password authentication"
fi

log "Installing packages..."
apt-get -y install curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https net-tools unzip

cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
AddressFamily inet
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
SyslogFacility AUTH
LogLevel VERBOSE
LoginGraceTime 30
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication no
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
PermitRootLogin no
AllowUsers $USER_NAME
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

systemctl enable ssh
systemctl start ssh

ufw allow "$SSH_PORT/tcp"
ufw allow 80,443/tcp
echo y | ufw enable

log "Finished ssh hardening setup at $(date)."

echo "SSH hardening (install version) setup complete!"

# 2. fail2ban

log "Setting up fail2ban..."
apt-get -y install fail2ban

log "Writing configuration files..."

cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban

log "Finished fail2ban setup at $(date)."

echo "Fail2Ban setup complete!"

# 3. node exporter

log "Setting up node exporter..."

log "Creating node_exporter user and group..."
if ! getent group $NODE_EXPORTER_GROUP >/dev/null 2>&1; then
    groupadd --system $NODE_EXPORTER_GROUP
fi

if ! getent passwd $NODE_EXPORTER_USER >/dev/null 2>&1; then
    useradd -r -g $NODE_EXPORTER_GROUP -s /sbin/nologin $NODE_EXPORTER_USER
fi

log "Downloading Node Exporter v$NODE_EXPORTER_VERSION..."

download_url="https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
temp_dir="/tmp/node-exporter-install"

mkdir -p $temp_dir
cd $temp_dir

wget -q "$download_url" -O node_exporter.tar.gz || error "Failed to download Node Exporter"
tar -xzf node_exporter.tar.gz --strip-components=1 || error "Failed to extract Node Exporter"

log "Installing Node Exporter binary..."

cp node_exporter $NODE_EXPORTER_BIN_DIR/
chown $NODE_EXPORTER_USER:$NODE_EXPORTER_GROUP $NODE_EXPORTER_BIN_DIR/node_exporter
chmod +x $NODE_EXPORTER_BIN_DIR/node_exporter

log "Creating systemd service..."

cat > $NODE_EXPORTER_SERVICE_FILE << EOF
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=$NODE_EXPORTER_USER
Group=$NODE_EXPORTER_GROUP
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=$NODE_EXPORTER_BIN_DIR/node_exporter

[Install]
WantedBy=multi-user.target
EOF

log "Enabling Node Exporter service (will start on reboot)..."

systemctl daemon-reload
systemctl enable node_exporter

log "Cleaning up..."
rm -rf /tmp/node-exporter-install

log "Node Exporter installation completed successfully!"
log "Version: $NODE_EXPORTER_VERSION"
log "Service enabled and will start on reboot"
log "Metrics will be available at: http://localhost:9100/metrics"

cd ~

# 4. alloy
log "Setting up alloy..."

log "Starting Grafana Alloy installation script..."

log "Creating alloy group and user..."

groupadd --system alloy 2>/dev/null || true
useradd --system --no-create-home --shell /bin/false --gid alloy alloy 2>/dev/null || true
if ! id -u alloy >/dev/null 2>&1; then
    log "ERROR: Failed to create user alloy. Exiting."
    exit 1
else
    log "User alloy created or already exists."
fi

log "Creating alloy base directories and setting permissions..."
mkdir -p /etc/alloy
mkdir -p /var/lib/alloy/data
mkdir -p /var/log/alloy

log "Setting ownership and permissions for alloy directories..."
chown -R alloy:alloy /etc/alloy
chown -R alloy:alloy /var/lib/alloy
chown -R alloy:alloy /var/log/alloy

chmod 755 /etc/alloy
chmod 755 /var/lib/alloy
chmod 755 /var/lib/alloy/data
chmod 755 /var/log/alloy

chmod g+w /var/lib/alloy/data

log "Downloading Grafana Alloy v${ALLOY_VERSION}..."
cd /tmp || { log "ERROR: Failed to change directory to /tmp. Exiting."; exit 1; }

wget -q "https://github.com/grafana/alloy/releases/download/v${ALLOY_VERSION}/alloy-linux-amd64.zip"

if [ $? -ne 0 ]; then
    log "ERROR: Failed to download Alloy binary from v${ALLOY_VERSION}. Please check version and network connectivity."
    exit 1
fi

log "Extracting and installing Alloy..."
unzip -q alloy-linux-amd64.zip
mv alloy-linux-amd64 /usr/local/bin/alloy
chmod +x /usr/local/bin/alloy
rm -f alloy-linux-amd64.zip

log "Creating Alloy configuration file at /etc/alloy/config.alloy..."
cat > /etc/alloy/config.alloy << 'EOF'
otelcol.receiver.otlp "default" {
  grpc {
    endpoint = "localhost:4320"
  }
  http {
    endpoint = "localhost:4321"
  }

  output {
    metrics = [otelcol.processor.batch.default.input]
    traces  = [otelcol.processor.batch.default.input]
  }
}

otelcol.processor.batch "default" {
  output {
    metrics = [otelcol.exporter.prometheus.default.input]
    traces  = [otelcol.exporter.otlp.tempo.input]
  }
}

otelcol.exporter.prometheus "default" {
  forward_to = [prometheus.remote_write.default.receiver]
}

prometheus.remote_write "default" {
  endpoint {
    url = "http://localhost:9090/api/v1/write"
  }
}

otelcol.exporter.otlp "tempo" {
  client {
    endpoint = "http://localhost:4317"
    tls {
      insecure = true
    }
  }
}
EOF

chown alloy:alloy /etc/alloy/config.alloy
chmod 644 /etc/alloy/config.alloy

log "Creating Alloy systemd service file at /etc/systemd/system/alloy.service..."
cat > /etc/systemd/system/alloy.service << EOF
[Unit]
Description=Grafana Alloy
Documentation=https://grafana.com/docs/alloy/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=alloy
Group=alloy
# Ensure --storage.path points to the directory we configured permissions for
ExecStart=/usr/local/bin/alloy run --storage.path=/var/lib/alloy/data /etc/alloy/config.alloy
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=alloy
KillMode=mixed
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF

log "Reloading systemd daemon, enabling, and starting Alloy service..."
systemctl daemon-reload
systemctl enable alloy

log "Finished Grafana Alloy installation at $(date)."

cd ~

log "Installing Loki version $LOKI_VERSION..."

log "Creating loki system user..."
useradd --system --no-create-home --shell /bin/false loki

log "Creating Loki directories..."
mkdir -p /opt/loki
mkdir -p /var/lib/loki/chunks
mkdir -p /var/lib/loki/rules
mkdir -p /etc/loki

log "Downloading Loki binary..."
cd /tmp
wget "https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-amd64.zip"
unzip loki-linux-amd64.zip
mv loki-linux-amd64 /opt/loki/loki
chmod +x /opt/loki/loki
rm loki-linux-amd64.zip

log "Creating Loki configuration..."
cat > /etc/loki/loki.yaml << EOF
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096
  log_level: info

common:
  instance_addr: 127.0.0.1
  path_prefix: /var/lib/loki
  storage:
    filesystem:
      chunks_directory: /var/lib/loki/chunks
      rules_directory: /var/lib/loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

limits_config:
  retention_period: 744h
  ingestion_rate_mb: 16
  ingestion_burst_size_mb: 32
  per_stream_rate_limit: 3MB
  per_stream_rate_limit_burst: 15MB

schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

ruler:
  storage:
    type: local
    local:
      directory: /var/lib/loki/rules
  rule_path: /var/lib/loki/rules
  ring:
    kvstore:
      store: inmemory
  enable_api: true
EOF

log "Setting file permissions..."
chown -R loki:loki /opt/loki
chown -R loki:loki /var/lib/loki
chown -R loki:loki /etc/loki

log "Creating systemd service..."
cat > /etc/systemd/system/loki.service << EOF
[Unit]
Description=Loki log aggregation system
Documentation=https://grafana.com/docs/loki/
After=network.target

[Service]
Type=simple
User=loki
Group=loki
ExecStart=/opt/loki/loki -config.file=/etc/loki/loki.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=loki
KillMode=mixed
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF

log "Enabling Loki service..."
systemctl daemon-reload
systemctl enable loki

log "Finished Loki installation at $(date)."

log "Installing Grafana Tempo..."

log "Creating tempo user..."
useradd --system --shell /bin/false --home-dir /var/lib/tempo tempo || log "User tempo already exists"

log "Creating tempo directories..."
mkdir -p /etc/tempo
mkdir -p /var/lib/tempo
mkdir -p /var/log/tempo
chown -R tempo:tempo /var/lib/tempo
chown -R tempo:tempo /var/log/tempo
chown -R tempo:tempo /etc/tempo

log "Downloading Grafana Tempo v${TEMPO_VERSION}..."
cd /tmp
wget -q https://github.com/grafana/tempo/releases/download/v${TEMPO_VERSION}/tempo_${TEMPO_VERSION}_linux_amd64.tar.gz

if [ $? -ne 0 ]; then
    log "ERROR: Failed to download Tempo binary"
    exit 1
fi

log "Extracting and installing Tempo..."
tar -xzf tempo_${TEMPO_VERSION}_linux_amd64.tar.gz
mv tempo /usr/local/bin/tempo
chmod +x /usr/local/bin/tempo
rm -f tempo_${TEMPO_VERSION}_linux_amd64.tar.gz

log "Creating Tempo configuration..."
cat > /etc/tempo/tempo.yml << EOF
server:
  http_listen_port: 3200
  grpc_listen_port: 9095

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317
        http:
          endpoint: 0.0.0.0:4318

ingester:
  max_block_duration: 5m

compactor:
  compaction:
    block_retention: 1h

storage:
  trace:
    backend: local
    local:
      path: /var/lib/tempo/blocks
    wal:
      path: /var/lib/tempo/wal
    pool:
      max_workers: 100
      queue_depth: 10000

query_frontend:
  search:
    duration_slo: 5s
    throughput_bytes_slo: 1.073741824e+09
  trace_by_id:
    duration_slo: 5s

metrics_generator:
  registry:
    external_labels:
      source: tempo
      cluster: docker-compose
  storage:
    path: /var/lib/tempo/generator/wal
    remote_write:
      - url: http://localhost:9090/api/v1/write
        send_exemplars: true
EOF

chown tempo:tempo /etc/tempo/tempo.yml

log "Creating Tempo systemd service..."
cat > /etc/systemd/system/tempo.service << EOF
[Unit]
Description=Tempo
Documentation=https://grafana.com/docs/tempo/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=tempo
Group=tempo
ExecStart=/usr/local/bin/tempo -config.file=/etc/tempo/tempo.yml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tempo
KillMode=mixed
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF

log "Enabling Tempo service..."
systemctl daemon-reload
systemctl enable tempo

log "Finished Grafana Tempo installation at $(date)."

log "Starting Prometheus installation..."

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

log "Creating prometheus user and group..."
if ! getent group $PROMETHEUS_GROUP >/dev/null 2>&1; then
    groupadd --system $PROMETHEUS_GROUP
fi

if ! getent passwd $PROMETHEUS_USER >/dev/null 2>&1; then
    useradd -r -g $PROMETHEUS_GROUP -d $PROMETHEUS_HOME -s /sbin/nologin $PROMETHEUS_USER
fi

if [[ -n "$CONFIG_WRITER_USER" ]] && getent passwd "$CONFIG_WRITER_USER" >/dev/null 2>&1; then
    log "Adding user $CONFIG_WRITER_USER to prometheus group..."
    usermod -a -G $PROMETHEUS_GROUP "$CONFIG_WRITER_USER"
fi
log "Creating directories..."
mkdir -p $PROMETHEUS_CONFIG_DIR
mkdir -p $PROMETHEUS_HOME
mkdir -p $PROMETHEUS_CONFIG_DIR/consoles
mkdir -p $PROMETHEUS_CONFIG_DIR/console_libraries

chown $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_CONFIG_DIR
chown $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_HOME

chmod 2775 $PROMETHEUS_CONFIG_DIR  # 2775 = drwxrwsr-x
chmod 2775 $PROMETHEUS_CONFIG_DIR/consoles
chmod 2775 $PROMETHEUS_CONFIG_DIR/console_libraries

log "Downloading Prometheus v$PROMETHEUS_VERSION..."

download_url="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz"
temp_dir="/tmp/prometheus-install"

mkdir -p $temp_dir
cd $temp_dir

wget -q "$download_url" -O prometheus.tar.gz || error "Failed to download Prometheus"
tar -xzf prometheus.tar.gz --strip-components=1 || error "Failed to extract Prometheus"
log "Installing Prometheus binaries..."

cp prometheus $PROMETHEUS_BIN_DIR/
cp promtool $PROMETHEUS_BIN_DIR/

chown $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_BIN_DIR/prometheus
chown $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_BIN_DIR/promtool

chmod +x $PROMETHEUS_BIN_DIR/prometheus
chmod +x $PROMETHEUS_BIN_DIR/promtool

if [ -d "consoles" ] && [ "$(ls -A consoles)" ]; then
    cp -r consoles/* $PROMETHEUS_CONFIG_DIR/consoles/
fi
if [ -d "console_libraries" ] && [ "$(ls -A console_libraries)" ]; then
    cp -r console_libraries/* $PROMETHEUS_CONFIG_DIR/console_libraries/
fi

chown -R $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_CONFIG_DIR/consoles
chown -R $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_CONFIG_DIR/console_libraries
log "Creating default Prometheus configuration..."

cat > $PROMETHEUS_CONFIG_DIR/prometheus.yml << 'EOF'
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

# Prometheus handles all the scraping
scrape_configs:
  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Node Exporter
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 10s

  # Loki metrics
  - job_name: 'loki'
    static_configs:
      - targets: ['localhost:3100']
    metrics_path: /metrics

  # Tempo metrics
  - job_name: 'tempo'
    static_configs:
      - targets: ['localhost:3200']
    metrics_path: /metrics

  - job_name: 'alloy'
    static_configs:
      - targets: ['localhost:12345']  # Default Alloy metrics port
    metrics_path: /metrics
EOF
    
chown $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_CONFIG_DIR/prometheus.yml
chmod 664 $PROMETHEUS_CONFIG_DIR/prometheus.yml  # 664 = -rw-rw-r--

log "Setting final permissions..."

find $PROMETHEUS_CONFIG_DIR -type f -exec chmod 664 {} \;
find $PROMETHEUS_CONFIG_DIR -type d -exec chmod 2775 {} \;

chown -R $PROMETHEUS_USER:$PROMETHEUS_GROUP $PROMETHEUS_CONFIG_DIR

log "Creating systemd service..."

cat > $PROMETHEUS_SERVICE_FILE << EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=$PROMETHEUS_USER
Group=$PROMETHEUS_GROUP
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=$PROMETHEUS_BIN_DIR/prometheus \\
    --config.file=$PROMETHEUS_CONFIG_DIR/prometheus.yml \\
    --storage.tsdb.path=$PROMETHEUS_HOME \\
    --web.console.templates=$PROMETHEUS_CONFIG_DIR/consoles \\
    --web.console.libraries=$PROMETHEUS_CONFIG_DIR/console_libraries \\
    --web.listen-address=0.0.0.0:9090 \\
    --web.enable-lifecycle \\
    --web.enable-remote-write-receiver

[Install]
WantedBy=multi-user.target
EOF

log "Enabling Prometheus service (will start on reboot)..."

systemctl daemon-reload
systemctl enable prometheus

log "Cleaning up..."
rm -rf /tmp/prometheus-install

log "Prometheus installation completed successfully!"
log "Version: $PROMETHEUS_VERSION"
log "Service enabled and will start on reboot"

if [[ -n "$CONFIG_WRITER_USER" ]]; then
    log "User $CONFIG_WRITER_USER has been added to prometheus group"
    log "They can now write to $PROMETHEUS_CONFIG_DIR"
    log "Note: $CONFIG_WRITER_USER may need to log out and back in for group membership to take effect"
fi

log "Starting caddy installation..."

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy

log "Configuring Caddy for telemetry services..."

cat > /etc/caddy/Caddyfile << EOF
# Mithlond application reverse proxy configuration
${MITHLOND_DOMAIN_NAME:-your-domain.com} {
    reverse_proxy localhost:8080
}

${TEL_PROM_DOMAIN_NAME:-your-domain.com} {
	basic_auth {
		${CADDY_USER_NAME} ${CADDY_PASSWORD}
    }

	reverse_proxy localhost:9090
}

${TEL_LOKI_DOMAIN_NAME:-your-domain.com} {
	basic_auth {
		${CADDY_USER_NAME} ${CADDY_PASSWORD}
    }

    reverse_proxy localhost:3100
}

${TEL_TEMPO_DOMAIN_NAME:-your-domain.com} {
	basic_auth {
		${CADDY_USER_NAME} ${CADDY_PASSWORD}
    }

    reverse_proxy localhost:3200
}

${TEL_ALLOY_DOMAIN_NAME:-your-domain.com} {
	basic_auth {
		${CADDY_USER_NAME} ${CADDY_PASSWORD}
    }

    # Route for /ingestor
    route /ingestor* {
            uri strip_prefix /ingestor
            reverse_proxy localhost:4321
    }

    reverse_proxy localhost:12345
}
EOF

mkdir -p /var/log/caddy
chown caddy:caddy /var/log/caddy

log "Enabling Caddy service (but not starting yet)..."
systemctl enable caddy

log "Starting mithlond app setup..."

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

log "Downloading Mithlond binary version ${LATEST_RELEASE}..."
curl -fsSL "https://github.com/mbvlabs/mithlond-ce/releases/download/${LATEST_RELEASE}/mithlond-linux-amd64" -o "$INSTALL_DIR/mithlond-linux-amd64"

chmod +x "$INSTALL_DIR/mithlond-linux-amd64"

touch "$INSTALL_DIR/mithlond_prod.db"

chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 644 "$INSTALL_DIR/mithlond_prod.db"

log "Creating environment configuration..."
cat > "$CONFIG_DIR/mithlond.env" << EOF
ENVIRONMENT=production

SERVER_HOST=0.0.0.0
SERVER_PORT=8080
DEFAULT_SENDER_SIGNATURE=info@$ROOT_DOMAIN

DB_KIND=sqlite3

DB_PATH=$INSTALL_DIR/mithlond_prod.db

PASSWORD_SALT=$PASSWORD_SALT

PROJECT_NAME=mithlond
APP_DOMAIN=mithlond.$ROOT_DOMAIN
APP_PROTOCOL=https

SESSION_KEY=$SESSION_KEY
SESSION_ENCRYPTION_KEY=$SESSION_ENCRYPTION_KEY

TOKEN_SIGNING_KEY=$TOKEN_SIGNING_KEY

SUDO_USER=$USER_NAME
SUDO_PASSWORD=$USER_PASSWORD

CLOUDFLARE_APIKEY=$CLOUDFLARE_API_KEY

TELEMETRY_SERVICE_NAME=mithlond
TELEMETRY_OTLP_ENDPOINT=http://localhost:4317
EOF

chown "$USER_NAME:$USER_NAME" "$CONFIG_DIR/mithlond.env"

log "Creating systemd service..."
cat > /etc/systemd/system/mithlond.service << EOF
[Unit]
Description=Mithlond Application Server
After=network.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/mithlond-linux-amd64
Restart=always
RestartSec=10
EnvironmentFile=$CONFIG_DIR/mithlond.env

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR /etc/prometheus

[Install]
WantedBy=multi-user.target
EOF

log "Creating update socket unit..."
cat > /etc/systemd/system/mithlond-update.socket << EOF
[Unit]
Description=Mithlond Update Socket

[Socket]
ListenStream=/run/mithlond-update.sock
SocketMode=0660
SocketUser=$USER_NAME
SocketGroup=$USER_NAME

[Install]
WantedBy=sockets.target
EOF

SERVICE_NAME="mithlond"
BINARY_PATH="$INSTALL_DIR/mithlond-linux-amd64"

cat > $INSTALL_DIR/update-app.sh << EOF
#!/bin/bash
set -e

# Configuration
INSTALL_DIR="$INSTALL_DIR"
SERVICE_NAME="$SERVICE_NAME"
BINARY_PATH="$BINARY_PATH"
BACKUP_PATH="\${BINARY_PATH}.backup"
TEMP_BINARY="/tmp/mithlond-linux-amd64"

# Function to rollback on failure
rollback() {
    echo "Something went wrong! Rolling back..."
    sudo systemctl stop "\$SERVICE_NAME" 2>/dev/null || true
    sudo mv "\$BACKUP_PATH" "\$BINARY_PATH" 2>/dev/null || true
    sudo systemctl start "\$SERVICE_NAME"
    echo "Rollback completed"
    exit 1
}

# Set trap to call rollback on any error
trap rollback ERR

echo "Starting \$SERVICE_NAME update..."
wget -O "\$TEMP_BINARY" https://github.com/mbvlabs/mithlond/releases/latest/download/mithlond-linux-amd64
chmod +x "\$TEMP_BINARY"
sudo cp "\$BINARY_PATH" "\$BACKUP_PATH"
sudo systemctl stop "\$SERVICE_NAME"
sudo mv "\$TEMP_BINARY" "\$BINARY_PATH"
sudo systemctl start "\$SERVICE_NAME"

# Wait a moment for service to fully start
sleep 2

# Verify service is running properly
if sudo systemctl is-active --quiet "\$SERVICE_NAME"; then
    echo "Update successful! Service is running."
    sudo systemctl status "\$SERVICE_NAME"
    echo "Cleaning up backup..."
    sudo rm "\$BACKUP_PATH"
    echo "Update completed successfully"
else
    echo "Service is not active, triggering rollback..."
    false  # This will trigger the trap
fi

# Clear the trap since we succeeded
trap - ERR
EOF

chown "$USER_NAME:$USER_NAME" "$INSTALL_DIR/update-app.sh"
chmod 755 "$INSTALL_DIR/update-app.sh"

log "Creating update service unit..."
cat > /etc/systemd/system/mithlond-update.service << EOF
[Unit]
Description=Mithlond Application Update
After=network.target

[Service]
Type=oneshot
User=$USER_NAME
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/update-app.sh
StandardOutput=journal
StandardError=journal
StandardInput=socket
EOF

log "Reloading systemd daemon, enabling, and starting mithlond service..."

systemctl enable mithlond
systemctl enable mithlond-update.socket
systemctl start mithlond-update.socket

log "Installation process completed successfully!"

# echo "=========================================="
# echo "Mithlond Installation Complete!"
# echo "=========================================="
# echo "Access your application at: https://mithlond.$ROOT_DOMAIN"
# echo 
# echo "Admin credentials:"
# echo "Email: admin@admin.com"
# echo "Password: password"
# echo 
# echo "=========================================="
# echo "SSH access: ssh -i path-to-private-key -p $SSH_PORT $USER_NAME@$(curl -s -4 ifconfig.me)"
# echo "=========================================="
