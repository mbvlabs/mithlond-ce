#!/bin/bash

# SSH Hardening script specifically for install.sh
# This version copies root's SSH keys to the new user

# TODO: configurable
timedatectl set-timezone Europe/Copenhagen

if ! id "$USER_NAME" &>/dev/null; then
    useradd -m -u 1000 -s /bin/bash "$USER_NAME"
fi

usermod -aG sudo "$USER_NAME"

echo "Admin Password: $USER_PASSWORD"
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

# sudo apt-get install -y apache2-utils
snap install btop

echo "SSH hardening (install version) setup complete!"
