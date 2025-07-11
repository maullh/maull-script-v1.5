#!/bin/bash

# SSH Tunneling VPS Auto-Install Script
# Compatible with Ubuntu/Debian systems
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_VERSION="1.0"
LOG_FILE="/var/log/ssh-tunnel-install.log"
CONFIG_DIR="/etc/ssh-tunnel"
SERVICE_NAME="ssh-tunnel-manager"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  SSH Tunneling VPS Installer${NC}"
    echo -e "${BLUE}  Version: $SCRIPT_VERSION${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS version"
        exit 1
    fi
    
    print_status "Detected OS: $OS $VERSION"
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    apt-get update -y >> "$LOG_FILE" 2>&1
    apt-get upgrade -y >> "$LOG_FILE" 2>&1
    print_status "System updated successfully"
}

# Function to install required packages
install_packages() {
    print_status "Installing required packages..."
    
    local packages=(
        "openssh-server"
        "ufw"
        "fail2ban"
        "htop"
        "iftop"
        "netstat-nat"
        "curl"
        "wget"
        "nano"
        "vim"
        "screen"
        "tmux"
        "git"
        "python3"
        "python3-pip"
        "jq"
        "bc"
        "net-tools"
        "dnsutils"
        "tcpdump"
        "nmap"
        "stunnel4"
        "dropbear"
        "squid"
        "nginx"
        "openvpn"
        "easy-rsa"
        "shadowsocks-libev"
        "v2ray"
        "dante-server"
        "proxychains"
        "autossh"
        "sshuttle"
        "socat"
        "haproxy"
        "supervisor"
    )
    
    for package in "${packages[@]}"; do
        print_status "Installing $package..."
        apt-get install -y "$package" >> "$LOG_FILE" 2>&1
        if [[ $? -eq 0 ]]; then
            print_status "$package installed successfully"
        else
            print_warning "Failed to install $package"
        fi
    done
}

# Function to configure SSH server
configure_ssh() {
    print_status "Configuring SSH server..."
    
    # Backup original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create new SSH config
    cat > /etc/ssh/sshd_config << 'EOF'
# SSH Configuration for Tunneling
Port 22
Port 2222
Port 443
Port 80

Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024

SyslogFacility AUTH
LogLevel INFO

LoginGraceTime 120
PermitRootLogin no
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile %h/.ssh/authorized_keys

IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes

AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

UsePAM yes

# Tunneling Configuration
AllowTcpForwarding yes
GatewayPorts yes
PermitTunnel yes
AllowAgentForwarding yes

# Performance Tuning
MaxAuthTries 3
MaxSessions 20
MaxStartups 100:30:200
ClientAliveInterval 60
ClientAliveCountMax 3

# Compression
Compression delayed
EOF

    # Restart SSH service
    systemctl restart ssh
    systemctl enable ssh
    print_status "SSH server configured successfully"
}

# Function to configure Dropbear
configure_dropbear() {
    print_status "Configuring Dropbear SSH server..."
    
    # Configure Dropbear
    cat > /etc/default/dropbear << 'EOF'
# Dropbear SSH server configuration
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109 -p 110"
DROPBEAR_BANNER="/etc/dropbear/banner"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

    # Create banner
    mkdir -p /etc/dropbear
    cat > /etc/dropbear/banner << 'EOF'
=====================================
   SSH Tunneling Server Ready
=====================================
EOF

    systemctl restart dropbear
    systemctl enable dropbear
    print_status "Dropbear configured successfully"
}

# Function to configure Stunnel
configure_stunnel() {
    print_status "Configuring Stunnel..."
    
    # Enable Stunnel
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
    
    # Create Stunnel configuration
    cat > /etc/stunnel/stunnel.conf << 'EOF'
# Stunnel Configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel4.pid
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 442
connect = 127.0.0.1:143

[ssh]
accept = 443
connect = 127.0.0.1:22

[openvpn]
accept = 992
connect = 127.0.0.1:1194
EOF

    # Generate SSL certificate
    openssl req -new -x509 -days 365 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    
    systemctl restart stunnel4
    systemctl enable stunnel4
    print_status "Stunnel configured successfully"
}

# Function to configure Squid proxy
configure_squid() {
    print_status "Configuring Squid proxy..."
    
    # Backup original config
    cp /etc/squid/squid.conf /etc/squid/squid.conf.backup
    
    # Create new Squid config
    cat > /etc/squid/squid.conf << 'EOF'
# Squid Configuration for Tunneling
http_port 8080
http_port 3128

# Access Control
acl all src 0.0.0.0/0.0.0.0
acl manager proto cache_object
acl localhost src 127.0.0.1/32
acl to_localhost dst 127.0.0.0/8
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# Safe ports
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT

# Access rules
http_access allow manager localhost
http_access deny manager
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access allow all

# Performance
cache_mem 256 MB
cache_dir ufs /var/spool/squid 1024 16 256
maximum_object_size 1024 MB
maximum_object_size_in_memory 512 KB

# Logging
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
EOF

    # Initialize Squid cache
    squid -z
    
    systemctl restart squid
    systemctl enable squid
    print_status "Squid proxy configured successfully"
}

# Function to configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    # Reset UFW
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH ports
    ufw allow 22/tcp
    ufw allow 2222/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow tunnel ports
    ufw allow 109/tcp
    ufw allow 110/tcp
    ufw allow 143/tcp
    ufw allow 442/tcp
    ufw allow 992/tcp
    
    # Allow proxy ports
    ufw allow 3128/tcp
    ufw allow 8080/tcp
    
    # Allow VPN ports
    ufw allow 1194/udp
    ufw allow 1194/tcp
    
    # Enable UFW
    ufw --force enable
    
    print_status "Firewall configured successfully"
}

# Function to configure fail2ban
configure_fail2ban() {
    print_status "Configuring Fail2Ban..."
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = 22,2222,80,443
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[dropbear]
enabled = true
port = 109,110,143
filter = dropbear
logpath = /var/log/auth.log
maxretry = 3

[squid]
enabled = true
port = 3128,8080
filter = squid
logpath = /var/log/squid/access.log
maxretry = 5
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban
    print_status "Fail2Ban configured successfully"
}

# Function to create management tools
create_management_tools() {
    print_status "Creating management tools..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    
    # Create user management script
    cat > "$CONFIG_DIR/manage-users.sh" << 'EOF'
#!/bin/bash

# User Management Script
ACTION=$1
USERNAME=$2
PASSWORD=$3
EXPIRE_DAYS=$4

case $ACTION in
    "add")
        if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
            echo "Usage: $0 add username password [expire_days]"
            exit 1
        fi
        
        # Create user
        useradd -m -s /bin/bash "$USERNAME"
        echo "$USERNAME:$PASSWORD" | chpasswd
        
        # Set expiration if specified
        if [[ -n "$EXPIRE_DAYS" ]]; then
            chage -E $(date -d "+$EXPIRE_DAYS days" +%Y-%m-%d) "$USERNAME"
        fi
        
        echo "User $USERNAME created successfully"
        ;;
    
    "delete")
        if [[ -z "$USERNAME" ]]; then
            echo "Usage: $0 delete username"
            exit 1
        fi
        
        userdel -r "$USERNAME"
        echo "User $USERNAME deleted successfully"
        ;;
    
    "list")
        echo "Active SSH tunnel users:"
        cut -d: -f1 /etc/passwd | grep -E "^[^:]+$" | grep -v -E "^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd-network|systemd-resolve|syslog|messagebus|_apt|lxd|uuidd|dnsmasq|landscape|pollinate|sshd|fwupd-refresh)$"
        ;;
    
    "reset")
        if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
            echo "Usage: $0 reset username new_password"
            exit 1
        fi
        
        echo "$USERNAME:$PASSWORD" | chpasswd
        echo "Password for $USERNAME reset successfully"
        ;;
    
    *)
        echo "Usage: $0 {add|delete|list|reset} [username] [password] [expire_days]"
        exit 1
        ;;
esac
EOF

    chmod +x "$CONFIG_DIR/manage-users.sh"
    
    # Create monitoring script
    cat > "$CONFIG_DIR/monitor.sh" << 'EOF'
#!/bin/bash

# SSH Tunnel Monitoring Script

echo "=== SSH Tunnel Server Status ==="
echo "Date: $(date)"
echo ""

echo "=== Active SSH Connections ==="
netstat -tnp | grep :22 | grep ESTABLISHED | wc -l
echo ""

echo "=== Port Status ==="
netstat -tlnp | grep -E "(22|80|443|109|110|143|442|992|3128|8080|1194)"
echo ""

echo "=== Service Status ==="
systemctl status ssh --no-pager -l
systemctl status dropbear --no-pager -l
systemctl status stunnel4 --no-pager -l
systemctl status squid --no-pager -l
echo ""

echo "=== System Resources ==="
free -h
df -h
echo ""

echo "=== Active Users ==="
who
echo ""

echo "=== Recent Failed Login Attempts ==="
tail -n 20 /var/log/auth.log | grep "Failed password"
EOF

    chmod +x "$CONFIG_DIR/monitor.sh"
    
    # Create info script
    cat > "$CONFIG_DIR/server-info.sh" << 'EOF'
#!/bin/bash

# Server Information Script

echo "=== SSH Tunnel Server Information ==="
echo "Server IP: $(curl -s ifconfig.me)"
echo "Hostname: $(hostname)"
echo "OS: $(lsb_release -d | cut -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo ""

echo "=== Available Ports ==="
echo "SSH: 22, 2222, 80, 443"
echo "Dropbear: 109, 110, 143"
echo "Stunnel: 442, 992"
echo "Squid Proxy: 3128, 8080"
echo "OpenVPN: 1194"
echo ""

echo "=== Connection Examples ==="
echo "SSH: ssh username@$(curl -s ifconfig.me) -p 22"
echo "SSH via HTTP: ssh username@$(curl -s ifconfig.me) -p 80"
echo "SSH via HTTPS: ssh username@$(curl -s ifconfig.me) -p 443"
echo "Dropbear: ssh username@$(curl -s ifconfig.me) -p 109"
echo "Stunnel: stunnel client config needed"
echo "Proxy: $(curl -s ifconfig.me):3128"
echo ""

echo "=== Management Commands ==="
echo "Add user: $CONFIG_DIR/manage-users.sh add username password [expire_days]"
echo "Delete user: $CONFIG_DIR/manage-users.sh delete username"
echo "List users: $CONFIG_DIR/manage-users.sh list"
echo "Reset password: $CONFIG_DIR/manage-users.sh reset username new_password"
echo "Monitor: $CONFIG_DIR/monitor.sh"
echo "Server info: $CONFIG_DIR/server-info.sh"
EOF

    chmod +x "$CONFIG_DIR/server-info.sh"
    
    print_status "Management tools created successfully"
}

# Function to optimize system
optimize_system() {
    print_status "Optimizing system for tunneling..."
    
    # Kernel parameters for better networking
    cat >> /etc/sysctl.conf << 'EOF'

# SSH Tunnel Optimizations
net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 30
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 65536
EOF

    sysctl -p
    
    # Increase limits
    cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 65536
* hard nofile 65536
* soft nproc 65536
* hard nproc 65536
EOF

    print_status "System optimized successfully"
}

# Function to create systemd service
create_service() {
    print_status "Creating systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SSH Tunnel Manager Service
After=network.target

[Service]
Type=simple
ExecStart=$CONFIG_DIR/monitor.sh
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    print_status "Systemd service created successfully"
}

# Function to create installation summary
create_summary() {
    print_status "Creating installation summary..."
    
    cat > "$CONFIG_DIR/README.md" << 'EOF'
# SSH Tunneling VPS Setup Complete

## Server Information
- **Server IP**: Check with `curl ifconfig.me`
- **Installation Date**: $(date)
- **Configuration Directory**: /etc/ssh-tunnel

## Available Services

### SSH Servers
- **OpenSSH**: Ports 22, 2222, 80, 443
- **Dropbear**: Ports 109, 110, 143

### Proxy Services
- **Squid Proxy**: Ports 3128, 8080
- **Stunnel SSL**: Ports 442, 992

### Security
- **Fail2Ban**: Enabled with SSH protection
- **UFW Firewall**: Configured with required ports

## Management Commands

### User Management
```bash
# Add user
/etc/ssh-tunnel/manage-users.sh add username password [expire_days]

# Delete user
/etc/ssh-tunnel/manage-users.sh delete username

# List users
/etc/ssh-tunnel/manage-users.sh list

# Reset password
/etc/ssh-tunnel/manage-users.sh reset username new_password
```

### Monitoring
```bash
# Check server status
/etc/ssh-tunnel/monitor.sh

# Show server info
/etc/ssh-tunnel/server-info.sh
```

## Connection Examples

### SSH Tunneling
```bash
# Standard SSH
ssh username@YOUR_SERVER_IP -p 22

# SSH via HTTP port
ssh username@YOUR_SERVER_IP -p 80

# SSH via HTTPS port
ssh username@YOUR_SERVER_IP -p 443

# Dynamic SOCKS proxy
ssh -D 1080 username@YOUR_SERVER_IP -p 22
```

### HTTP Proxy
```bash
# Use proxy in applications
http_proxy=http://YOUR_SERVER_IP:3128
https_proxy=http://YOUR_SERVER_IP:3128
```

## Important Files
- SSH Config: `/etc/ssh/sshd_config`
- Dropbear Config: `/etc/default/dropbear`
- Stunnel Config: `/etc/stunnel/stunnel.conf`
- Squid Config: `/etc/squid/squid.conf`
- Firewall Rules: `ufw status`
- Fail2Ban Config: `/etc/fail2ban/jail.local`

## Security Notes
- Root login is disabled
- Fail2Ban is monitoring all services
- Firewall is configured to allow only necessary ports
- All services are configured for optimal security

## Troubleshooting
- Check service status: `systemctl status service_name`
- View logs: `journalctl -u service_name`
- Monitor connections: `netstat -tlnp`
- Check firewall: `ufw status`

EOF

    print_status "Installation summary created at $CONFIG_DIR/README.md"
}

# Main installation function
main() {
    print_header
    
    # Initialize log file
    echo "SSH Tunnel Installation Started - $(date)" > "$LOG_FILE"
    
    # Run installation steps
    check_root
    detect_os
    update_system
    install_packages
    configure_ssh
    configure_dropbear
    configure_stunnel
    configure_squid
    configure_firewall
    configure_fail2ban
    create_management_tools
    optimize_system
    create_service
    create_summary
    
    print_status "Installation completed successfully!"
    print_status "Check $CONFIG_DIR/README.md for usage instructions"
    print_status "Run '$CONFIG_DIR/server-info.sh' to see server information"
    
    echo ""
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Create tunnel users: $CONFIG_DIR/manage-users.sh add username password"
    echo "2. Check server info: $CONFIG_DIR/server-info.sh"
    echo "3. Monitor connections: $CONFIG_DIR/monitor.sh"
    echo ""
    echo "Server is ready for SSH tunneling!"
}

# Run the main function
main "$@"
EOF