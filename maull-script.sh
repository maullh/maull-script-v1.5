#!/bin/bash

# Maull-Script V1.5 - Advanced VPN/Tunnel Manager
# Compatible with Ubuntu 20.04, 22.04, 24.04 and Debian 10, 11, 12
# Author: Maull-Script Team
# Version: 1.5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_VERSION="1.5"
SCRIPT_NAME="Maull-Script"
CONFIG_DIR="/etc/maull-script"
LOG_FILE="/var/log/maull-script.log"
DOMAIN_FILE="$CONFIG_DIR/domain.conf"
USERS_DIR="$CONFIG_DIR/users"
CERTS_DIR="$CONFIG_DIR/certs"

# Check if script should show menu
if [[ "$1" != "menu" && "$1" != "install" ]]; then
    exit 0
fi

# Function to print colored output
print_header() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    ${WHITE}${SCRIPT_NAME} V${SCRIPT_VERSION}${CYAN}                        ║${NC}"
    echo -e "${CYAN}║              ${GREEN}Advanced VPN/Tunnel Manager${CYAN}                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
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
    
    # Check if OS is supported
    case $OS in
        "Ubuntu")
            if [[ ! "$VERSION" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
                print_error "Ubuntu version $VERSION is not supported. Supported: 20.04, 22.04, 24.04"
                exit 1
            fi
            ;;
        "Debian GNU/Linux")
            if [[ ! "$VERSION" =~ ^(10|11|12)$ ]]; then
                print_error "Debian version $VERSION is not supported. Supported: 10, 11, 12"
                exit 1
            fi
            ;;
        *)
            print_error "OS $OS is not supported"
            exit 1
            ;;
    esac
    
    print_status "Detected OS: $OS $VERSION"
}

# Function to count active accounts
count_accounts() {
    local ssh_count=0
    local vmess_count=0
    local vless_count=0
    local trojan_count=0
    local shadowsocks_count=0
    local noobz_count=0
    
    if [[ -d "$USERS_DIR" ]]; then
        ssh_count=$(find "$USERS_DIR/ssh" -name "*.conf" 2>/dev/null | wc -l)
        vmess_count=$(find "$USERS_DIR/vmess" -name "*.json" 2>/dev/null | wc -l)
        vless_count=$(find "$USERS_DIR/vless" -name "*.json" 2>/dev/null | wc -l)
        trojan_count=$(find "$USERS_DIR/trojan" -name "*.json" 2>/dev/null | wc -l)
        shadowsocks_count=$(find "$USERS_DIR/shadowsocks" -name "*.json" 2>/dev/null | wc -l)
        noobz_count=$(find "$USERS_DIR/noobz" -name "*.conf" 2>/dev/null | wc -l)
    fi
    
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    ${WHITE}ACTIVE ACCOUNTS${CYAN}                        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${GREEN}SSH/OpenVPN/SlowDNS${CYAN}    : ${WHITE}$ssh_count accounts${CYAN}                  ║${NC}"
    echo -e "${CYAN}║ ${GREEN}VMess${CYAN}                : ${WHITE}$vmess_count accounts${CYAN}                  ║${NC}"
    echo -e "${CYAN}║ ${GREEN}VLess${CYAN}                : ${WHITE}$vless_count accounts${CYAN}                  ║${NC}"
    echo -e "${CYAN}║ ${GREEN}Trojan${CYAN}               : ${WHITE}$trojan_count accounts${CYAN}                  ║${NC}"
    echo -e "${CYAN}║ ${GREEN}ShadowSocks${CYAN}          : ${WHITE}$shadowsocks_count accounts${CYAN}                  ║${NC}"
    echo -e "${CYAN}║ ${GREEN}NoobzVPN${CYAN}             : ${WHITE}$noobz_count accounts${CYAN}                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to show main menu
show_menu() {
    print_header
    count_accounts
    
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      ${WHITE}MAIN MENU${CYAN}                           ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${GREEN}1.${NC}  SSH WS & SSL Management                              ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}2.${NC}  SSH UDP Management                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}3.${NC}  SSH SlowDNS Management                              ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}4.${NC}  SSH OpenVPN Management                              ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}5.${NC}  ShadowSocks Management                              ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}6.${NC}  VMess Management                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}7.${NC}  VLess Management                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}8.${NC}  Trojan Management                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}9.${NC}  NoobzVPN Management                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${YELLOW}10.${NC} Domain & SSL Management                             ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${YELLOW}11.${NC} System Monitoring                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${YELLOW}12.${NC} Security Settings                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${YELLOW}13.${NC} Traffic Engineering                                 ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${YELLOW}14.${NC} Backup & Restore                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${YELLOW}15.${NC} System Information                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${RED}0.${NC}  Exit                                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${WHITE}Select option [0-15]: ${NC}"
}

# Function to install required packages
install_packages() {
    print_status "Installing required packages..."
    
    # Update system
    apt-get update -y >> "$LOG_FILE" 2>&1
    apt-get upgrade -y >> "$LOG_FILE" 2>&1
    
    # Install basic packages
    local packages=(
        "curl" "wget" "nano" "vim" "htop" "iftop" "jq" "bc" "git"
        "net-tools" "dnsutils" "tcpdump" "nmap" "screen" "tmux"
        "ufw" "fail2ban" "nginx" "certbot" "python3-certbot-nginx"
        "openssh-server" "dropbear" "stunnel4" "squid" "privoxy"
        "openvpn" "easy-rsa" "shadowsocks-libev" "v2ray" "xray"
        "haproxy" "supervisor" "cron" "logrotate" "unzip" "zip"
        "python3" "python3-pip" "nodejs" "npm" "golang-go"
        "build-essential" "cmake" "pkg-config" "libssl-dev"
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
    
    # Install Sing-box
    install_singbox
    
    # Install Hysteria 2
    install_hysteria2
    
    # Install TUIC
    install_tuic
}

# Function to install Sing-box
install_singbox() {
    print_status "Installing Sing-box..."
    
    # Download and install sing-box
    local latest_version=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    local download_url="https://github.com/SagerNet/sing-box/releases/download/${latest_version}/sing-box-${latest_version#v}-linux-amd64.tar.gz"
    
    cd /tmp
    wget -O sing-box.tar.gz "$download_url" >> "$LOG_FILE" 2>&1
    tar -xzf sing-box.tar.gz
    cp sing-box-*/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # Create sing-box service
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=1800s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /etc/sing-box
    systemctl daemon-reload
    systemctl enable sing-box
    
    print_status "Sing-box installed successfully"
}

# Function to install Hysteria 2
install_hysteria2() {
    print_status "Installing Hysteria 2..."
    
    # Download and install hysteria
    bash <(curl -fsSL https://get.hy2.sh/) >> "$LOG_FILE" 2>&1
    
    # Create hysteria service
    cat > /etc/systemd/system/hysteria.service << 'EOF'
[Unit]
Description=Hysteria Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /etc/hysteria
    systemctl daemon-reload
    systemctl enable hysteria
    
    print_status "Hysteria 2 installed successfully"
}

# Function to install TUIC
install_tuic() {
    print_status "Installing TUIC..."
    
    # Download and install TUIC
    local latest_version=$(curl -s https://api.github.com/repos/EAimTY/tuic/releases/latest | jq -r .tag_name)
    local download_url="https://github.com/EAimTY/tuic/releases/download/${latest_version}/tuic-server-${latest_version}-x86_64-unknown-linux-gnu"
    
    wget -O /usr/local/bin/tuic-server "$download_url" >> "$LOG_FILE" 2>&1
    chmod +x /usr/local/bin/tuic-server
    
    # Create TUIC service
    cat > /etc/systemd/system/tuic.service << 'EOF'
[Unit]
Description=TUIC Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tuic-server -c /etc/tuic/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /etc/tuic
    systemctl daemon-reload
    systemctl enable tuic
    
    print_status "TUIC installed successfully"
}

# Function to configure SSH services
configure_ssh() {
    print_status "Configuring SSH services..."
    
    # Backup original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create optimized SSH config
    cat > /etc/ssh/sshd_config << 'EOF'
# SSH Configuration for Tunneling
Port 22
Port 2222

Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
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
MaxSessions 50
MaxStartups 100:30:200
ClientAliveInterval 60
ClientAliveCountMax 3

# Compression
Compression delayed
EOF

    # Configure Dropbear
    cat > /etc/default/dropbear << 'EOF'
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109 -p 110"
DROPBEAR_BANNER="/etc/dropbear/banner"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

    mkdir -p /etc/dropbear
    cat > /etc/dropbear/banner << 'EOF'
=====================================
   Maull-Script SSH Server Ready
=====================================
EOF

    # Configure Stunnel
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
    
    cat > /etc/stunnel/stunnel.conf << 'EOF'
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
EOF

    # Generate SSL certificate for Stunnel
    openssl req -new -x509 -days 365 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    
    # Restart services
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart stunnel4
    
    print_status "SSH services configured successfully"
}

# Function to configure Nginx and reverse proxy
configure_nginx() {
    print_status "Configuring Nginx reverse proxy..."
    
    # Remove default nginx config
    rm -f /etc/nginx/sites-enabled/default
    
    # Create main nginx config
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    
    # Include site configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

stream {
    # Stream configurations for TCP/UDP proxying
    include /etc/nginx/stream.d/*.conf;
}
EOF

    # Create directories
    mkdir -p /etc/nginx/stream.d
    mkdir -p /var/www/html
    
    # Create default index page
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Maull-Script Server</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        .logo { font-size: 2em; color: #333; margin-bottom: 20px; }
        .status { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🚀 Maull-Script V1.5</div>
        <h1>Server is Running</h1>
        <p class="status">✅ All services are operational</p>
        <p>Advanced VPN/Tunnel Manager</p>
    </div>
</body>
</html>
EOF

    systemctl restart nginx
    systemctl enable nginx
    
    print_status "Nginx configured successfully"
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
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow tunnel ports
    ufw allow 109/tcp
    ufw allow 110/tcp
    ufw allow 143/tcp
    ufw allow 442/tcp
    
    # Allow proxy ports
    ufw allow 3128/tcp
    ufw allow 8080/tcp
    ufw allow 8880/tcp
    
    # Allow VPN ports
    ufw allow 1194/udp
    ufw allow 1194/tcp
    
    # Allow V2Ray/Xray ports
    ufw allow 10000:10100/tcp
    ufw allow 10000:10100/udp
    
    # Allow Hysteria/TUIC ports
    ufw allow 36712/udp
    ufw allow 36713/udp
    
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
banaction = ufw

[sshd]
enabled = true
port = 22,2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[dropbear]
enabled = true
port = 109,110,143
filter = dropbear
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 3
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban
    
    print_status "Fail2Ban configured successfully"
}

# Function to optimize system
optimize_system() {
    print_status "Optimizing system for tunneling..."
    
    # Kernel parameters
    cat >> /etc/sysctl.conf << 'EOF'

# Maull-Script Optimizations
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
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
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
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

# Function to create directories
create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$USERS_DIR"/{ssh,vmess,vless,trojan,shadowsocks,noobz}
    mkdir -p "$CERTS_DIR"
    mkdir -p /var/log/maull-script
    
    print_status "Directories created successfully"
}

# Function to create management tools
create_management_tools() {
    print_status "Creating management tools..."
    
    # Create SSH user management script
    cat > "$CONFIG_DIR/ssh-manager.sh" << 'EOF'
#!/bin/bash

CONFIG_DIR="/etc/maull-script"
USERS_DIR="$CONFIG_DIR/users/ssh"

case $1 in
    "add")
        username=$2
        password=$3
        days=${4:-30}
        
        if [[ -z "$username" || -z "$password" ]]; then
            echo "Usage: $0 add username password [days]"
            exit 1
        fi
        
        # Create user
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        
        # Set expiration
        exp_date=$(date -d "+$days days" +%Y-%m-%d)
        chage -E "$exp_date" "$username"
        
        # Save user info
        cat > "$USERS_DIR/$username.conf" << EOL
username=$username
password=$password
created=$(date)
expires=$exp_date
protocol=ssh
EOL
        
        echo "SSH user $username created successfully"
        echo "Expires: $exp_date"
        ;;
    
    "delete")
        username=$2
        if [[ -z "$username" ]]; then
            echo "Usage: $0 delete username"
            exit 1
        fi
        
        userdel -r "$username" 2>/dev/null
        rm -f "$USERS_DIR/$username.conf"
        echo "SSH user $username deleted successfully"
        ;;
    
    "list")
        echo "Active SSH users:"
        for conf in "$USERS_DIR"/*.conf; do
            if [[ -f "$conf" ]]; then
                source "$conf"
                echo "- $username (expires: $expires)"
            fi
        done
        ;;
    
    *)
        echo "Usage: $0 {add|delete|list}"
        ;;
esac
EOF

    chmod +x "$CONFIG_DIR/ssh-manager.sh"
    
    # Create monitoring script
    cat > "$CONFIG_DIR/monitor.sh" << 'EOF'
#!/bin/bash

echo "=== Maull-Script Server Status ==="
echo "Date: $(date)"
echo ""

echo "=== Service Status ==="
services=("ssh" "dropbear" "stunnel4" "nginx" "v2ray" "xray" "sing-box" "hysteria" "tuic")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "✅ $service: Running"
    else
        echo "❌ $service: Stopped"
    fi
done
echo ""

echo "=== Port Status ==="
netstat -tlnp | grep -E "(22|80|443|109|110|143|442|10000|36712)" | head -10
echo ""

echo "=== System Resources ==="
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "Memory Usage: $(free | grep Mem | awk '{printf("%.2f%%", $3/$2 * 100.0)}')"
echo "Disk Usage: $(df -h / | awk 'NR==2{printf "%s", $5}')"
echo ""

echo "=== Active Connections ==="
echo "SSH: $(netstat -tn | grep :22 | grep ESTABLISHED | wc -l)"
echo "HTTP: $(netstat -tn | grep :80 | grep ESTABLISHED | wc -l)"
echo "HTTPS: $(netstat -tn | grep :443 | grep ESTABLISHED | wc -l)"
EOF

    chmod +x "$CONFIG_DIR/monitor.sh"
    
    print_status "Management tools created successfully"
}

# Function to setup domain and SSL
setup_domain() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   ${WHITE}DOMAIN & SSL SETUP${CYAN}                     ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "Enter your domain name: " domain
    
    if [[ -z "$domain" ]]; then
        print_error "Domain name cannot be empty"
        return 1
    fi
    
    # Save domain
    echo "$domain" > "$DOMAIN_FILE"
    
    # Create nginx config for domain
    cat > "/etc/nginx/sites-available/$domain" << EOF
server {
    listen 80;
    server_name $domain;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $domain;
    
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    
    root /var/www/html;
    index index.html;
    
    # WebSocket upgrade
    location /ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # gRPC
    location /grpc {
        grpc_pass grpc://127.0.0.1:10001;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
    }
    
    # XHTTP
    location /xhttp {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

    ln -sf "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/"
    
    # Test nginx config
    nginx -t
    if [[ $? -ne 0 ]]; then
        print_error "Nginx configuration error"
        return 1
    fi
    
    systemctl reload nginx
    
    # Obtain SSL certificate
    print_status "Obtaining SSL certificate for $domain..."
    certbot --nginx -d "$domain" --non-interactive --agree-tos --email admin@"$domain"
    
    if [[ $? -eq 0 ]]; then
        print_status "SSL certificate obtained successfully"
        
        # Setup auto-renewal
        echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -
        
        return 0
    else
        print_error "Failed to obtain SSL certificate"
        return 1
    fi
}

# Function to install all services
install_all() {
    print_header
    print_status "Starting Maull-Script V1.5 installation..."
    
    check_root
    detect_os
    create_directories
    install_packages
    configure_ssh
    configure_nginx
    configure_firewall
    configure_fail2ban
    optimize_system
    create_management_tools
    
    print_status "Installation completed successfully!"
    print_status "Run 'bash maull-script.sh menu' to access the management interface"
}

# Function to handle SSH management
ssh_management() {
    while true; do
        clear
        print_header
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                 ${WHITE}SSH WS & SSL MANAGEMENT${CYAN}                  ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║ ${GREEN}1.${NC} Create SSH Account                                    ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}2.${NC} Delete SSH Account                                    ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}3.${NC} List SSH Accounts                                     ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}4.${NC} Check SSH Login                                       ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}5.${NC} SSH Configuration                                     ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${RED}0.${NC} Back to Main Menu                                     ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -ne "${WHITE}Select option [0-5]: ${NC}"
        
        read choice
        case $choice in
            1)
                echo ""
                read -p "Username: " username
                read -p "Password: " password
                read -p "Expired (days): " days
                
                "$CONFIG_DIR/ssh-manager.sh" add "$username" "$password" "$days"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                read -p "Username to delete: " username
                "$CONFIG_DIR/ssh-manager.sh" delete "$username"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                "$CONFIG_DIR/ssh-manager.sh" list
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                echo "Active SSH connections:"
                who
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                echo "SSH Configuration:"
                echo "Ports: 22, 2222"
                echo "Dropbear: 109, 110, 143"
                echo "Stunnel: 442, 443"
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Function to handle domain management
domain_management() {
    while true; do
        clear
        print_header
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                ${WHITE}DOMAIN & SSL MANAGEMENT${CYAN}                   ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║ ${GREEN}1.${NC} Setup New Domain                                      ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}2.${NC} Change Domain                                         ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}3.${NC} Renew SSL Certificate                                 ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}4.${NC} Check SSL Status                                      ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${GREEN}5.${NC} View Current Domain                                   ${CYAN}║${NC}"
        echo -e "${CYAN}║ ${RED}0.${NC} Back to Main Menu                                     ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -ne "${WHITE}Select option [0-5]: ${NC}"
        
        read choice
        case $choice in
            1|2)
                setup_domain
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                print_status "Renewing SSL certificates..."
                certbot renew
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                if [[ -f "$DOMAIN_FILE" ]]; then
                    domain=$(cat "$DOMAIN_FILE")
                    echo "Checking SSL for: $domain"
                    echo | openssl s_client -servername "$domain" -connect "$domain":443 2>/dev/null | openssl x509 -noout -dates
                else
                    echo "No domain configured"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                if [[ -f "$DOMAIN_FILE" ]]; then
                    echo "Current domain: $(cat "$DOMAIN_FILE")"
                else
                    echo "No domain configured"
                fi
                read -p "Press Enter to continue..."
                ;;
            0)
                break
                ;;
            *)
                echo "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Function to show system information
system_info() {
    clear
    print_header
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                  ${WHITE}SYSTEM INFORMATION${CYAN}                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${GREEN}Server Information:${NC}"
    echo "Hostname: $(hostname)"
    echo "OS: $(lsb_release -d | cut -f2)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Uptime: $(uptime -p)"
    echo ""
    
    echo -e "${GREEN}Network Information:${NC}"
    echo "Public IP: $(curl -s ifconfig.me)"
    echo "Private IP: $(hostname -I | awk '{print $1}')"
    if [[ -f "$DOMAIN_FILE" ]]; then
        echo "Domain: $(cat "$DOMAIN_FILE")"
    fi
    echo ""
    
    echo -e "${GREEN}System Resources:${NC}"
    echo "CPU: $(nproc) cores"
    echo "RAM: $(free -h | awk 'NR==2{printf "%s/%s (%.2f%%)", $3,$2,$3*100/$2 }')"
    echo "Disk: $(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3,$2,$5}')"
    echo ""
    
    echo -e "${GREEN}Service Status:${NC}"
    services=("ssh" "dropbear" "stunnel4" "nginx" "fail2ban" "ufw")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "✅ $service"
        else
            echo "❌ $service"
        fi
    done
    echo ""
    
    read -p "Press Enter to continue..."
}

# Main menu handler
main_menu() {
    while true; do
        show_menu
        read choice
        
        case $choice in
            1)
                ssh_management
                ;;
            2)
                echo "SSH UDP Management - Coming Soon"
                sleep 2
                ;;
            3)
                echo "SSH SlowDNS Management - Coming Soon"
                sleep 2
                ;;
            4)
                echo "SSH OpenVPN Management - Coming Soon"
                sleep 2
                ;;
            5)
                echo "ShadowSocks Management - Coming Soon"
                sleep 2
                ;;
            6)
                echo "VMess Management - Coming Soon"
                sleep 2
                ;;
            7)
                echo "VLess Management - Coming Soon"
                sleep 2
                ;;
            8)
                echo "Trojan Management - Coming Soon"
                sleep 2
                ;;
            9)
                echo "NoobzVPN Management - Coming Soon"
                sleep 2
                ;;
            10)
                domain_management
                ;;
            11)
                "$CONFIG_DIR/monitor.sh"
                read -p "Press Enter to continue..."
                ;;
            12)
                echo "Security Settings - Coming Soon"
                sleep 2
                ;;
            13)
                echo "Traffic Engineering - Coming Soon"
                sleep 2
                ;;
            14)
                echo "Backup & Restore - Coming Soon"
                sleep 2
                ;;
            15)
                system_info
                ;;
            0)
                echo ""
                echo -e "${GREEN}Thank you for using Maull-Script V1.5!${NC}"
                exit 0
                ;;
            *)
                echo "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Main execution
case "$1" in
    "install")
        install_all
        ;;
    "menu")
        if [[ ! -d "$CONFIG_DIR" ]]; then
            print_error "Maull-Script is not installed. Run: bash maull-script.sh install"
            exit 1
        fi
        main_menu
        ;;
    *)
        echo "Usage: $0 {install|menu}"
        echo "  install - Install Maull-Script"
        echo "  menu    - Show management menu"
        exit 1
        ;;
esac