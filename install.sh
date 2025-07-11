#!/bin/bash

# Maull-Script V1.5 Quick Installer
# Run this script to start the installation

clear
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Maull-Script V1.5                        ║"
echo "║              Advanced VPN/Tunnel Manager                    ║"
echo "║                     Quick Installer                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root"
    echo "Please run: sudo bash install.sh"
    exit 1
fi

echo "🚀 Starting Maull-Script V1.5 installation..."
echo "This will install and configure all necessary components"
echo ""

# Download the main script if not exists
if [[ ! -f "maull-script.sh" ]]; then
    echo "📥 Downloading main script..."
    
    # Try different possible URLs
    GITHUB_USER="YOUR_GITHUB_USERNAME"  # Replace with your actual GitHub username
    REPO_NAME="maull-script"
    
    # Method 1: Try raw.githubusercontent.com
    wget -O maull-script.sh "https://raw.githubusercontent.com/${GITHUB_USER}/${REPO_NAME}/main/maull-script.sh" 2>/dev/null
    
    # Method 2: If failed, try with master branch
    if [[ ! -f "maull-script.sh" || ! -s "maull-script.sh" ]]; then
        echo "Trying master branch..."
        wget -O maull-script.sh "https://raw.githubusercontent.com/${GITHUB_USER}/${REPO_NAME}/master/maull-script.sh" 2>/dev/null
    fi
    
    # Method 3: If still failed, create the script locally
    if [[ ! -f "maull-script.sh" || ! -s "maull-script.sh" ]]; then
        echo "⚠️  Download failed. Creating script locally..."
        cat > maull-script.sh << 'SCRIPT_EOF'
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
        "openvpn" "easy-rsa" "shadowsocks-libev"
        "haproxy" "supervisor" "cron" "logrotate" "unzip" "zip"
        "python3" "python3-pip" "build-essential"
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

# Function to create directories
create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$USERS_DIR"/{ssh,vmess,vless,trojan,shadowsocks,noobz}
    mkdir -p "$CERTS_DIR"
    mkdir -p /var/log/maull-script
    
    print_status "Directories created successfully"
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

    # Restart SSH service
    systemctl restart ssh
    systemctl enable ssh
    print_status "SSH services configured successfully"
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
    
    # Enable UFW
    ufw --force enable
    
    print_status "Firewall configured successfully"
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
services=("ssh" "nginx" "fail2ban" "ufw")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "✅ $service: Running"
    else
        echo "❌ $service: Stopped"
    fi
done
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

# Function to install all services
install_all() {
    print_header
    print_status "Starting Maull-Script V1.5 installation..."
    
    check_root
    detect_os
    create_directories
    install_packages
    configure_ssh
    configure_firewall
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
        echo -e "${CYAN}║ ${RED}0.${NC} Back to Main Menu                                     ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -ne "${WHITE}Select option [0-4]: ${NC}"
        
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
    echo ""
    
    echo -e "${GREEN}System Resources:${NC}"
    echo "CPU: $(nproc) cores"
    echo "RAM: $(free -h | awk 'NR==2{printf "%s/%s (%.2f%%)", $3,$2,$3*100/$2 }')"
    echo "Disk: $(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3,$2,$5}')"
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
            2|3|4|5|6|7|8|9)
                echo "Feature coming soon in next update"
                sleep 2
                ;;
            10)
                echo "Domain & SSL Management - Coming Soon"
                sleep 2
                ;;
            11)
                "$CONFIG_DIR/monitor.sh"
                read -p "Press Enter to continue..."
                ;;
            12|13|14)
                echo "Feature coming soon in next update"
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
SCRIPT_EOF
    fi
fi

# Make the main script executable
chmod +x maull-script.sh

# Run the main installer
./maull-script.sh install

echo ""
echo "✅ Installation completed!"
echo ""
echo "📋 Next steps:"
echo "1. Run: bash maull-script.sh menu"
echo "2. Setup your domain in Domain & SSL Management"
echo "3. Create user accounts for your protocols"
echo ""
echo "📖 For help and documentation, check the README.md file"
