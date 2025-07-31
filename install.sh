#!/bin/bash

# VPN Panel - Enterprise Edition Installer
# One-line installer: bash <(curl -Ls https://raw.githubusercontent.com/smaghili/vpn-panel/main/install.sh)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# ===== UTILITY FUNCTIONS =====
# Generate secure random password
generate_random_password() {
    local length=${1:-12}
    # Use multiple sources for better randomness
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 $((length * 3/4 + 1)) | tr -d "=+/" | cut -c1-$length
    elif [ -f /dev/urandom ]; then
        tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c $length
    else
        # Fallback method
        date +%s | sha256sum | base64 | head -c $length
    fi
}

# Validate password strength
validate_password() {
    local password="$1"
    local min_length=8
    
    if [ ${#password} -lt $min_length ]; then
        return 1
    fi
    return 0
}

# Function to check existing installation
check_existing_installation() {
    if [ -d "/var/lib/vpn-panel" ] || [ -f "/etc/systemd/system/vpn-panel.service" ] || systemctl is-active --quiet redis-server 2>/dev/null; then
        echo -n -e "${YELLOW}⚠️  VPN Panel is already installed! Would you like to completely remove all settings and reinstall? [Y/n]: ${NC}"
        read REINSTALL
        REINSTALL=${REINSTALL:-Y}
        
        if [[ $REINSTALL =~ ^[Yy]$ ]]; then
            print_status "Removing existing installation..."
            
            # Stop services
            systemctl stop vpn-panel 2>/dev/null || true
            systemctl stop redis-server 2>/dev/null || true
            systemctl disable vpn-panel 2>/dev/null || true
            
            # Remove directories
            rm -rf /var/lib/vpn-panel
            rm -rf /etc/vpn-panel
            rm -rf /var/log/vpn-panel
            rm -f /etc/systemd/system/vpn-panel.service
            
            # Remove Redis data
            rm -rf /var/lib/redis
            
            # Clean firewall rules
            ufw delete allow 8000 2>/dev/null || true
            ufw delete allow 1194 2>/dev/null || true
            ufw delete allow 51820 2>/dev/null || true
            
            systemctl daemon-reload
            print_success "Previous installation removed"
            echo ""
        else
            print_error "Installation cancelled"
            exit 0
        fi
    fi
}

# Function to get user input with auto mode
get_user_input() {
    echo -n -e "${BLUE}🚀 Do you want to install with auto mode? [Y/n]: ${NC}"
    read AUTO_MODE
    AUTO_MODE=${AUTO_MODE:-Y}
    
    if [[ $AUTO_MODE =~ ^[Yy]$ ]]; then
        # AUTO MODE - Generate everything
        print_status "Using auto mode - generating secure defaults..."
        
        ADMIN_USERNAME="admin"
        ADMIN_PASSWORD=$(generate_random_password 16)
        PORT="8000"
        OPENVPN_PORT="1194"
        OPENVPN_PROTOCOL="tcp"
        WIREGUARD_PORT="51820"
        
        print_success "Auto-generated configuration created"
        
    else
        # MANUAL MODE - Ask user for everything
        print_status "Using manual mode - please configure settings..."
        echo ""
        
        # Get admin username
        while true; do
            read -p "Admin username [admin]: " ADMIN_USERNAME
            ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
            if [[ $ADMIN_USERNAME =~ ^[a-zA-Z0-9_]+$ ]] && [ ${#ADMIN_USERNAME} -ge 3 ]; then
                break
            else
                print_error "Username must be at least 3 characters (letters, numbers, underscore only)"
            fi
        done
        
        # Get admin password
        while true; do
            echo ""
            echo "Admin password (leave empty for auto-generation):"
            read -p "Password: " ADMIN_PASSWORD
            
            if [ -z "$ADMIN_PASSWORD" ]; then
                ADMIN_PASSWORD=$(generate_random_password 16)
                print_success "Generated password: $ADMIN_PASSWORD"
                break
            elif validate_password "$ADMIN_PASSWORD"; then
                break
            else
                print_error "Password must be at least 8 characters"
            fi
        done
        
        # Get panel port
        while true; do
            read -p "VPN Panel port [8000]: " PORT
            PORT=${PORT:-8000}
            if [[ $PORT =~ ^[0-9]+$ ]] && [ $PORT -ge 1024 ] && [ $PORT -le 65535 ]; then
                break
            else
                print_error "Port must be between 1024-65535"
            fi
        done
        
        # Get OpenVPN port
        while true; do
            read -p "OpenVPN port [1194]: " OPENVPN_PORT
            OPENVPN_PORT=${OPENVPN_PORT:-1194}
            if [[ $OPENVPN_PORT =~ ^[0-9]+$ ]] && [ $OPENVPN_PORT -ge 1024 ] && [ $OPENVPN_PORT -le 65535 ]; then
                break
            else
                print_error "Port must be between 1024-65535"
            fi
        done
        
        # Get OpenVPN protocol
        echo ""
        echo "OpenVPN Protocol:"
        echo "  1) TCP (recommended - reliable)"
        echo "  2) UDP (faster but less reliable)"
        read -p "Choose protocol [1]: " PROTO_CHOICE
        PROTO_CHOICE=${PROTO_CHOICE:-1}
        
        if [ "$PROTO_CHOICE" = "2" ]; then
            OPENVPN_PROTOCOL="udp"
        else
            OPENVPN_PROTOCOL="tcp"
        fi
        
        # Get WireGuard port
        while true; do
            read -p "WireGuard port [51820]: " WIREGUARD_PORT
            WIREGUARD_PORT=${WIREGUARD_PORT:-51820}
            if [[ $WIREGUARD_PORT =~ ^[0-9]+$ ]] && [ $WIREGUARD_PORT -ge 1024 ] && [ $WIREGUARD_PORT -le 65535 ]; then
                break
            else
                print_error "Port must be between 1024-65535"
            fi
        done
        
        echo ""
        print_success "Configuration complete!"
    fi
    
    print_status "Starting installation..."
}

# ===== SILENT SYSTEM UPDATE =====
update_system() {
    print_status "Updating system packages..."
    apt-get update >/dev/null 2>&1
    apt-get upgrade -y >/dev/null 2>&1
    print_success "System updated successfully"
}

# ===== SILENT PACKAGE INSTALLATION =====
install_system_deps() {
    print_status "Installing system dependencies..."
    
    # Silent installation function
    silent_install() {
        local packages=("$@")
        for package in "${packages[@]}"; do
            if ! dpkg -l | grep -q "^ii.*$package "; then
                apt-get install -y "$package" >/dev/null 2>&1
            fi
        done
    }
    
    # Essential packages
    silent_install curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release
    
    # Python and development tools
    silent_install python3 python3-pip python3-venv python3-dev build-essential
    
    # VPN protocols
    silent_install wireguard wireguard-tools openvpn easy-rsa
    
    # Database and caching
    silent_install sqlite3 redis-server
    
    # System monitoring
    silent_install htop iotop nethogs iftop
    
    # Network tools
    silent_install net-tools iproute2
    
    # Additional Python packages
    silent_install python3-psutil python3-redis python3-websockets python3-cryptography
    
    print_success "System dependencies installed successfully"
}

# Function to create directories
create_directories() {
    print_status "Creating application directories..."
    
    mkdir -p /var/lib/vpn-panel
    mkdir -p /var/log/vpn-panel
    mkdir -p /etc/vpn-panel
    mkdir -p /etc/vpn-panel/ssl
    mkdir -p /etc/vpn-panel/certs
    mkdir -p /etc/vpn-panel/configs
    
    # Set permissions
    chown -R root:root /var/lib/vpn-panel
    chown -R root:root /var/log/vpn-panel
    chown -R root:root /etc/vpn-panel
    chmod 755 /var/lib/vpn-panel
    chmod 755 /var/log/vpn-panel
    chmod 700 /etc/vpn-panel
    
    print_success "Directories created successfully"
}

# ===== SILENT PYTHON ENVIRONMENT =====
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    cd /var/lib/vpn-panel
    
    # Create virtual environment silently
    python3 -m venv venv >/dev/null 2>&1
    source venv/bin/activate
    
    # Silent pip installation function
    silent_pip_install() {
        local packages=("$@")
        for package in "${packages[@]}"; do
            if ! pip show "${package%\[*\]}" >/dev/null 2>&1; then
                pip install --quiet --disable-pip-version-check "$package" >/dev/null 2>&1
            fi
        done
    }
    
    # Upgrade pip silently
    pip install --quiet --disable-pip-version-check --upgrade pip setuptools wheel >/dev/null 2>&1
    
    # Install Python dependencies silently
    silent_pip_install fastapi uvicorn jinja2 python-multipart
    silent_pip_install bcrypt pydantic "python-jose[cryptography]" PyJWT
    silent_pip_install redis psutil websockets
    silent_pip_install cryptography pycryptodome
    silent_pip_install pytest pytest-asyncio httpx
    silent_pip_install structlog python-json-logger
    
    print_success "Python environment setup completed"
}

# Function to setup WireGuard
setup_wireguard() {
    print_status "Setting up WireGuard..."
    
    # Enable IP forwarding (check if not already set)
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
    
    # Create WireGuard directory
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
    
    # Generate server keys
    cd /etc/wireguard
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key
    chmod 600 server_public.key
    
    # Create basic WireGuard config
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat server_private.key)
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
SaveConfig = true
EOF
    
    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    print_success "WireGuard setup completed"
}

# ===== OPENVPN SETUP FUNCTION =====
# Complete OpenVPN installation based on angristan/openvpn-install
setup_openvpn() {
    print_status "Setting up OpenVPN with professional configuration..."
    
    # ===== CLEANUP EXISTING INSTALLATION =====
    print_status "Cleaning up any existing OpenVPN installation..."
    
    # Stop existing OpenVPN services
    systemctl stop openvpn@server 2>/dev/null || true
    systemctl stop openvpn-server@server 2>/dev/null || true
    systemctl disable openvpn@server 2>/dev/null || true
    systemctl disable openvpn-server@server 2>/dev/null || true
    
    # Remove existing OpenVPN configuration and files
    rm -rf /etc/openvpn/*
    rm -rf /var/log/openvpn
    rm -f /etc/systemd/system/openvpn@.service
    rm -f /etc/systemd/system/openvpn-server@.service
    
    # ===== DETECT SYSTEM CONFIGURATION =====
    # Find out if the machine uses nogroup or nobody for the permissionless group
    if grep -qs "^nogroup:" /etc/group; then
        NOGROUP=nogroup
    else
        NOGROUP=nobody
    fi
    
    # Get the "public" interface from the default route
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    if [[ -z $NIC ]]; then
        NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
    fi
    
    # Detect public IP
    PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s api.ipify.org 2>/dev/null || echo "")
    
    # ===== INSTALL EASY-RSA FROM SOURCE =====
    print_status "Installing Easy-RSA from source..."
    
    # Download and install Easy-RSA
    local version="3.1.2"
    wget -O /tmp/easy-rsa.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz"
    mkdir -p /etc/openvpn/easy-rsa
    tar xzf /tmp/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
    rm -f /tmp/easy-rsa.tgz
    
    # ===== CONFIGURE EASY-RSA =====
    cd /etc/openvpn/easy-rsa/
    
    # Configure for ECDSA certificates (modern and fast)
    cat > vars << EOF
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE prime256v1
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 3650
set_var EASYRSA_CRL_DAYS 3650
set_var EASYRSA_BATCH 1
EOF
    
    # ===== GENERATE CERTIFICATES =====
    print_status "Generating certificates and keys..."
    
    # Generate random server name
    SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
    SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
    
    # Save server name for client generation
    echo "$SERVER_CN" > SERVER_CN_GENERATED
    echo "$SERVER_NAME" > SERVER_NAME_GENERATED
    
    # Initialize PKI and create CA
    ./easyrsa init-pki >/dev/null 2>&1
    EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass >/dev/null 2>&1
    
    # Generate server certificate and key
    EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass >/dev/null 2>&1
    
    # Generate CRL (Certificate Revocation List)
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl >/dev/null 2>&1
    
    # Generate tls-crypt key
    openvpn --genkey secret tls-crypt.key
    
    # ===== COPY CERTIFICATES =====
    print_status "Installing certificates..."
    
    # Copy certificates to OpenVPN directory
    cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" pki/crl.pem tls-crypt.key /etc/openvpn/
    
    # Set proper permissions
    chmod 644 /etc/openvpn/crl.pem
    chmod 600 /etc/openvpn/tls-crypt.key
    chmod 600 /etc/openvpn/pki/private/* 2>/dev/null || true
    
    # ===== CREATE SERVER CONFIGURATION =====
    print_status "Creating server configuration..."
    
    cat > /etc/openvpn/server.conf << EOF
# OpenVPN Server Configuration
# Generated by VPN Panel Installer

# Network settings
port $OPENVPN_PORT
proto $OPENVPN_PROTOCOL
dev tun

# Security settings
user nobody
group $NOGROUP
persist-key
persist-tun

# Connection settings
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# DNS and routing
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"

# Modern encryption (ECDSA + AES-128-GCM)
dh none
ecdh-curve prime256v1
tls-crypt tls-crypt.key
crl-verify crl.pem

# Certificates
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key

# Cipher settings
auth SHA256
cipher AES-128-GCM
ncp-ciphers AES-128-GCM
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256

# Management
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3
explicit-exit-notify 1
EOF
    
    # ===== CREATE DIRECTORIES =====
    mkdir -p /etc/openvpn/ccd
    mkdir -p /var/log/openvpn
    
    # ===== CREATE CLIENT TEMPLATE =====
    print_status "Creating client template..."
    
    cat > /etc/openvpn/client-template.txt << EOF
client
remote ${PUBLIC_IP:-localhost} $OPENVPN_PORT
proto $OPENVPN_PROTOCOL
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns
verb 3
explicit-exit-notify
EOF
    
    # ===== SETUP IPTABLES RULES =====
    print_status "Configuring firewall rules..."
    
    # Create iptables rules directory
    mkdir -p /etc/iptables
    
    # Script to add OpenVPN rules
    cat > /etc/iptables/add-openvpn-rules.sh << EOF
#!/bin/bash
# Add OpenVPN iptables rules
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $OPENVPN_PROTOCOL --dport $OPENVPN_PORT -j ACCEPT
EOF
    
    # Script to remove OpenVPN rules
    cat > /etc/iptables/rm-openvpn-rules.sh << EOF
#!/bin/bash
# Remove OpenVPN iptables rules
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE 2>/dev/null || true
iptables -D INPUT -i tun0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i $NIC -p $OPENVPN_PROTOCOL --dport $OPENVPN_PORT -j ACCEPT 2>/dev/null || true
EOF
    
    chmod +x /etc/iptables/add-openvpn-rules.sh
    chmod +x /etc/iptables/rm-openvpn-rules.sh
    
    # ===== CREATE SYSTEMD SERVICE FOR IPTABLES =====
    cat > /etc/systemd/system/iptables-openvpn.service << EOF
[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # ===== ENABLE IP FORWARDING =====
    print_status "Enabling IP forwarding..."
    
    # Only create OpenVPN sysctl config if not already configured
    if [ ! -f /etc/sysctl.d/99-openvpn.conf ]; then
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn.conf
    fi
    # Apply only OpenVPN specific settings silently
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    
    # ===== START SERVICES =====
    print_status "Starting OpenVPN services..."
    
    # Reload systemd and start services silently
    systemctl daemon-reload >/dev/null 2>&1
    
    # Enable and start iptables rules silently
    systemctl enable iptables-openvpn >/dev/null 2>&1
    systemctl start iptables-openvpn >/dev/null 2>&1
    
    # Enable and start OpenVPN silently
    systemctl enable openvpn@server >/dev/null 2>&1
    systemctl start openvpn@server >/dev/null 2>&1
    
    # Wait a moment for service to start
    sleep 3
    
    # Check if OpenVPN started successfully
    if systemctl is-active --quiet openvpn@server; then
        print_success "OpenVPN setup completed successfully!"
        print_status "OpenVPN is running on port $OPENVPN_PORT ($OPENVPN_PROTOCOL)"
        print_status "Server certificate: $SERVER_NAME"
        print_status "Encryption: AES-128-GCM with ECDSA certificates"
    else
        print_error "OpenVPN failed to start. Checking logs..."
        journalctl -u openvpn@server --no-pager -l
        exit 1
    fi
}

# Function to setup security
setup_security() {
    print_status "Setting up security features..."
    
    # Create vpn-panel user and group
    useradd -r -s /bin/false -d /var/lib/vpn-panel vpn-panel 2>/dev/null || true
    groupadd vpn-panel 2>/dev/null || true
    usermod -a -G vpn-panel vpn-panel 2>/dev/null || true
    
    # Set proper permissions
    chown -R vpn-panel:vpn-panel /var/lib/vpn-panel
    chown -R vpn-panel:vpn-panel /etc/vpn-panel
    chown -R vpn-panel:vpn-panel /var/log/vpn-panel
    
    # Set restrictive permissions
    chmod 750 /var/lib/vpn-panel
    chmod 750 /etc/vpn-panel
    chmod 750 /var/log/vpn-panel
    chmod 600 /var/lib/vpn-panel/users.db 2>/dev/null || true
    chmod 600 /etc/vpn-panel/secrets.json 2>/dev/null || true
    
    # Setup capabilities for network operations
    setcap cap_net_admin+ep /sbin/ip 2>/dev/null || true
    setcap cap_net_admin+ep /sbin/iptables 2>/dev/null || true
    setcap cap_net_bind_service+ep /var/lib/vpn-panel/venv/bin/python 2>/dev/null || true
    
    # Create sudo rules for specific commands
    cat > /etc/sudoers.d/vpn-panel << EOF
vpn-panel ALL=(ALL) NOPASSWD: /sbin/iptables
vpn-panel ALL=(ALL) NOPASSWD: /sbin/ip
vpn-panel ALL=(ALL) NOPASSWD: /bin/systemctl restart wg-quick@*
vpn-panel ALL=(ALL) NOPASSWD: /bin/systemctl restart openvpn@*
vpn-panel ALL=(ALL) NOPASSWD: /bin/systemctl status wg-quick@*
vpn-panel ALL=(ALL) NOPASSWD: /bin/systemctl status openvpn@*
EOF
    chmod 440 /etc/sudoers.d/vpn-panel
    
    print_success "Security setup completed"
}

# Function to create VPN Panel application
create_vpn_panel_app() {
    print_status "Creating VPN Panel application..."
    
    cd /var/lib/vpn-panel
    
    # Download complete source code from GitHub
    print_status "Downloading VPN Panel source code..."
    
    # Download the complete source code
    wget -q -O vpn-panel-source.zip "https://github.com/smaghili/vpn-panel/archive/main.zip"
    unzip -q vpn-panel-source.zip
    
    # Copy source files
    if [ -d "vpn-panel-main/src" ]; then
        cp -r vpn-panel-main/src ./
        cp -r vpn-panel-main/static ./ 2>/dev/null || mkdir -p static/{css,js}
        cp -r vpn-panel-main/templates ./ 2>/dev/null || mkdir -p templates
        cp -r vpn-panel-main/tests ./ 2>/dev/null || mkdir -p tests/{unit,integration}
        cp vpn-panel-main/requirements.txt ./ 2>/dev/null || true
        cp vpn-panel-main/pytest.ini ./ 2>/dev/null || true
        print_success "Source code downloaded successfully"
    else
        print_warning "GitHub source not found - creating minimal structure"
        # Fallback: create basic structure
        mkdir -p src/{domain/{entities,repositories,services},application/{use_cases,dto},infrastructure/{database,protocols,monitoring,security,caching,analytics,traffic},presentation/{api,templates}}
        mkdir -p static/{css,js}
        mkdir -p templates  
        mkdir -p tests/{unit,integration}
    fi
    
    # Copy script files if available (before cleanup)
    if [ -f "vpn-panel-main/scripts/main.py" ]; then
        cp vpn-panel-main/scripts/main.py main.py
        print_success "Main application script copied from source"
    else
        # Fallback: create minimal main.py
        cat > main.py << 'EOF'
#!/usr/bin/env python3
import sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from src.presentation.api.main import app
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
except ImportError as e:
    print(f"VPN Panel modules not found: {e}")
    sys.exit(1)
EOF
        print_warning "Created fallback main.py"
    fi
    
    # Copy admin user creation script if available
    if [ -f "vpn-panel-main/scripts/create_admin.py" ]; then
        cp vpn-panel-main/scripts/create_admin.py create_admin.py
        print_success "Admin user script copied from source"
    else
        # Fallback: create minimal create_admin.py
        cat > create_admin.py << 'EOF'
#!/usr/bin/env python3
import sys, sqlite3, bcrypt, uuid
if len(sys.argv) != 3:
    print("Usage: python3 create_admin.py <username> <password>")
    sys.exit(1)

username, password = sys.argv[1], sys.argv[2]
conn = sqlite3.connect('/var/lib/vpn-panel/users.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE, email TEXT,
    password_hash TEXT, role TEXT DEFAULT 'user', status TEXT DEFAULT 'active'
)''')
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
try:
    cursor.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)',
                  (str(uuid.uuid4()), username, 'admin@vpn-panel.local',
                   password_hash, 'admin', 'active'))
    conn.commit()
    print("✅ Admin user created successfully!")
except sqlite3.IntegrityError:
    print("⚠️  Admin user already exists")
conn.close()
EOF
        print_warning "Created fallback create_admin.py"
    fi
    
    # Cleanup after copying all files
    rm -f vpn-panel-source.zip
    rm -rf vpn-panel-main
    
    # Create systemd service
    cat > /etc/systemd/system/vpn-panel.service << EOF
[Unit]
Description=VPN Panel Enterprise Edition
After=network.target

[Service]
Type=exec
User=vpn-panel
Group=vpn-panel
WorkingDirectory=/var/lib/vpn-panel
Environment=PATH=/var/lib/vpn-panel/venv/bin
Environment=PYTHONPATH=/var/lib/vpn-panel/src
Environment=DB_PATH=/var/lib/vpn-panel/vpn_panel.db
Environment=REDIS_URL=redis://localhost:6379
Environment=PORT=$PORT
ExecStart=/var/lib/vpn-panel/venv/bin/python main.py
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vpn-panel /etc/vpn-panel /var/log/vpn-panel

[Install]
WantedBy=multi-user.target
EOF
    
    # Make scripts executable
    chmod +x main.py
    chmod +x create_admin.py
    
    # Install owpanel management tool
    if [ -f "scripts/owpanel.py" ]; then
        chmod +x scripts/owpanel.py
        ln -sf /var/lib/vpn-panel/scripts/owpanel.py /usr/local/bin/owpanel
        
        # Create bash completion for owpanel
        cat > /etc/bash_completion.d/owpanel << 'EOF'
# Bash completion for owpanel
_owpanel_completion() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Available commands
    local commands="status logs restart start stop help"
    
    if [[ ${COMP_CWORD} == 1 ]]; then
        COMPREPLY=($(compgen -W "${commands}" -- ${cur}))
    fi
}

# Register completion for both owpanel and owp
complete -F _owpanel_completion owpanel
complete -F _owpanel_completion owp
EOF
        
        # Create short alias 'owp' for owpanel
        ln -sf /var/lib/vpn-panel/scripts/owpanel.py /usr/local/bin/owp
        
        print_success "OWPanel management tool installed (owpanel or owp)"
    fi
    
    print_success "VPN Panel application created successfully"
}



# ===== START SERVICES =====
start_services() {
    print_status "Starting services..."
    
    # Setup Redis
    systemctl stop redis-server 2>/dev/null || true
    pkill redis-server 2>/dev/null || true
    rm -rf /var/lib/redis/* 2>/dev/null || true
    
    if netstat -tuln | grep -q ":6379 "; then
        fuser -k 6379/tcp 2>/dev/null || true
        sleep 1
    fi
    if [ -f /etc/redis/redis.conf ]; then
        # Backup original config
        cp /etc/redis/redis.conf /etc/redis/redis.conf.backup
        
        # Create clean minimal config
        cat > /etc/redis/redis.conf << EOF
# Redis VPN Panel Configuration
bind 127.0.0.1
port 6379
timeout 0
tcp-keepalive 300
daemonize yes
supervised systemd
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
maxmemory 128mb
maxmemory-policy allkeys-lru
EOF
    fi
    
    # Ensure proper ownership and permissions
    chown redis:redis /var/lib/redis
    chown redis:redis /var/log/redis
    chmod 750 /var/lib/redis
    chmod 750 /var/log/redis
    
    # Try to start Redis
    print_status "Starting Redis server..."
    systemctl daemon-reload
    
    # Start Redis
    if systemctl enable redis-server >/dev/null 2>&1 && systemctl start redis-server >/dev/null 2>&1; then
        sleep 2
        if redis-cli ping >/dev/null 2>&1; then
            print_success "Redis started successfully"
        else
            print_warning "Redis issue - continuing without cache"
        fi
    else
        print_warning "Redis could not start - continuing without cache"
    fi
    
    # Start VPN Panel
    print_status "Starting VPN Panel..."
    systemctl daemon-reload
    systemctl enable vpn-panel >/dev/null 2>&1
    systemctl start vpn-panel >/dev/null 2>&1
    
    # Wait for service to be ready
    sleep 3
    
    # Check if VPN Panel is running
    if systemctl is-active --quiet vpn-panel; then
        print_success "VPN Panel started successfully"
        return 0
    else
        print_error "VPN Panel failed to start"
        print_status "Checking logs..."
        journalctl -u vpn-panel --no-pager -n 5
        return 1
    fi
}

# Function to create admin user
create_admin_user() {
    print_status "Creating admin user..."
    
    cd /var/lib/vpn-panel
    source venv/bin/activate
    
    # Try to use new database structure script first
    if [ -f "scripts/create_proper_database.py" ]; then
        python scripts/create_proper_database.py "$ADMIN_USERNAME" "$ADMIN_PASSWORD" >/dev/null 2>&1 && \
        print_success "Database and admin user created with new structure" && return 0
    fi
    
    # Fallback to old method
    python create_admin.py "$ADMIN_USERNAME" "$ADMIN_PASSWORD" >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Admin user created successfully"
    else
        print_error "Failed to create admin user"
        return 1
    fi
}

# ===== INSTALLATION COMPLETION & SUMMARY =====
# Display final installation summary with credentials
display_final_info() {
    # Final service status check
    print_status "Verifying installation..."
    
    # Check if panel is accessible
    sleep 2
    if curl -s --connect-timeout 5 "http://localhost:$PORT" >/dev/null 2>&1; then
        print_success "VPN Panel is running and accessible!"
    else
        print_warning "Panel might need a moment to start - checking service..."
        if systemctl is-active --quiet vpn-panel; then
            print_success "Service is running - panel should be accessible soon"
        else
            print_error "Service is not running - check logs"
            return 1
        fi
    fi
    
    echo ""
    echo "=================================================================="
    echo "🎉            VPN PANEL - INSTALLATION COMPLETE            🎉"
    echo "=================================================================="
    echo ""
    echo "📋 SYSTEM INFORMATION:"
    echo "   • Panel URL: http://$(curl -s ifconfig.me):$PORT"
    echo "   • Panel Port: $PORT"
    echo "   • WireGuard Port: $WIREGUARD_PORT (udp)"
    echo "   • OpenVPN Port: $OPENVPN_PORT ($OPENVPN_PROTOCOL)"
    echo ""
    echo "🔐 ADMIN CREDENTIALS:"
    echo "   • Username: $ADMIN_USERNAME"
    echo "   • Password: $ADMIN_PASSWORD"
    echo ""
    echo "⚠️  IMPORTANT: Save these credentials securely!"
    echo ""
    echo "🚀 NEXT STEPS:"
    echo "   1. Open browser and go to: http://$(curl -s ifconfig.me):$PORT"
    echo "   2. Login with the credentials above"
    echo "   3. Start creating VPN users and servers"

    echo ""
    echo "📁 FILES LOCATION:"
    echo "   • Application: /var/lib/vpn-panel"
    echo "   • Logs: /var/log/vpn-panel"
    echo "   • Config: /etc/vpn-panel"
    echo "   • Credentials: /root/vpn-panel-credentials.txt"
    echo ""
    echo "📚 DOCUMENTATION:"
    echo "   • GitHub: https://github.com/smaghili/vpn-panel"
    echo "   • Support: Create an issue on GitHub"
    echo ""
    echo "=================================================================="
    
    # Save credentials to file for reference
    cat > /root/vpn-panel-credentials.txt << EOF
VPN Panel Installation - $(date)
================================

Panel URL: http://$(curl -s ifconfig.me):$PORT
Admin Username: $ADMIN_USERNAME
Admin Password: $ADMIN_PASSWORD
Panel Port: $PORT
WireGuard Port: $WIREGUARD_PORT (udp)
OpenVPN Port: $OPENVPN_PORT ($OPENVPN_PROTOCOL)

Installation Date: $(date)
Server IP: $(curl -s ifconfig.me)
EOF
    
    chmod 600 /root/vpn-panel-credentials.txt
    echo "💾 Credentials saved to: /root/vpn-panel-credentials.txt"
    echo ""
    
    print_success "Installation completed! Panel is ready to use."
}

# Main installation function
main() {
    echo -e "${BLUE}VPN Panel - Enterprise Edition Installer${NC}"
    echo "================================================"
    echo ""
    
    # Check if running as root
    check_root
    
    # Check existing installation
    check_existing_installation
    
    # Get user input
    get_user_input
    
    # Run installation steps
    update_system
    install_system_deps
    create_directories
    setup_python_env
    setup_wireguard
    setup_openvpn
    setup_security
    create_vpn_panel_app
    
    # Start services and check success
    if start_services; then
        # Create admin user
        if create_admin_user; then
            # Only display final info if everything succeeded
            display_final_info
        else
            print_error "Admin user creation failed - check logs"
            exit 1
        fi
    else
        print_error "VPN Panel failed to start - check logs"
        print_status "Try: sudo journalctl -u vpn-panel -f"
        exit 1
    fi
}

# Run main function
main "$@" 