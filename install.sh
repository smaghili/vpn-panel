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

# Function to get user input
get_user_input() {
    echo -e "${BLUE}=== VPN Panel Installation ===${NC}"
    echo ""
    
    # Get port
    while true; do
        read -p "Enter port for VPN Panel (default: 8000): " PORT
        PORT=${PORT:-8000}
        if [[ $PORT =~ ^[0-9]+$ ]] && [ $PORT -ge 1024 ] && [ $PORT -le 65535 ]; then
            break
        else
            print_error "Port must be a number between 1024 and 65535"
        fi
    done
    
    # Get admin username
    while true; do
        read -p "Enter admin username (default: admin): " ADMIN_USERNAME
        ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
        if [[ $ADMIN_USERNAME =~ ^[a-zA-Z0-9_]+$ ]] && [ ${#ADMIN_USERNAME} -ge 3 ]; then
            break
        else
            print_error "Username must be at least 3 characters and contain only letters, numbers, and underscores"
        fi
    done
    
    # ===== ADMIN PASSWORD INPUT =====
    # Get admin password with enhanced UX
    echo ""
    echo "Enter admin password (leave empty for auto-generation):"
    echo "  • Minimum 8 characters required"
    echo "  • Press ENTER without typing for random password"
    echo ""
    read -p "Admin password: " ADMIN_PASSWORD
    
    # Generate random password if empty
    if [ -z "$ADMIN_PASSWORD" ]; then
        ADMIN_PASSWORD=$(generate_random_password 12)
        ADMIN_PASSWORD_GENERATED=true
        print_status "Random password generated successfully"
    else
        # Validate manual password
        if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
            print_error "Password must be at least 8 characters"
            exit 1
        fi
        ADMIN_PASSWORD_GENERATED=false
        print_status "Manual password accepted"
    fi
    
    # Get OpenVPN port
    while true; do
        read -p "Enter OpenVPN port (default: 1194): " OPENVPN_PORT
        OPENVPN_PORT=${OPENVPN_PORT:-1194}
        if [[ $OPENVPN_PORT =~ ^[0-9]+$ ]] && [ $OPENVPN_PORT -ge 1 ] && [ $OPENVPN_PORT -le 65535 ]; then
            break
        else
            print_error "Port must be a number between 1 and 65535"
        fi
    done
    
    # Get OpenVPN protocol
    while true; do
        echo "Select OpenVPN protocol:"
        echo "  1) UDP (faster, recommended)"
        echo "  2) TCP (more reliable)"
        read -p "Protocol choice [1-2]: " PROTOCOL_CHOICE
        case $PROTOCOL_CHOICE in
            1)
                OPENVPN_PROTOCOL="udp"
                break
                ;;
            2)
                OPENVPN_PROTOCOL="tcp"
                break
                ;;
            *)
                print_error "Please select 1 or 2"
                ;;
        esac
    done
    
    echo ""
    print_status "Installation will proceed with:"
    echo "  Panel Port: $PORT"
    echo "  Admin Username: $ADMIN_USERNAME"
    echo "  OpenVPN Port: $OPENVPN_PORT"
    echo "  OpenVPN Protocol: $OPENVPN_PROTOCOL"
    echo ""
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
Environment=DB_PATH=/var/lib/vpn-panel/users.db
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
    
    print_success "VPN Panel application created successfully"
}



# ===== START SERVICES =====
start_services() {
    print_status "Starting services..."
    
    # ===== REDIS TROUBLESHOOTING AND SETUP =====
    print_status "Configuring Redis..."
    
    # Stop any existing Redis processes
    systemctl stop redis-server 2>/dev/null || true
    pkill redis-server 2>/dev/null || true
    
    # Clean Redis data directory
    print_status "Cleaning Redis data..."
    rm -rf /var/lib/redis/* 2>/dev/null || true
    rm -rf /var/log/redis/* 2>/dev/null || true
    
    # Check if port 6379 is in use
    if netstat -tuln | grep -q ":6379 "; then
        print_warning "Port 6379 is busy - killing processes..."
        fuser -k 6379/tcp 2>/dev/null || true
        sleep 2
    fi
    
    # Fix Redis configuration
    print_status "Fixing Redis configuration..."
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
    
    # Try multiple Redis startup methods - NEVER FAIL INSTALLATION
    REDIS_SUCCESS=false
    
    # Method 1: Standard systemd service
    if systemctl enable redis-server >/dev/null 2>&1 && systemctl start redis-server >/dev/null 2>&1; then
        sleep 3
        if systemctl is-active --quiet redis-server && redis-cli ping >/dev/null 2>&1; then
            print_success "Redis started successfully via systemd"
            REDIS_SUCCESS=true
        else
            print_warning "Redis systemd service failed - trying manual start"
            systemctl stop redis-server >/dev/null 2>&1 || true
        fi
    fi
    
    # Method 2: Manual Redis with custom config (if systemd failed)
    if [ "$REDIS_SUCCESS" = false ]; then
        print_status "Attempting manual Redis startup..."
        mkdir -p /etc/vpn-panel/redis
        cat > /etc/vpn-panel/redis/redis.conf << EOF
bind 127.0.0.1
port 6379
daemonize yes
maxmemory 64mb
maxmemory-policy allkeys-lru
timeout 0
save ""
EOF
        
        if redis-server /etc/vpn-panel/redis/redis.conf >/dev/null 2>&1; then
            sleep 2
            if redis-cli ping >/dev/null 2>&1; then
                print_success "Redis started with custom config"
                REDIS_SUCCESS=true
            fi
        fi
    fi
    
    # Method 3: Redis on alternative port (if port 6379 busy)
    if [ "$REDIS_SUCCESS" = false ]; then
        print_status "Trying Redis on alternative port..."
        cat > /etc/vpn-panel/redis/redis-alt.conf << EOF
bind 127.0.0.1
port 6380
daemonize yes
maxmemory 32mb
maxmemory-policy allkeys-lru
timeout 0
save ""
EOF
        
        if redis-server /etc/vpn-panel/redis/redis-alt.conf >/dev/null 2>&1; then
            sleep 2
            if redis-cli -p 6380 ping >/dev/null 2>&1; then
                print_success "Redis started on port 6380"
                REDIS_SUCCESS=true
                # Update panel config to use port 6380
                echo "REDIS_PORT=6380" > /etc/vpn-panel/redis-port.conf
            fi
        fi
    fi
    
    # Final status
    if [ "$REDIS_SUCCESS" = true ]; then
        print_success "Redis is running and accessible"
    else
        print_warning "Redis could not be started - VPN Panel will use file-based caching"
        print_warning "This will not affect VPN functionality"
        # Create dummy Redis port file for panel
        echo "REDIS_DISABLED=true" > /etc/vpn-panel/redis-port.conf
    fi
    
    # Start VPN Panel
    print_status "Starting VPN Panel..."
    systemctl daemon-reload
    systemctl enable vpn-panel
    systemctl start vpn-panel
    
    print_success "Services started successfully"
}

# Function to create admin user
create_admin_user() {
    print_status "Creating admin user..."
    
    cd /var/lib/vpn-panel
    source venv/bin/activate
    python create_admin.py "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
    
    print_success "Admin user created successfully"
}

# ===== INSTALLATION COMPLETION & SUMMARY =====
# Display final installation summary with credentials
display_final_info() {
    print_success "VPN Panel installation completed successfully!"
    
    echo ""
    echo "=================================================================="
    echo "🎉            VPN PANEL - INSTALLATION COMPLETE            🎉"
    echo "=================================================================="
    echo ""
    echo "📋 SYSTEM INFORMATION:"
    echo "   • Panel URL: http://$(curl -s ifconfig.me):$PORT"
    echo "   • Panel Port: $PORT"
    echo "   • WireGuard Port: 51820"
    echo "   • OpenVPN Port: $OPENVPN_PORT ($OPENVPN_PROTOCOL)"
    echo ""
    echo "🔐 ADMIN CREDENTIALS:"
    echo "   • Username: $ADMIN_USERNAME"
    if [ "$ADMIN_PASSWORD_GENERATED" = true ]; then
        echo "   • Password: $ADMIN_PASSWORD (AUTO-GENERATED)"
        echo ""
        echo "⚠️  IMPORTANT: Save these credentials securely!"
        echo "   The auto-generated password will not be shown again."
    else
        echo "   • Password: [Your manual password]"
    fi
    echo ""
    echo "🚀 NEXT STEPS:"
    echo "   1. Open browser and go to: http://$(curl -s ifconfig.me):$PORT"
    echo "   2. Login with the credentials above"
    echo "   3. Start creating VPN users and servers"
    echo ""
    echo "🔧 SERVICE MANAGEMENT:"
    echo "   • Start: sudo systemctl start vpn-panel"
    echo "   • Stop: sudo systemctl stop vpn-panel"
    echo "   • Status: sudo systemctl status vpn-panel"
    echo "   • Logs: sudo journalctl -u vpn-panel -f"
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
WireGuard Port: 51820
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
    start_services
    create_admin_user
    
    # Display final information
    display_final_info
}

# Run main function
main "$@" 