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
    
    # Get admin password
    while true; do
        read -s -p "Enter admin password (min 8 characters): " ADMIN_PASSWORD
        echo ""
        if [ ${#ADMIN_PASSWORD} -ge 8 ]; then
            read -s -p "Confirm admin password: " ADMIN_PASSWORD_CONFIRM
            echo ""
            if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
                break
            else
                print_error "Passwords do not match"
            fi
        else
            print_error "Password must be at least 8 characters"
        fi
    done
    

    
    echo ""
    print_status "Installation will proceed with:"
    echo "  Port: $PORT"
    echo "  Admin Username: $ADMIN_USERNAME"
    echo ""
    
    read -p "Continue with installation? (y/N): " CONFIRM
    if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
        print_warning "Installation cancelled"
        exit 0
    fi
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    apt-get update
    apt-get upgrade -y
    print_success "System updated successfully"
}

# Function to install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    # Essential packages
    apt-get install -y curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release
    
    # Python and development tools
    apt-get install -y python3 python3-pip python3-venv python3-dev build-essential
    
    # VPN protocols
    apt-get install -y wireguard wireguard-tools openvpn easy-rsa
    
    # Database and caching
    apt-get install -y sqlite3 redis-server
    
    # System monitoring
    apt-get install -y htop iotop nethogs iftop
    
    # Network tools
    apt-get install -y net-tools iproute2
    

    

    
    # Additional Python packages
    apt-get install -y python3-psutil python3-redis python3-websockets python3-cryptography
    
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

# Function to setup Python environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    cd /var/lib/vpn-panel
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    
    # Install Python dependencies
    print_status "Installing Python dependencies..."
    pip install fastapi uvicorn jinja2 python-multipart
    pip install bcrypt pydantic python-jose[cryptography]
    pip install redis psutil websockets
    pip install cryptography pycryptodome
    pip install pytest pytest-asyncio httpx
    pip install structlog python-json-logger
    
    print_success "Python environment setup completed"
}

# Function to setup WireGuard
setup_wireguard() {
    print_status "Setting up WireGuard..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    sysctl -p
    
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

# Function to setup OpenVPN
setup_openvpn() {
    print_status "Setting up OpenVPN..."
    
    # Setup Easy-RSA
    cd /etc/openvpn
    make-cadir easy-rsa
    cd easy-rsa
    
    # Initialize PKI
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    
    # Generate server certificate
    ./easyrsa build-server-full server nopass
    
    # Generate Diffie-Hellman parameters
    ./easyrsa gen-dh
    
    # Generate TLS auth key
    openvpn --genkey secret ta.key
    
    # Create server config
    cat > /etc/openvpn/server.conf << EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
EOF
    
    # Enable and start OpenVPN
    systemctl enable openvpn@server
    systemctl start openvpn@server
    
    print_success "OpenVPN setup completed"
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
    
    # Create application structure
    mkdir -p src/{domain/{entities,repositories,services},application/{use_cases,dto},infrastructure/{database,protocols,monitoring,security,caching,analytics,traffic},presentation/{api,templates}}
    mkdir -p static/{css,js}
    mkdir -p templates
    mkdir -p tests/{unit,integration}
    
    # Create main application file
    cat > main.py << 'EOF'
#!/usr/bin/env python3
"""
VPN Panel - Enterprise Edition
Main application entry point
"""

import os
import sys
import asyncio
import uvicorn
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.presentation.api.main import app
from src.infrastructure.monitoring.background_monitor import background_monitor

async def main():
    """Main application function"""
    # Start background monitoring
    await background_monitor.start_monitoring()
    
    # Get configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    
    # Start server
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
EOF
    
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
    
    # Create admin user script
    cat > create_admin.py << EOF
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '/var/lib/vpn-panel/src')

from src.infrastructure.database.unified_user_repository import UnifiedUserRepository
from src.domain.services.auth_service import AuthService
from src.domain.entities.user_profile import UserProfile, ProtocolType
import uuid

def create_admin_user():
    """Create admin user"""
    # Initialize repository and auth service
    repo = UnifiedUserRepository('/var/lib/vpn-panel/users.db')
    auth_service = AuthService()
    
    # Create admin user profile
    admin_user = UserProfile(
        user_id=str(uuid.uuid4()),
        username='$ADMIN_USERNAME',
        email='admin@vpn-panel.local',
        password_hash=auth_service.hash_password('$ADMIN_PASSWORD'),
        role='admin',
        status='active'
    )
    
    # Save admin user
    if repo.save_user(admin_user):
        print("Admin user created successfully!")
        print(f"Username: $ADMIN_USERNAME")
        print(f"Password: $ADMIN_PASSWORD")
    else:
        print("Failed to create admin user")

if __name__ == "__main__":
    create_admin_user()
EOF
    
    # Make scripts executable
    chmod +x main.py
    chmod +x create_admin.py
    
    print_success "VPN Panel application created successfully"
}



# Function to start services
start_services() {
    print_status "Starting services..."
    
    # Start Redis
    systemctl enable redis-server
    systemctl start redis-server
    
    # Start VPN Panel
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
    python create_admin.py
    
    print_success "Admin user created successfully"
}

# Function to display final information
display_final_info() {
    echo ""
    echo -e "${GREEN}=== VPN Panel Installation Completed! ===${NC}"
    echo ""
    echo -e "${BLUE}Access Information:${NC}"
    echo "  URL: http://$(curl -s ifconfig.me):$PORT"
    echo "  Username: $ADMIN_USERNAME"
    echo "  Password: $ADMIN_PASSWORD"
    echo ""
    echo -e "${BLUE}Service Management:${NC}"
    echo "  Start: sudo systemctl start vpn-panel"
    echo "  Stop: sudo systemctl stop vpn-panel"
    echo "  Status: sudo systemctl status vpn-panel"
    echo "  Logs: sudo journalctl -u vpn-panel -f"
    echo ""
    echo -e "${BLUE}Files Location:${NC}"
    echo "  Application: /var/lib/vpn-panel"
    echo "  Logs: /var/log/vpn-panel"
    echo "  Config: /etc/vpn-panel"
    echo ""
    echo -e "${YELLOW}Security Notes:${NC}"
    echo "  - Change default admin password"
    echo "  - Configure firewall rules"
    echo "  - Set up SSL certificate"
    echo "  - Regular system updates"
    echo ""
    echo -e "${GREEN}Installation completed successfully!${NC}"
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