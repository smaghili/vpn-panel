#!/bin/bash

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Update system packages
update_system() {
    print_status "Updating system packages..."
    apt update && apt upgrade -y
    print_success "System updated successfully"
}

# Install Python dependencies
install_python() {
    print_status "Installing Python and pip..."
    apt install -y python3 python3-pip python3-venv
    print_success "Python installed successfully"
}

# Install WireGuard
install_wireguard() {
    print_status "Installing WireGuard..."
    apt install -y wireguard wireguard-tools
    print_success "WireGuard installed successfully"
}

# Install OpenVPN
install_openvpn() {
    print_status "Installing OpenVPN..."
    apt install -y openvpn easy-rsa
    print_success "OpenVPN installed successfully"
}

# Install additional dependencies
install_dependencies() {
    print_status "Installing additional dependencies..."
    apt install -y wget curl git build-essential
    print_success "Dependencies installed successfully"
}

# Create VPN Panel directory
create_directories() {
    print_status "Creating VPN Panel directories..."
    mkdir -p /opt/vpn-panel
    mkdir -p /var/lib/vpn-panel
    mkdir -p /var/log/vpn-panel
    mkdir -p /etc/vpn-panel
    print_success "Directories created successfully"
}

# Copy project files
copy_project_files() {
    print_status "Copying project files..."
    cp -r . /opt/vpn-panel/
    chown -R root:root /opt/vpn-panel
    chmod -R 755 /opt/vpn-panel
    print_success "Project files copied successfully"
}

# Set up Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    cd /opt/vpn-panel
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    print_success "Python environment created successfully"
}

# Install Python requirements
install_python_requirements() {
    print_status "Installing Python requirements..."
    cd /opt/vpn-panel
    source venv/bin/activate
    pip install -r requirements.txt
    print_success "Python requirements installed successfully"
}

# Install Redis and additional dependencies
install_additional_deps() {
    print_status "Installing Redis and additional dependencies..."
    apt-get install -y redis-server python3-psutil python3-redis python3-websockets
    
    # Start and enable Redis
    systemctl enable redis-server
    systemctl start redis-server
    
    print_success "Redis and additional dependencies installed successfully"
}

# Create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    cat > /etc/systemd/system/vpn-panel.service << EOF
[Unit]
Description=VPN Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpn-panel
Environment=PATH=/opt/vpn-panel/venv/bin
Environment=DB_PATH=/var/lib/vpn-panel/vpn_panel.db
Environment=SECRET_KEY=$(openssl rand -hex 32)
ExecStart=/opt/vpn-panel/venv/bin/python -m uvicorn src.presentation.api.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    print_success "Systemd service created successfully"
}

# Enable and start service
enable_service() {
    print_status "Enabling and starting VPN Panel service..."
    systemctl daemon-reload
    systemctl enable vpn-panel
    systemctl start vpn-panel
    print_success "VPN Panel service started successfully"
}

# Create admin user
create_admin_user() {
    print_status "Creating admin user..."
    cd /opt/vpn-panel
    source venv/bin/activate
    
    # Create a Python script to initialize the database and create admin user
    cat > create_admin.py << 'EOF'
import os
import sys
sys.path.append('/opt/vpn-panel')

from src.infrastructure.database.sqlite_repository import SQLiteUserRepository
from src.domain.services.auth_service import AuthService
from src.domain.entities.user import User, UserRole, UserStatus
from datetime import datetime
import uuid

# Initialize repositories
user_repo = SQLiteUserRepository('/var/lib/vpn-panel/vpn_panel.db')
auth_service = AuthService(user_repo, os.getenv('SECRET_KEY', 'default-secret-key'))

# Check if admin user already exists
existing_admin = user_repo.find_by_username('admin')
if existing_admin:
    print('Admin user already exists')
    exit(0)

# Create admin user
admin_user = User(
    id=str(uuid.uuid4()),
    username='admin',
    email='admin@vpn-panel.com',
    password_hash=auth_service.hash_password('admin123'),
    role=UserRole.ADMIN,
    status=UserStatus.ACTIVE,
    created_at=datetime.now(),
    updated_at=datetime.now()
)

if user_repo.save(admin_user):
    print('Admin user created successfully')
    print('Username: admin')
    print('Password: admin123')
else:
    print('Failed to create admin user')
    exit(1)
EOF

    python3 create_admin.py
    rm create_admin.py
    print_success "Admin user created successfully"
}

# Configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    ufw allow 8000/tcp
    ufw allow 51820/udp  # WireGuard default port
    ufw allow 1194/udp   # OpenVPN default port
    print_success "Firewall configured successfully"
}

# Set proper permissions
set_permissions() {
    print_status "Setting proper permissions..."
    chown -R root:root /var/lib/vpn-panel
    chmod -R 700 /var/lib/vpn-panel
    chown -R root:root /var/log/vpn-panel
    chmod -R 755 /var/log/vpn-panel
    chown -R root:root /etc/vpn-panel
    chmod -R 700 /etc/vpn-panel
    print_success "Permissions set successfully"
}

# Display installation summary
show_summary() {
    print_success "VPN Panel installation completed successfully!"
    echo
    echo "Installation Summary:"
    echo "====================="
    echo "• VPN Panel installed in: /opt/vpn-panel"
    echo "• Database location: /var/lib/vpn-panel/vpn_panel.db"
    echo "• Logs location: /var/log/vpn-panel"
    echo "• Configuration: /etc/vpn-panel"
    echo "• Web interface: http://your-server-ip:8000"
    echo
    echo "Default admin credentials:"
    echo "• Username: admin"
    echo "• Password: admin123"
    echo "• Email: admin@vpn-panel.com"
    echo
    echo "Service management:"
    echo "• Start: systemctl start vpn-panel"
    echo "• Stop: systemctl stop vpn-panel"
    echo "• Status: systemctl status vpn-panel"
    echo "• Logs: journalctl -u vpn-panel -f"
    echo
    print_warning "Please change the default admin password after first login!"
}

# Main installation function
main() {
    print_status "Starting VPN Panel installation..."
    
    check_root
    update_system
    install_python
    install_wireguard
    install_openvpn
    install_dependencies
    create_directories
    copy_project_files
    setup_python_env
    install_python_requirements
    install_additional_deps
    create_systemd_service
    set_permissions
    enable_service
    create_admin_user
    configure_firewall
    show_summary
}

# Run main function
main "$@" 