#!/bin/bash

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

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed!"
        echo "Please install Docker first:"
        echo "curl -fsSL https://get.docker.com -o get-docker.sh"
        echo "sudo sh get-docker.sh"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed!"
        echo "Please install Docker Compose first:"
        echo "sudo curl -L \"https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose"
        echo "sudo chmod +x /usr/local/bin/docker-compose"
        exit 1
    fi
    
    print_success "Docker and Docker Compose are installed"
}

# Function to get user input
get_user_input() {
    echo -e "${BLUE}=== VPN Panel Docker Installation ===${NC}"
    echo ""
    
    # Get port
    read -p "Enter port for VPN Panel [8080]: " PORT
    PORT=${PORT:-8080}
    
    # Get admin username
    read -p "Enter admin username [admin]: " ADMIN_USERNAME
    ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
    
    # Get admin password
    read -s -p "Enter admin password: " ADMIN_PASSWORD
    echo ""
    
    if [ -z "$ADMIN_PASSWORD" ]; then
        print_error "Password cannot be empty!"
        exit 1
    fi
    
    # Confirm password
    read -s -p "Confirm admin password: " ADMIN_PASSWORD_CONFIRM
    echo ""
    
    if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
        print_error "Passwords do not match!"
        exit 1
    fi
    
    print_success "Configuration saved"
}

# Function to create environment file
create_env_file() {
    print_status "Creating environment file..."
    
    cat > .env << EOF
# VPN Panel Configuration
PORT=$PORT
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD

# Database
DB_PATH=/var/lib/vpn-panel/users.db

# Redis
REDIS_URL=redis://redis:6379

# Security
SECRET_KEY=$(openssl rand -hex 32)
EOF
    
    print_success "Environment file created"
}

# Function to create docker-compose override
create_compose_override() {
    print_status "Creating Docker Compose override..."
    
    cat > docker-compose.override.yml << EOF
version: '3.8'

services:
  vpn-panel:
    environment:
      - PORT=$PORT
      - ADMIN_USERNAME=$ADMIN_USERNAME
      - ADMIN_PASSWORD=$ADMIN_PASSWORD
    ports:
      - "$PORT:8080"
EOF
    
    print_success "Docker Compose override created"
}

# Function to setup directories
setup_directories() {
    print_status "Setting up directories..."
    
    mkdir -p data/vpn-panel
    mkdir -p data/redis
    mkdir -p data/prometheus
    mkdir -p data/grafana
    mkdir -p config/vpn-panel
    mkdir -p logs/vpn-panel
    
    print_success "Directories created"
}

# Function to build and start containers
build_and_start() {
    print_status "Building and starting containers..."
    
    # Build the image
    docker-compose build
    
    if [ $? -ne 0 ]; then
        print_error "Failed to build containers!"
        exit 1
    fi
    
    # Start containers
    docker-compose up -d
    
    if [ $? -ne 0 ]; then
        print_error "Failed to start containers!"
        exit 1
    fi
    
    print_success "Containers started successfully"
}

# Function to wait for services
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    # Wait for Redis
    echo "Waiting for Redis..."
    until docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; do
        sleep 2
    done
    
    # Wait for VPN Panel
    echo "Waiting for VPN Panel..."
    until curl -f http://localhost:$PORT/health > /dev/null 2>&1; do
        sleep 5
    done
    
    print_success "All services are ready"
}

# Function to create admin user
create_admin_user() {
    print_status "Creating admin user..."
    
    # Wait a bit more for the application to fully start
    sleep 10
    
    # Create admin user via API
    curl -X POST http://localhost:$PORT/api/auth/register \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"$ADMIN_USERNAME\",
            \"password\": \"$ADMIN_PASSWORD\",
            \"email\": \"admin@vpn-panel.local\",
            \"role\": \"admin\"
        }" > /dev/null 2>&1
    
    print_success "Admin user created"
}

# Function to display final information
display_final_info() {
    echo ""
    echo -e "${GREEN}=== VPN Panel Docker Installation Completed! ===${NC}"
    echo ""
    echo -e "${BLUE}Access Information:${NC}"
    echo "  URL: http://localhost:$PORT"
    echo "  Username: $ADMIN_USERNAME"
    echo "  Password: $ADMIN_PASSWORD"
    echo ""
    echo -e "${BLUE}Docker Management:${NC}"
    echo "  Start: docker-compose up -d"
    echo "  Stop: docker-compose down"
    echo "  Status: docker-compose ps"
    echo "  Logs: docker-compose logs -f vpn-panel"
    echo "  Restart: docker-compose restart"
    echo ""
    echo -e "${BLUE}Monitoring:${NC}"
    echo "  Prometheus: http://localhost:9090"
    echo "  Grafana: http://localhost:3000 (admin/admin)"
    echo ""
    echo -e "${BLUE}Data Location:${NC}"
    echo "  Application Data: ./data/vpn-panel"
    echo "  Logs: ./logs/vpn-panel"
    echo "  Config: ./config/vpn-panel"
    echo ""
    echo -e "${YELLOW}Security Notes:${NC}"
    echo "  - Change default admin password"
    echo "  - Configure firewall rules"
    echo "  - Set up SSL certificate (reverse proxy)"
    echo "  - Regular Docker image updates"
    echo ""
    echo -e "${GREEN}Installation completed successfully!${NC}"
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check available memory (at least 2GB)
    MEMORY_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEMORY_GB=$((MEMORY_KB / 1024 / 1024))
    
    if [ $MEMORY_GB -lt 2 ]; then
        print_warning "Low memory detected: ${MEMORY_GB}GB (recommended: 2GB+)"
    fi
    
    # Check available disk space (at least 5GB)
    DISK_GB=$(df . | awk 'NR==2 {print int($4/1024/1024)}')
    
    if [ $DISK_GB -lt 5 ]; then
        print_error "Insufficient disk space: ${DISK_GB}GB (required: 5GB+)"
        exit 1
    fi
    
    print_success "System requirements met"
}

# Main installation function
main() {
    echo -e "${BLUE}VPN Panel - Docker Installation${NC}"
    echo "====================================="
    echo ""
    
    # Check requirements
    check_requirements
    
    # Check Docker
    check_docker
    
    # Get user input
    get_user_input
    
    # Setup directories
    setup_directories
    
    # Create environment file
    create_env_file
    
    # Create compose override
    create_compose_override
    
    # Build and start
    build_and_start
    
    # Wait for services
    wait_for_services
    
    # Create admin user
    create_admin_user
    
    # Display final information
    display_final_info
}

# Run main function
main "$@" 