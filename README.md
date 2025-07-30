# VPN Panel - Enterprise Edition

A professional, extensible VPN management panel supporting multiple protocols with unified user management.

## 🚀 Features

### Core Features
- **Multi-Protocol Support**: WireGuard, OpenVPN (extensible for future protocols)
- **Unified User Management**: Single user account with multiple protocol profiles
- **Combined Bandwidth Limits**: Total usage limits across all protocols
- **Real-time Monitoring**: Live traffic monitoring and statistics
- **Professional UI**: Modern, responsive web interface

### Advanced Features
- **Protocol Breakdown**: Individual usage tracking per protocol
- **Flexible Authentication**: Certificate-only and username/password for OpenVPN
- **Bandwidth Management**: Daily and monthly limits with visual indicators
- **Configuration Export**: Download VPN configs for all protocols
- **Extensible Architecture**: Easy to add new protocols and features

### 🛡️ Enterprise Security Features

#### Security Monitoring
- **Real-time Log Monitoring**: Comprehensive security event tracking
- **Intrusion Detection System (HIDS)**: Host-based intrusion detection
- **Security Alerts**: Automated threat detection and notification
- **IP Blocking**: Automatic blocking of suspicious IP addresses
- **Security Dashboard**: Real-time security statistics and monitoring

#### Access Control & Authentication
- **Rate Limiting**: Configurable API rate limiting with IP/user-based rules
- **Secret Management**: Automatic generation and rotation of security keys
- **Non-Root Execution**: Secure execution with minimal privileges
- **Permission Management**: File and directory permission monitoring
- **Security Baseline**: System security baseline creation and verification

#### Data Protection
- **Complete Backup System**: Full, database, and config-only backups
- **Encrypted Backups**: Secure backup encryption and storage
- **Log Aggregation**: Centralized log collection and analysis
- **Audit Logging**: Comprehensive audit trail for all actions
- **Data Integrity**: File integrity monitoring and verification

#### Monitoring & Analytics
- **Real-time Monitoring**: Live system and traffic monitoring
- **Performance Analytics**: Detailed performance metrics and analysis
- **Traffic Analytics**: Comprehensive traffic analysis and reporting
- **System Health**: Continuous system health monitoring
- **Alert Management**: Configurable alert rules and notifications

#### Container Security (Docker)
- **Container Isolation**: Secure container execution
- **Health Checks**: Automated container health monitoring
- **Security Scanning**: Container vulnerability scanning
- **Resource Limits**: Container resource usage limits
- **Network Security**: Isolated container networking

## 🏗️ Architecture

### Clean Architecture
```
vpn-panel/
├── src/
│   ├── domain/           # Business logic and entities
│   │   ├── entities/     # Data models
│   │   └── services/     # Business services
│   ├── application/      # Use cases and application logic
│   ├── infrastructure/   # External interfaces
│   │   ├── database/     # Data persistence
│   │   ├── protocols/    # VPN protocol implementations
│   │   ├── monitoring/   # System monitoring
│   │   ├── security/     # Security features
│   │   └── caching/      # Performance optimization
│   └── presentation/     # Web interface
│       ├── api/          # REST API endpoints
│       └── templates/    # HTML templates
├── static/               # CSS, JS, and static assets
├── templates/            # HTML templates
└── tests/                # Unit and integration tests
```

### Key Components
- **UserProfile**: Unified user with multiple protocol profiles
- **ProtocolManager**: Extensible protocol management system
- **UnifiedUserRepository**: Database operations for unified users
- **WebSocketManager**: Real-time updates and monitoring
- **BandwidthManager**: Traffic control and limiting

## 📦 Installation

### Method 1: Direct Installation (Recommended for Production)

#### Quick Install (One-Line)
```bash
bash <(curl -Ls https://raw.githubusercontent.com/smaghili/vpn-panel/main/install.sh)
```

**Important Notes:**
- Script automatically installs all dependencies
- Asks for port, username, and admin password
- Automatically configures WireGuard and OpenVPN
- Creates systemd service
- User must configure firewall manually

#### Manual Install
```bash
# Clone the repository
git clone https://github.com/smaghili/vpn-panel.git
cd vpn-panel

# Run installation script
chmod +x install.sh
sudo ./install.sh
```

#### System Requirements (Direct Installation)
- **OS**: Ubuntu 20.04+ or Debian 11+
- **RAM**: 1GB minimum (2GB recommended)
- **Storage**: 5GB minimum
- **Root Access**: Required for installation

### Method 2: Docker Installation (Recommended for Development/Testing)

#### Quick Docker Install
```bash
bash <(curl -Ls https://raw.githubusercontent.com/smaghili/vpn-panel/main/docker-install.sh)
```

#### Manual Docker Install
```bash
# Clone the repository
git clone https://github.com/smaghili/vpn-panel.git
cd vpn-panel

# Run Docker installation
chmod +x docker-install.sh
./docker-install.sh
```

#### Docker Compose (Advanced)
```bash
# Clone the repository
git clone https://github.com/smaghili/vpn-panel.git
cd vpn-panel

# Build and start with Docker Compose
docker-compose up -d

# Access the application
# Main Panel: http://localhost:8080
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
```

#### System Requirements (Docker)
- **OS**: Any Linux with Docker support
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **RAM**: 2GB minimum (includes monitoring stack)
- **Storage**: 10GB minimum

### Installation Comparison

| Feature | Direct Install | Docker Install |
|---------|---------------|----------------|
| **Speed** | Fast (~2-3 min) | Medium (~5-10 min) |
| **Resource Usage** | Low (200MB RAM) | Medium (500MB RAM) |
| **Isolation** | ❌ | ✅ |
| **Portability** | ❌ | ✅ |
| **Monitoring Stack** | ❌ | ✅ (Prometheus/Grafana) |
| **Production Ready** | ✅ | ✅ |
| **Development** | ❌ | ✅ |
| **Easy Updates** | ❌ | ✅ |

### Post-Installation

#### Access Information
- **URL**: `http://your-server-ip:port`
- **Default Admin**: Created during installation
- **Security Dashboard**: `/security`
- **Backup Management**: `/backup`
- **Analytics**: `/analytics`

#### Service Management (Direct Install)
```bash
# Start service
sudo systemctl start vpn-panel

# Stop service
sudo systemctl stop vpn-panel

# Check status
sudo systemctl status vpn-panel

# View logs
sudo journalctl -u vpn-panel -f

# Restart service
sudo systemctl restart vpn-panel
```

#### Container Management (Docker)
```bash
# Start containers
docker-compose up -d

# Stop containers
docker-compose down

# View logs
docker-compose logs -f vpn-panel

# Restart containers
docker-compose restart

# Update containers
docker-compose pull
docker-compose up -d
```

## 🔧 Configuration

### Environment Variables
```bash
export SECRET_KEY="your-secret-key-here"
export DB_PATH="/var/lib/vpn-panel/users.db"
export REDIS_URL="redis://localhost:6379"
```

### VPN Server Configuration
1. **WireGuard**: Configure servers in `/etc/wireguard/`
2. **OpenVPN**: Configure servers in `/etc/openvpn/`
3. **Authentication**: Set up certificates and user credentials

## 📊 Usage

### Creating Users
```python
# Example: Create user with multiple protocols
user_data = {
    "username": "ali",
    "email": "ali@example.com",
    "password": "secure_password",
    "total_daily_limit_gb": 10,
    "total_monthly_limit_gb": 100,
    "protocols": {
        "wireguard": {
            "enabled": True,
            "server_id": "wg-server-1"
        },
        "openvpn": {
            "enabled": True,
            "server_id": "ovpn-server-1",
            "auth_type": "username_password",
            "username": "ali_ovpn",
            "password": "ovpn_password"
        }
    }
}
```

### API Endpoints
- `GET /api/users` - List all users
- `POST /api/users` - Create new user
- `PUT /api/users/{user_id}` - Update user
- `DELETE /api/users/{user_id}` - Delete user
- `GET /api/users/{user_id}/usage` - Get usage statistics
- `GET /api/users/{user_id}/configs` - Download VPN configs

## 🎨 UI Features

### Dashboard
- Real-time traffic monitoring
- Server status indicators
- User activity overview
- System performance metrics

### User Management
- Unified user creation with protocol selection
- Combined usage limits and individual protocol tracking
- Visual usage breakdown with progress bars
- Protocol-specific configuration management

### Analytics
- Historical traffic data
- Protocol usage analysis
- Bandwidth consumption reports
- Export capabilities

## 🔒 Security Features

- **JWT Authentication**: Secure API access
- **Password Hashing**: bcrypt for password security
- **CSRF Protection**: Cross-site request forgery prevention
- **Rate Limiting**: DDoS protection
- **Input Sanitization**: XSS prevention
- **Audit Logging**: Comprehensive activity tracking
- **Firewall Configuration**: Automatic iptables setup
- **SSH Security**: SSH port disabled by default for security
- **VPN Isolation**: Separate network namespaces for VPN protocols

## 🚀 Performance Features

- **Redis Caching**: Fast data access
- **WebSocket Updates**: Real-time notifications
- **Background Monitoring**: System health tracking
- **Optimized Queries**: Efficient database operations

## 🧪 Testing

```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run all tests with coverage
pytest --cov=src tests/
```

## 🔧 Development

### Adding New Protocols
1. Create protocol handler implementing `ProtocolHandler`
2. Add protocol type to `ProtocolType` enum
3. Register handler in `ProtocolManager`
4. Update UI components

### Database Migrations
The system uses SQLite with automatic schema creation. For production, consider PostgreSQL with Alembic migrations.

## 📈 Monitoring

### System Metrics
- CPU, Memory, Disk usage
- Network traffic statistics
- VPN connection status
- Error rates and response times

### User Analytics
- Protocol usage breakdown
- Bandwidth consumption patterns
- Connection frequency analysis
- Geographic distribution (if available)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/smaghili/vpn-panel/wiki)
- **Issues**: [GitHub Issues](https://github.com/smaghili/vpn-panel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/smaghili/vpn-panel/discussions)

## 🔧 Troubleshooting


### Service Issues
```bash
# Check service status
sudo systemctl status vpn-panel

# View logs
sudo journalctl -u vpn-panel -f

# Restart service
sudo systemctl restart vpn-panel
```

### Firewall Configuration
```bash
# Configure firewall manually
sudo ufw allow YOUR_VPN_PANEL_PORT
sudo ufw allow 51820/udp  # WireGuard
sudo ufw allow 1194/udp   # OpenVPN
sudo ufw enable
```

## 🗺️ Roadmap

- [ ] Shadowsocks protocol support
- [ ] V2Ray protocol integration
- [ ] Mobile app for user management
- [ ] Advanced analytics dashboard
- [ ] Multi-server load balancing
- [ ] API rate limiting per user
- [ ] Webhook notifications
- [ ] Backup and restore functionality

---

**Built with ❤️ for the VPN community** 