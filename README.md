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

### Quick Install (One-Line)
```bash
bash <(curl -Ls https://raw.githubusercontent.com/smaghili/vpn-panel/main/install.sh)
```

**نکات مهم:**
- اسکریپت به صورت خودکار تمام وابستگی‌ها را نصب می‌کند
- از شما پورت، نام کاربری، رمز عبور و ایمیل ادمین را می‌پرسد
- WireGuard و OpenVPN را به صورت خودکار پیکربندی می‌کند
- Firewall را برای امنیت تنظیم می‌کند
- سرویس systemd ایجاد می‌کند

### Manual Install
```bash
# Clone the repository
git clone https://github.com/smaghili/vpn-panel.git
cd vpn-panel

# Run installation script
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv wireguard openvpn easy-rsa redis-server

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Initialize database
python -c "from src.infrastructure.database.unified_user_repository import UnifiedUserRepository; UnifiedUserRepository('/var/lib/vpn-panel/users.db')"

# Start the application
python src/presentation/api/main.py
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
# بررسی وضعیت سرویس
sudo systemctl status vpn-panel

# مشاهده لاگ‌ها
sudo journalctl -u vpn-panel -f

# راه‌اندازی مجدد
sudo systemctl restart vpn-panel
```

### Firewall Issues
```bash
# بررسی قوانین iptables
sudo iptables -L -n -v

# بازنشانی firewall
sudo iptables -F
sudo iptables -X
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