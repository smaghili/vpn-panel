# Use Python 3.11 slim image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wireguard \
    openvpn \
    iptables \
    iproute2 \
    net-tools \
    redis-server \
    curl \
    wget \
    gnupg \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Create VPN panel user
RUN useradd -r -s /bin/false -d /var/lib/vpn-panel vpn-panel && \
    groupadd vpn-panel && \
    usermod -a -G vpn-panel vpn-panel

# Create necessary directories
RUN mkdir -p /var/lib/vpn-panel \
    /etc/vpn-panel \
    /var/log/vpn-panel \
    /etc/wireguard \
    /etc/openvpn \
    /var/lib/vpn-panel/backups

# Set proper permissions
RUN chown -R vpn-panel:vpn-panel /var/lib/vpn-panel \
    /etc/vpn-panel \
    /var/log/vpn-panel

# Set working directory
WORKDIR /var/lib/vpn-panel

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set proper ownership
RUN chown -R vpn-panel:vpn-panel /var/lib/vpn-panel

# Create startup script
RUN cat > /usr/local/bin/start-vpn-panel.sh << 'EOF'
#!/bin/bash
set -e

# Start Redis
redis-server --daemonize yes

# Wait for Redis to be ready
until redis-cli ping; do
    echo "Waiting for Redis..."
    sleep 1
done

# Initialize database if needed
if [ ! -f /var/lib/vpn-panel/vpn_panel.db ]; then
    echo "Initializing database..."
    python /var/lib/vpn-panel/scripts/create_proper_database.py admin admin123
fi

# Start VPN Panel
exec python -m uvicorn src.presentation.api.main:app --host 0.0.0.0 --port ${PORT:-8080}
EOF

RUN chmod +x /usr/local/bin/start-vpn-panel.sh

# Switch to non-root user
USER vpn-panel

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start the application
CMD ["/usr/local/bin/start-vpn-panel.sh"] 