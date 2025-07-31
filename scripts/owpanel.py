#!/usr/bin/env python3
"""
OWPanel - VPN Panel Management Tool
===================================

Command-line tool for monitoring and managing VPN Panel services.
"""
import subprocess
import sys
import os
import time
from pathlib import Path

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
NC = '\033[0m'  # No Color

def run_command(command, quiet=True):
    """Run shell command and return output"""
    try:
        if quiet:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
        else:
            result = subprocess.run(command, shell=True)
            return result.returncode == 0, "", ""
    except Exception as e:
        return False, "", str(e)

def check_service_status(service_name):
    """Check if a systemd service is running"""
    success, output, _ = run_command(f"systemctl is-active {service_name}")
    return "Running" if success and output == "active" else "Stopped"

def check_service_enabled(service_name):
    """Check if a systemd service is enabled for auto-start"""
    success, output, _ = run_command(f"systemctl is-enabled {service_name}")
    return "Yes" if success and output == "enabled" else "No"

def check_process_running(process_name):
    """Check if a process is running"""
    success, output, _ = run_command(f"pgrep -f {process_name}")
    return "Running" if success and output else "Stopped"

def check_port_listening(port):
    """Check if a port is listening"""
    success, output, _ = run_command(f"netstat -tuln | grep ':{port} '")
    return "Running" if success and output else "Stopped"

def get_panel_url():
    """Get panel URL"""
    try:
        # Try to get external IP
        success, ip, _ = run_command("curl -s --connect-timeout 3 ifconfig.me")
        if not success or not ip:
            ip = "localhost"
        
        # Get port from service file
        success, output, _ = run_command("grep 'Environment=PORT=' /etc/systemd/system/vpn-panel.service")
        if success and "PORT=" in output:
            port = output.split("PORT=")[1].strip()
        else:
            port = "8000"
        
        return f"http://{ip}:{port}"
    except:
        return "http://localhost:8000"

def show_status():
    """Show complete system status"""
    print(f"\n{BLUE}📊 VPN Panel System Status{NC}")
    print("=" * 50)
    
    success, _, _ = run_command(f"curl -s --connect-timeout 3 localhost:8000")
    panel_status = "Running" if success else "Not Responding"
    panel_color = GREEN if success else RED
    
    panel_enabled = check_service_enabled("vpn-panel")
    auto_color = GREEN if panel_enabled == "Yes" else YELLOW
    
    print(f"Panel State: {panel_color}{panel_status}{NC}")
    print(f"Start automatically: {auto_color}{panel_enabled}{NC}")
    
    # Service Status
    print(f"\n{BLUE}🔧 Services Status{NC}")
    print("-" * 30)
    
    # WireGuard
    wg_status = check_process_running("wg")
    wg_port_status = check_port_listening("51820")
    wg_color = GREEN if wg_status == "Running" or wg_port_status == "Running" else RED
    wg_final = "Running" if (wg_status == "Running" or wg_port_status == "Running") else "Stopped"
    print(f"WireGuard: {wg_color}{wg_final}{NC}")
    
    # OpenVPN
    ovpn_status = check_service_status("openvpn")
    ovpn_process = check_process_running("openvpn")
    ovpn_port_status = check_port_listening("1194")
    ovpn_color = GREEN if any([ovpn_status == "Running", ovpn_process == "Running", ovpn_port_status == "Running"]) else RED
    ovpn_final = "Running" if any([ovpn_status == "Running", ovpn_process == "Running", ovpn_port_status == "Running"]) else "Stopped"
    print(f"OpenVPN: {ovpn_color}{ovpn_final}{NC}")
    
    # Redis
    redis_status = check_service_status("redis-server")
    redis_process = check_process_running("redis-server")
    redis_port_status = check_port_listening("6379")
    redis_color = GREEN if any([redis_status == "Running", redis_process == "Running", redis_port_status == "Running"]) else YELLOW
    redis_final = "Running" if any([redis_status == "Running", redis_process == "Running", redis_port_status == "Running"]) else "Stopped"
    print(f"Redis: {redis_color}{redis_final}{NC}")
    
    # Panel URL
    panel_url = get_panel_url()
    print(f"\n{BLUE}🌐 Access Information{NC}")
    print("-" * 30)
    print(f"Panel URL: {BLUE}{panel_url}{NC}")
    
    # Quick health check
    print(f"\n{BLUE}🔍 Quick Health Check{NC}")
    print("-" * 30)
    
    # Check database
    db_exists = os.path.exists("/var/lib/vpn-panel/vpn_panel.db")
    db_color = GREEN if db_exists else RED
    db_status = "Available" if db_exists else "Missing"
    print(f"Database: {db_color}{db_status}{NC}")
    
    print()

def show_logs():
    """Show recent logs"""
    print(f"\n{BLUE}📋 Recent Panel Logs{NC}")
    print("=" * 50)
    run_command("journalctl -u vpn-panel --no-pager -n 10", quiet=False)

def restart_panel():
    """Restart VPN Panel"""
    print(f"{YELLOW}🔄 Restarting VPN Panel...{NC}")
    
    success, _, _ = run_command("systemctl restart vpn-panel")
    if success:
        print(f"{GREEN}✅ VPN Panel restarted successfully{NC}")
        time.sleep(2)
        show_status()
    else:
        print(f"{RED}❌ Failed to restart VPN Panel{NC}")
        show_logs()

def stop_panel():
    """Stop VPN Panel"""
    print(f"{YELLOW}⏹️  Stopping VPN Panel...{NC}")
    
    success, _, _ = run_command("systemctl stop vpn-panel")
    if success:
        print(f"{GREEN}✅ VPN Panel stopped successfully{NC}")
    else:
        print(f"{RED}❌ Failed to stop VPN Panel{NC}")

def start_panel():
    """Start VPN Panel"""
    print(f"{YELLOW}▶️  Starting VPN Panel...{NC}")
    
    success, _, _ = run_command("systemctl start vpn-panel")
    if success:
        print(f"{GREEN}✅ VPN Panel started successfully{NC}")
        time.sleep(2)
        show_status()
    else:
        print(f"{RED}❌ Failed to start VPN Panel{NC}")
        show_logs()

def show_help():
    """Show help information"""
    print(f"\n{BLUE}🔧 OWPanel - VPN Panel Management Tool{NC}")
    print("=" * 50)
    print("Usage: owpanel [command]")
    print("\nCommands:")
    print("  status    Show system status (default)")
    print("  logs      Show recent logs")
    print("  restart   Restart VPN Panel service")
    print("  start     Start VPN Panel service")
    print("  stop      Stop VPN Panel service")
    print("  help      Show this help message")
    print(f"\nExamples:")
    print("  owpanel           # Show status")
    print("  owpanel status    # Show status")
    print("  owpanel logs      # Show logs")
    print("  owpanel restart   # Restart service")
    print()

def main():
    """Main function"""
    # Check if running as root for service commands
    if len(sys.argv) > 1 and sys.argv[1] in ['restart', 'start', 'stop'] and os.geteuid() != 0:
        print(f"{RED}❌ Root privileges required for service management{NC}")
        print(f"Try: sudo owpanel {sys.argv[1]}")
        sys.exit(1)
    
    # Parse command
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    
    if command == "status":
        show_status()
    elif command == "logs":
        show_logs()
    elif command == "restart":
        restart_panel()
    elif command == "start":
        start_panel()
    elif command == "stop":
        stop_panel()
    elif command == "help" or command == "--help" or command == "-h":
        show_help()
    else:
        print(f"{RED}❌ Unknown command: {command}{NC}")
        show_help()
        sys.exit(1)

if __name__ == "__main__":
    main()