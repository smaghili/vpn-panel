#!/usr/bin/env python3
"""
VPN Panel Main Application
==========================

FastAPI-based VPN management panel supporting WireGuard and OpenVPN.
"""
import sys
import os
import logging
from pathlib import Path

# Add source directory to Python path
current_dir = Path(__file__).parent
src_dir = current_dir.parent / "src"
sys.path.insert(0, str(src_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vpn-panel/app.log'),
        logging.StreamHandler()
    ]
)

def main():
    """Main application entry point"""
    try:
        # Import FastAPI app
        from src.presentation.api.main import app
        import uvicorn
        
        # Get configuration
        host = os.getenv('VPN_PANEL_HOST', '0.0.0.0')
        port = int(os.getenv('VPN_PANEL_PORT', '8000'))
        
        print(f"🚀 Starting VPN Panel on {host}:{port}")
        
        # Start server
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )
        
    except Exception as e:
        logging.error(f"Failed to start VPN Panel: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()