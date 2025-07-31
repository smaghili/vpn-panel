#!/usr/bin/env python3
"""
VPN Panel Admin Management Tool
==============================

A comprehensive command-line tool for managing the VPN panel.
Supports admin management, user management, and system operations.
"""
import sys
import os
import argparse
from datetime import datetime, timedelta

# Add VPN Panel source to path
sys.path.insert(0, '/var/lib/vpn-panel/src')

try:
    from src.infrastructure.database.admin_repository import AdminRepository
    from src.infrastructure.database.vpn_user_repository import VPNUserRepository
except ImportError as e:
    print(f"❌ Error importing VPN Panel modules: {e}")
    print("Make sure you're running this from the correct directory")
    sys.exit(1)

class VPNPanelAdmin:
    """VPN Panel Administration Tool"""
    
    def __init__(self, db_path='/var/lib/vpn-panel/vpn_panel.db'):
        self.db_path = db_path
        self.admin_repo = AdminRepository(db_path)
        self.user_repo = VPNUserRepository(db_path)
    
    def create_admin(self, username: str, password: str, role: str = 'representative'):
        """Create new admin user"""
        print(f"👤 Creating admin: {username} (role: {role})")
        
        if len(password) < 8:
            print("❌ Password must be at least 8 characters")
            return False
        
        admin_id = self.admin_repo.create_admin(username, password, role)
        if admin_id:
            print(f"✅ Admin created successfully!")
            print(f"   ID: {admin_id}")
            print(f"   Username: {username}")
            print(f"   Role: {role}")
            return True
        else:
            print("❌ Failed to create admin (username might already exist)")
            return False
    
    def list_admins(self):
        """List all admins"""
        print("👥 Admin Users:")
        print("-" * 80)
        
        admins = self.admin_repo.list_admins()
        if not admins:
            print("No admins found")
            return
        
        for admin in admins:
            status_icon = "✅" if admin['status'] == 'active' else "❌"
            role_icon = "👑" if admin['role'] == 'admin' else "👨‍💼"
            
            print(f"{status_icon} {role_icon} {admin['username']}")
            print(f"   ID: {admin['id']}")
            print(f"   Role: {admin['role']}")
            print(f"   Status: {admin['status']}")
            print(f"   Created: {admin['created_at'][:19]}")
            if admin['last_login']:
                print(f"   Last Login: {admin['last_login'][:19]}")
            print()
    
    def create_user(self, username: str, password: str, admin_username: str, **kwargs):
        """Create VPN user"""
        # Get admin ID
        admins = self.admin_repo.list_admins()
        admin_id = None
        for admin in admins:
            if admin['username'] == admin_username:
                admin_id = admin['id']
                break
        
        if not admin_id:
            print(f"❌ Admin not found: {admin_username}")
            return False
        
        print(f"👤 Creating VPN user: {username}")
        
        if len(password) < 6:
            print("❌ Password must be at least 6 characters")
            return False
        
        user_id = self.user_repo.create_user(username, password, admin_id, **kwargs)
        if user_id:
            print(f"✅ VPN user created successfully!")
            print(f"   ID: {user_id}")
            print(f"   Username: {username}")
            print(f"   Daily Limit: {kwargs.get('daily_limit_bytes', 1024*1024*1024) // (1024*1024)} MB")
            print(f"   Monthly Limit: {kwargs.get('monthly_limit_bytes', 30*1024*1024*1024) // (1024*1024*1024)} GB")
            print(f"   Expires in: {kwargs.get('expire_days', 30)} days")
            return True
        else:
            print("❌ Failed to create VPN user (username might already exist)")
            return False
    
    def list_users(self, status=None):
        """List VPN users"""
        print("👥 VPN Users:")
        print("-" * 80)
        
        users = self.user_repo.list_users(status=status)
        if not users:
            print("No users found")
            return
        
        for user in users:
            status_icon = {
                'active': '✅',
                'inactive': '⏸️',
                'suspended': '🚫',
                'expired': '⏰'
            }.get(user['status'], '❓')
            
            print(f"{status_icon} {user['username']}")
            print(f"   ID: {user['id']}")
            print(f"   Status: {user['status']}")
            
            # Bandwidth info
            daily_used_mb = user['daily_used_bytes'] // (1024*1024)
            daily_limit_mb = user['daily_limit_bytes'] // (1024*1024)
            monthly_used_gb = user['monthly_used_bytes'] // (1024*1024*1024)
            monthly_limit_gb = user['monthly_limit_bytes'] // (1024*1024*1024)
            
            print(f"   Daily: {daily_used_mb}/{daily_limit_mb} MB")
            print(f"   Monthly: {monthly_used_gb}/{monthly_limit_gb} GB")
            
            if user['expire_date']:
                expire_dt = datetime.fromisoformat(user['expire_date'])
                days_left = (expire_dt - datetime.now()).days
                print(f"   Expires: {expire_dt.strftime('%Y-%m-%d')} ({days_left} days)")
            
            print(f"   Protocols: {', '.join(user['allowed_protocols'])}")
            print(f"   Created: {user['created_at'][:19]}")
            
            if user['last_online']:
                print(f"   Last Online: {user['last_online'][:19]}")
            
            print()
    
    def show_statistics(self):
        """Show system statistics"""
        print("📊 VPN Panel Statistics")
        print("=" * 50)
        
        # Admin stats
        admin_stats = self.admin_repo.get_admin_statistics()
        print("👥 Admin Statistics:")
        print(f"   Total Admins: {admin_stats['total_admins']}")
        print(f"   Active Admins: {admin_stats['active_admins']}")
        print(f"   Main Admins: {admin_stats['admin_count']}")
        print(f"   Representatives: {admin_stats['representative_count']}")
        print()
        
        # User stats
        user_stats = self.user_repo.get_user_statistics()
        print("🔐 User Statistics:")
        print(f"   Total Users: {user_stats['total_users']}")
        print(f"   Active Users: {user_stats['active_users']}")
        print(f"   Expired Users: {user_stats['expired_users']}")
        print(f"   Created Today: {user_stats['today_users']}")
        print()
    
    def change_admin_password(self, username: str, new_password: str):
        """Change admin password"""
        admins = self.admin_repo.list_admins()
        admin_id = None
        for admin in admins:
            if admin['username'] == username:
                admin_id = admin['id']
                break
        
        if not admin_id:
            print(f"❌ Admin not found: {username}")
            return False
        
        if len(new_password) < 8:
            print("❌ Password must be at least 8 characters")
            return False
        
        if self.admin_repo.change_admin_password(admin_id, new_password):
            print(f"✅ Password changed for admin: {username}")
            return True
        else:
            print("❌ Failed to change password")
            return False
    
    def extend_user(self, username: str, days: int):
        """Extend user expiry"""
        users = self.user_repo.list_users()
        user_id = None
        for user in users:
            if user['username'] == username:
                user_id = user['id']
                break
        
        if not user_id:
            print(f"❌ User not found: {username}")
            return False
        
        if self.user_repo.extend_user_expiry(user_id, days):
            print(f"✅ Extended user {username} by {days} days")
            return True
        else:
            print("❌ Failed to extend user")
            return False
    
    def suspend_user(self, username: str):
        """Suspend user"""
        users = self.user_repo.list_users()
        user_id = None
        for user in users:
            if user['username'] == username:
                user_id = user['id']
                break
        
        if not user_id:
            print(f"❌ User not found: {username}")
            return False
        
        if self.user_repo.update_user_status(user_id, 'suspended'):
            print(f"✅ User suspended: {username}")
            return True
        else:
            print("❌ Failed to suspend user")
            return False
    
    def activate_user(self, username: str):
        """Activate user"""
        users = self.user_repo.list_users()
        user_id = None
        for user in users:
            if user['username'] == username:
                user_id = user['id']
                break
        
        if not user_id:
            print(f"❌ User not found: {username}")
            return False
        
        if self.user_repo.update_user_status(user_id, 'active'):
            print(f"✅ User activated: {username}")
            return True
        else:
            print("❌ Failed to activate user")
            return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='VPN Panel Admin Management Tool')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Admin commands
    admin_parser = subparsers.add_parser('admin', help='Admin management')
    admin_subparsers = admin_parser.add_subparsers(dest='admin_action')
    
    # Create admin
    create_admin_parser = admin_subparsers.add_parser('create', help='Create admin')
    create_admin_parser.add_argument('username', help='Admin username')
    create_admin_parser.add_argument('password', help='Admin password')
    create_admin_parser.add_argument('--role', choices=['admin', 'representative'], 
                                   default='representative', help='Admin role')
    
    # List admins
    admin_subparsers.add_parser('list', help='List admins')
    
    # Change admin password
    change_pass_parser = admin_subparsers.add_parser('passwd', help='Change admin password')
    change_pass_parser.add_argument('username', help='Admin username')
    change_pass_parser.add_argument('password', help='New password')
    
    # User commands
    user_parser = subparsers.add_parser('user', help='User management')
    user_subparsers = user_parser.add_subparsers(dest='user_action')
    
    # Create user
    create_user_parser = user_subparsers.add_parser('create', help='Create VPN user')
    create_user_parser.add_argument('username', help='User username')
    create_user_parser.add_argument('password', help='User password')
    create_user_parser.add_argument('admin', help='Admin username who creates this user')
    create_user_parser.add_argument('--daily-limit', type=int, default=1024,
                                   help='Daily limit in MB (default: 1024)')
    create_user_parser.add_argument('--monthly-limit', type=int, default=30,
                                   help='Monthly limit in GB (default: 30)')
    create_user_parser.add_argument('--expire-days', type=int, default=30,
                                   help='Expiry in days (default: 30)')
    create_user_parser.add_argument('--protocols', default='openvpn,wireguard',
                                   help='Allowed protocols (default: openvpn,wireguard)')
    
    # List users
    list_users_parser = user_subparsers.add_parser('list', help='List VPN users')
    list_users_parser.add_argument('--status', choices=['active', 'inactive', 'suspended', 'expired'],
                                  help='Filter by status')
    
    # Extend user
    extend_parser = user_subparsers.add_parser('extend', help='Extend user expiry')
    extend_parser.add_argument('username', help='User username')
    extend_parser.add_argument('days', type=int, help='Days to extend')
    
    # Suspend user
    suspend_parser = user_subparsers.add_parser('suspend', help='Suspend user')
    suspend_parser.add_argument('username', help='User username')
    
    # Activate user
    activate_parser = user_subparsers.add_parser('activate', help='Activate user')
    activate_parser.add_argument('username', help='User username')
    
    # Statistics
    subparsers.add_parser('stats', help='Show statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    admin_tool = VPNPanelAdmin()
    
    try:
        if args.command == 'admin':
            if args.admin_action == 'create':
                admin_tool.create_admin(args.username, args.password, args.role)
            elif args.admin_action == 'list':
                admin_tool.list_admins()
            elif args.admin_action == 'passwd':
                admin_tool.change_admin_password(args.username, args.password)
            else:
                admin_parser.print_help()
        
        elif args.command == 'user':
            if args.user_action == 'create':
                admin_tool.create_user(
                    args.username, args.password, args.admin,
                    daily_limit_bytes=args.daily_limit * 1024 * 1024,
                    monthly_limit_bytes=args.monthly_limit * 1024 * 1024 * 1024,
                    expire_days=args.expire_days,
                    allowed_protocols=args.protocols
                )
            elif args.user_action == 'list':
                admin_tool.list_users(status=args.status)
            elif args.user_action == 'extend':
                admin_tool.extend_user(args.username, args.days)
            elif args.user_action == 'suspend':
                admin_tool.suspend_user(args.username)
            elif args.user_action == 'activate':
                admin_tool.activate_user(args.username)
            else:
                user_parser.print_help()
        
        elif args.command == 'stats':
            admin_tool.show_statistics()
    
    except KeyboardInterrupt:
        print("\n👋 Exiting...")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()