#!/usr/bin/env python3
"""
Admin User Creation Script for VPN Panel
========================================

This script creates the initial admin user for the VPN Panel.
It supports both full VPN Panel modules and fallback SQLite method.
"""
import sys
import os
import sqlite3
import bcrypt
import uuid

# Add VPN Panel source to path
sys.path.insert(0, '/var/lib/vpn-panel/src')

def create_admin_user(username, password):
    """Create admin user with fallback method"""
    try:
        # Try to import VPN Panel modules
        from src.infrastructure.database.unified_user_repository import UnifiedUserRepository
        from src.domain.services.auth_service import AuthService
        from src.domain.entities.user_profile import UserProfile, ProtocolType
        
        print("Using VPN Panel modules...")
        
        # Initialize repository and auth service
        repo = UnifiedUserRepository('/var/lib/vpn-panel/users.db')
        auth_service = AuthService()
        
        # Create admin user profile
        admin_user = UserProfile(
            user_id=str(uuid.uuid4()),
            username=username,
            email='admin@vpn-panel.local',
            password_hash=auth_service.hash_password(password),
            role='admin',
            status='active'
        )
        
        # Save admin user
        if repo.save_user(admin_user):
            print("✅ Admin user created successfully!")
            print(f"   Username: {username}")
            return True
        else:
            print("❌ Failed to create admin user with VPN Panel modules")
            return False
    
    except ImportError as e:
        print(f"⚠️  VPN Panel modules not found: {e}")
        print("Using fallback SQLite method...")
        
        # Fallback: Create admin user directly with SQLite
        db_path = '/var/lib/vpn-panel/users.db'
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create users table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Insert admin user
            cursor.execute('''
                INSERT INTO users (id, username, email, password_hash, role, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                username,
                'admin@vpn-panel.local',
                password_hash,
                'admin',
                'active'
            ))
            conn.commit()
            
            print("✅ Admin user created successfully with fallback method!")
            print(f"   Username: {username}")
            return True
            
        except sqlite3.IntegrityError:
            print("⚠️  Admin user already exists")
            return True
        except Exception as e:
            print(f"❌ Failed to create admin user: {e}")
            return False
        finally:
            if 'conn' in locals():
                conn.close()

def main():
    """Main function"""
    if len(sys.argv) != 3:
        print("Usage: python3 create_admin.py <username> <password>")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    
    if not username or not password:
        print("❌ Username and password are required")
        sys.exit(1)
    
    if len(password) < 8:
        print("❌ Password must be at least 8 characters")
        sys.exit(1)
    
    success = create_admin_user(username, password)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()