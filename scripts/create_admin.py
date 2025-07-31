#!/usr/bin/env python3
"""
Admin User Creation Script for VPN Panel
========================================

This script creates the initial admin user for the VPN Panel.
Uses the new proper database structure with separate admin and user tables.
"""
import sys
import os
import sqlite3
import bcrypt
import uuid

# Add VPN Panel source to path
sys.path.insert(0, '/var/lib/vpn-panel/src')

def create_admin_user(username, password):
    """Create admin user using new repository structure"""
    try:
        # Try to import new VPN Panel modules
        from src.infrastructure.database.admin_repository import AdminRepository
        
        print("Using VPN Panel Admin Repository...")
        
        # Initialize admin repository
        db_path = '/var/lib/vpn-panel/vpn_panel.db'
        admin_repo = AdminRepository(db_path)
        
        # Create admin user
        admin_id = admin_repo.create_admin(username, password, role='admin')
        
        if admin_id:
            print("✅ Admin user created successfully!")
            print(f"   Username: {username}")
            print(f"   ID: {admin_id}")
            return True
        else:
            print("❌ Failed to create admin user (username might already exist)")
            return False
    
    except ImportError as e:
        print(f"⚠️  VPN Panel modules not found: {e}")
        print("Using fallback method...")
        
        # Fallback: Create database and admin directly
        db_path = '/var/lib/vpn-panel/vpn_panel.db'
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create admins table with proper schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admins (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'representative')),
                    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'suspended')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT,
                    created_by TEXT,
                    FOREIGN KEY (created_by) REFERENCES admins(id)
                )
            ''')
            
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Insert admin user
            from datetime import datetime
            current_time = datetime.now().isoformat()
            
            cursor.execute('''
                INSERT INTO admins (
                    id, username, password_hash, role, status,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                username,
                password_hash,
                'admin',
                'active',
                current_time,
                current_time
            ))
            conn.commit()
            
            print("✅ Admin user created successfully with fallback method!")
            print(f"   Username: {username}")
            print("   Database: /var/lib/vpn-panel/vpn_panel.db")
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