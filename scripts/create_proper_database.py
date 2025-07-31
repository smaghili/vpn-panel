#!/usr/bin/env python3
"""
Proper Database Schema Creation for VPN Panel
=============================================

This script creates the correct database structure with separate tables
for admins and users, following the business requirements.
"""
import sqlite3
import bcrypt
import uuid
from datetime import datetime
import sys
import os

def create_database_schema(db_path='/var/lib/vpn-panel/vpn_panel.db'):
    """Create proper database schema with separate admin and user tables"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🗃️ Creating proper database schema...")
        
        # ===== ADMINS TABLE =====
        # For system administrators and representatives
        cursor.execute("""
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
        """)
        
        # ===== USERS TABLE =====
        # For VPN clients/customers
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'suspended', 'expired')),
                
                -- Bandwidth Limits and Usage
                daily_limit_bytes INTEGER DEFAULT 0,
                monthly_limit_bytes INTEGER DEFAULT 0,
                daily_used_bytes INTEGER DEFAULT 0,
                monthly_used_bytes INTEGER DEFAULT 0,
                total_used_bytes INTEGER DEFAULT 0,
                
                -- Connection Info
                last_online TEXT,
                expire_date TEXT,
                
                -- Protocol Access (flexible for future protocols)
                allowed_protocols TEXT NOT NULL DEFAULT 'openvpn,wireguard',
                
                -- Management Info
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by TEXT,
                
                FOREIGN KEY (created_by) REFERENCES admins(id)
            )
        """)
        
        # ===== USER PROTOCOL CONFIGS TABLE =====
        # Store protocol-specific configurations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_protocol_configs (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                protocol_type TEXT NOT NULL CHECK(protocol_type IN ('openvpn', 'wireguard')),
                config_data TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, protocol_type)
            )
        """)
        
        # ===== BANDWIDTH USAGE LOGS TABLE =====
        # Track daily usage for reset purposes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bandwidth_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                date TEXT NOT NULL,
                bytes_used INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, date)
            )
        """)
        
        # ===== CONNECTION LOGS TABLE =====
        # Track user connections for monitoring
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS connection_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                protocol_type TEXT NOT NULL,
                connected_at TEXT NOT NULL,
                disconnected_at TEXT,
                bytes_transferred INTEGER DEFAULT 0,
                client_ip TEXT,
                server_ip TEXT,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # ===== CREATE INDEXES =====
        print("📊 Creating database indexes...")
        
        # Admin indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admins_role ON admins(role)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admins_status ON admins(status)")
        
        # User indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_expire_date ON users(expire_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_created_by ON users(created_by)")
        
        # Protocol config indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_protocol_configs_user_id ON user_protocol_configs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_protocol_configs_type ON user_protocol_configs(protocol_type)")
        
        # Bandwidth log indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bandwidth_logs_user_date ON bandwidth_logs(user_id, date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bandwidth_logs_date ON bandwidth_logs(date)")
        
        # Connection log indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_connection_logs_user_id ON connection_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_connection_logs_connected_at ON connection_logs(connected_at)")
        
        conn.commit()
        print("✅ Database schema created successfully!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating database schema: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def create_initial_admin(db_path='/var/lib/vpn-panel/vpn_panel.db', username='admin', password='admin123'):
    """Create initial admin user"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print(f"👤 Creating initial admin user: {username}")
        
        # Check if admin already exists
        cursor.execute("SELECT id FROM admins WHERE username = ?", (username,))
        if cursor.fetchone():
            print("⚠️  Admin user already exists!")
            return True
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create admin
        current_time = datetime.now().isoformat()
        admin_id = str(uuid.uuid4())
        
        cursor.execute("""
            INSERT INTO admins (
                id, username, password_hash, role, status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            admin_id,
            username,
            password_hash,
            'admin',
            'active',
            current_time,
            current_time
        ))
        
        conn.commit()
        print("✅ Initial admin created successfully!")
        print(f"   Username: {username}")
        print(f"   Password: {password}")
        print(f"   Role: admin")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating admin: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def create_sample_user(db_path='/var/lib/vpn-panel/vpn_panel.db', admin_id=None):
    """Create a sample user for testing"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get admin ID if not provided
        if not admin_id:
            cursor.execute("SELECT id FROM admins WHERE role = 'admin' LIMIT 1")
            result = cursor.fetchone()
            if result:
                admin_id = result[0]
        
        print("👥 Creating sample user...")
        
        # Check if user already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", ('testuser',))
        if cursor.fetchone():
            print("⚠️  Sample user already exists!")
            return True
        
        # Hash password
        password_hash = bcrypt.hashpw('test123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user
        current_time = datetime.now().isoformat()
        user_id = str(uuid.uuid4())
        
        # Expire date: 30 days from now
        from datetime import timedelta
        expire_date = (datetime.now() + timedelta(days=30)).isoformat()
        
        cursor.execute("""
            INSERT INTO users (
                id, username, password_hash, status,
                daily_limit_bytes, monthly_limit_bytes,
                daily_used_bytes, monthly_used_bytes, total_used_bytes,
                expire_date, allowed_protocols,
                created_at, updated_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            'testuser',
            password_hash,
            'active',
            1024*1024*1024,      # 1GB daily limit
            30*1024*1024*1024,   # 30GB monthly limit
            0,                   # daily used
            0,                   # monthly used
            0,                   # total used
            expire_date,
            'openvpn,wireguard', # allowed protocols
            current_time,
            current_time,
            admin_id
        ))
        
        conn.commit()
        print("✅ Sample user created successfully!")
        print(f"   Username: testuser")
        print(f"   Password: test123")
        print(f"   Daily Limit: 1GB")
        print(f"   Monthly Limit: 30GB")
        print(f"   Expire Date: {expire_date[:10]}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating sample user: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def verify_database(db_path='/var/lib/vpn-panel/vpn_panel.db'):
    """Verify database structure"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 Verifying database structure...")
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = ['admins', 'users', 'user_protocol_configs', 'bandwidth_logs', 'connection_logs']
        
        print(f"📋 Tables found: {tables}")
        
        for table in expected_tables:
            if table not in tables:
                print(f"❌ Missing table: {table}")
                return False
        
        # Check admin count
        cursor.execute("SELECT COUNT(*) FROM admins")
        admin_count = cursor.fetchone()[0]
        
        # Check user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        print(f"✅ Database verification successful!")
        print(f"   📊 Admins: {admin_count}")
        print(f"   👥 Users: {user_count}")
        
        return True
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def main():
    """Main function"""
    print("🚀 VPN Panel Database Setup")
    print("=" * 50)
    
    db_path = '/var/lib/vpn-panel/vpn_panel.db'
    
    # Get admin credentials
    if len(sys.argv) >= 3:
        admin_username = sys.argv[1]
        admin_password = sys.argv[2]
    else:
        admin_username = 'admin'
        admin_password = 'admin123'
        print(f"ℹ️  Using default admin credentials: {admin_username}/{admin_password}")
    
    # Create database directory if needed
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    # Step 1: Create schema
    if not create_database_schema(db_path):
        print("❌ Failed to create database schema!")
        sys.exit(1)
    
    # Step 2: Create initial admin
    if not create_initial_admin(db_path, admin_username, admin_password):
        print("❌ Failed to create initial admin!")
        sys.exit(1)
    
    # Step 3: Create sample user
    if not create_sample_user(db_path):
        print("⚠️  Failed to create sample user (non-critical)")
    
    # Step 4: Verify
    if not verify_database(db_path):
        print("❌ Database verification failed!")
        sys.exit(1)
    
    print("\n🎉 Database setup completed successfully!")
    print(f"📁 Database location: {db_path}")
    print(f"👤 Admin username: {admin_username}")
    print(f"🔑 Admin password: {admin_password}")
    print("\nYou can now start the VPN Panel application.")

if __name__ == "__main__":
    main()