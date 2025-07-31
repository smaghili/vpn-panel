#!/usr/bin/env python3
"""
Database Migration Script for VPN Panel
=======================================

This script migrates the existing users table to support the new unified schema
with bandwidth tracking and additional user management features.
"""
import sqlite3
import sys
from datetime import datetime

def migrate_users_table(db_path='/var/lib/vpn-panel/users.db'):
    """Migrate users table to new schema"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔄 Starting database migration...")
        
        # Check if migration is needed
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'total_daily_limit_bytes' in columns:
            print("✅ Database already migrated!")
            return True
        
        print("📊 Current columns:", columns)
        
        # Start transaction
        conn.execute("BEGIN TRANSACTION")
        
        # Step 1: Create new users table with full schema
        cursor.execute("""
            CREATE TABLE users_new (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                status TEXT NOT NULL DEFAULT 'active',
                total_daily_limit_bytes INTEGER DEFAULT 0,
                total_monthly_limit_bytes INTEGER DEFAULT 0,
                total_daily_used_bytes INTEGER DEFAULT 0,
                total_monthly_used_bytes INTEGER DEFAULT 0,
                total_used_bytes INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login TEXT,
                expire_date TEXT
            )
        """)
        
        # Step 2: Copy existing data with default values for new columns
        current_time = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO users_new (
                id, username, email, password_hash, role, status,
                total_daily_limit_bytes, total_monthly_limit_bytes,
                total_daily_used_bytes, total_monthly_used_bytes, total_used_bytes,
                created_at, updated_at, last_login, expire_date
            )
            SELECT 
                id, username, 
                COALESCE(email, username || '@vpn-panel.local') as email,
                password_hash, 
                COALESCE(role, 'user') as role,
                COALESCE(status, 'active') as status,
                0 as total_daily_limit_bytes,
                0 as total_monthly_limit_bytes,
                0 as total_daily_used_bytes,
                0 as total_monthly_used_bytes,
                0 as total_used_bytes,
                COALESCE(created_at, ?) as created_at,
                ? as updated_at,
                NULL as last_login,
                NULL as expire_date
            FROM users
        """, (current_time, current_time))
        
        # Step 3: Drop old table
        cursor.execute("DROP TABLE users")
        
        # Step 4: Rename new table
        cursor.execute("ALTER TABLE users_new RENAME TO users")
        
        # Step 5: Recreate indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        
        # Commit transaction
        conn.commit()
        
        print("✅ Database migration completed successfully!")
        print("📋 New schema applied with bandwidth tracking support")
        
        return True
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"❌ Migration failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def verify_migration(db_path='/var/lib/vpn-panel/users.db'):
    """Verify migration was successful"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check schema
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        required_columns = [
            'id', 'username', 'email', 'password_hash', 'role', 'status',
            'total_daily_limit_bytes', 'total_monthly_limit_bytes',
            'total_daily_used_bytes', 'total_monthly_used_bytes', 'total_used_bytes',
            'created_at', 'updated_at', 'last_login', 'expire_date'
        ]
        
        missing_columns = [col for col in required_columns if col not in columns]
        
        if missing_columns:
            print(f"❌ Missing columns: {missing_columns}")
            return False
        
        # Check data integrity
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        print(f"✅ Migration verified successfully!")
        print(f"📊 Total users: {user_count}")
        print(f"📋 All required columns present: {len(columns)} columns")
        
        return True
        
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def main():
    """Main migration function"""
    db_path = '/var/lib/vpn-panel/users.db'
    
    print("🚀 VPN Panel Database Migration")
    print("=" * 40)
    
    # Backup database first
    import shutil
    backup_path = f"{db_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        shutil.copy2(db_path, backup_path)
        print(f"💾 Database backed up to: {backup_path}")
    except Exception as e:
        print(f"⚠️  Backup failed: {e}")
        if input("Continue without backup? (y/N): ").lower() != 'y':
            sys.exit(1)
    
    # Run migration
    if migrate_users_table(db_path):
        if verify_migration(db_path):
            print("\n🎉 Migration completed successfully!")
            print("You can now create admin user without errors.")
        else:
            print("\n❌ Migration verification failed!")
            sys.exit(1)
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()