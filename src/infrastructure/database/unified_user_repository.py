import sqlite3
import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from ...domain.entities.user_profile import (
    UserProfile, ProtocolType, ProtocolProfile, 
    WireGuardProfile, OpenVPNProfile, AuthType
)

class UnifiedUserRepository:
    """Unified repository for managing users with multiple protocols"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Main users table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
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
                
                # Protocol profiles table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS protocol_profiles (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        server_id TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        daily_used_bytes INTEGER DEFAULT 0,
                        monthly_used_bytes INTEGER DEFAULT 0,
                        total_used_bytes INTEGER DEFAULT 0,
                        daily_limit_bytes INTEGER DEFAULT 0,
                        monthly_limit_bytes INTEGER DEFAULT 0,
                        last_connected TEXT,
                        connection_count INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        config_data TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        UNIQUE(user_id, protocol, server_id)
                    )
                """)
                
                # WireGuard specific data
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS wireguard_profiles (
                        profile_id TEXT PRIMARY KEY,
                        public_key TEXT NOT NULL,
                        private_key TEXT NOT NULL,
                        allowed_ips TEXT DEFAULT '10.0.0.2/32',
                        endpoint TEXT,
                        FOREIGN KEY (profile_id) REFERENCES protocol_profiles (id) ON DELETE CASCADE
                    )
                """)
                
                # OpenVPN specific data
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS openvpn_profiles (
                        profile_id TEXT PRIMARY KEY,
                        auth_type TEXT NOT NULL DEFAULT 'certificate_only',
                        username TEXT,
                        password_hash TEXT,
                        certificate_path TEXT,
                        key_path TEXT,
                        FOREIGN KEY (profile_id) REFERENCES protocol_profiles (id) ON DELETE CASCADE
                    )
                """)
                
                # Create indexes
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON protocol_profiles(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_profiles_protocol ON protocol_profiles(protocol)")
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    def save_user(self, user_profile: UserProfile) -> bool:
        """Save user profile to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Save main user data
                conn.execute("""
                    INSERT OR REPLACE INTO users (
                        id, username, email, password_hash, role, status,
                        total_daily_limit_bytes, total_monthly_limit_bytes,
                        total_daily_used_bytes, total_monthly_used_bytes, total_used_bytes,
                        created_at, updated_at, last_login, expire_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_profile.user_id,
                    user_profile.username,
                    user_profile.email,
                    user_profile.password_hash,
                    user_profile.role,
                    user_profile.status,
                    user_profile.total_daily_limit_bytes,
                    user_profile.total_monthly_limit_bytes,
                    user_profile.total_daily_used_bytes,
                    user_profile.total_monthly_used_bytes,
                    user_profile.total_used_bytes,
                    user_profile.created_at.isoformat(),
                    user_profile.updated_at.isoformat(),
                    user_profile.last_login.isoformat() if user_profile.last_login else None,
                    user_profile.expire_date.isoformat() if user_profile.expire_date else None
                ))
                
                # Save protocol profiles
                for protocol, profile in user_profile.protocols.items():
                    self._save_protocol_profile(conn, profile)
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error saving user: {e}")
            return False
    
    def _save_protocol_profile(self, conn: sqlite3.Connection, profile: ProtocolProfile):
        """Save protocol profile to database"""
        profile_id = str(uuid.uuid4())
        
        # Save base profile data
        conn.execute("""
            INSERT OR REPLACE INTO protocol_profiles (
                id, user_id, protocol, server_id, is_active,
                daily_used_bytes, monthly_used_bytes, total_used_bytes,
                daily_limit_bytes, monthly_limit_bytes,
                last_connected, connection_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile_id,
            profile.user_id,
            profile.protocol.value,
            profile.server_id,
            profile.is_active,
            profile.daily_used_bytes,
            profile.monthly_used_bytes,
            profile.total_used_bytes,
            profile.daily_limit_bytes,
            profile.monthly_limit_bytes,
            profile.last_connected.isoformat() if profile.last_connected else None,
            profile.connection_count,
            profile.created_at.isoformat(),
            profile.updated_at.isoformat()
        ))
        
        # Save protocol-specific data
        if isinstance(profile, WireGuardProfile):
            conn.execute("""
                INSERT OR REPLACE INTO wireguard_profiles (
                    profile_id, public_key, private_key, allowed_ips, endpoint
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                profile_id,
                profile.public_key,
                profile.private_key,
                profile.allowed_ips,
                profile.endpoint
            ))
        
        elif isinstance(profile, OpenVPNProfile):
            conn.execute("""
                INSERT OR REPLACE INTO openvpn_profiles (
                    profile_id, auth_type, username, password_hash, certificate_path, key_path
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                profile_id,
                profile.auth_type.value,
                profile.username,
                profile.password_hash,
                profile.certificate_path,
                profile.key_path
            ))
    
    def find_by_id(self, user_id: str) -> Optional[UserProfile]:
        """Find user by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get main user data
                cursor = conn.execute("""
                    SELECT * FROM users WHERE id = ?
                """, (user_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Create user profile
                user_profile = UserProfile(
                    user_id=row[0],
                    username=row[1],
                    email=row[2],
                    password_hash=row[3],
                    role=row[4],
                    status=row[5],
                    total_daily_limit_bytes=row[6],
                    total_monthly_limit_bytes=row[7],
                    total_daily_used_bytes=row[8],
                    total_monthly_used_bytes=row[9],
                    total_used_bytes=row[10],
                    created_at=datetime.fromisoformat(row[11]),
                    updated_at=datetime.fromisoformat(row[12]),
                    last_login=datetime.fromisoformat(row[13]) if row[13] else None,
                    expire_date=datetime.fromisoformat(row[14]) if row[14] else None
                )
                
                # Load protocol profiles
                self._load_protocol_profiles(conn, user_profile)
                
                return user_profile
                
        except Exception as e:
            self.logger.error(f"Error finding user by ID: {e}")
            return None
    
    def find_by_username(self, username: str) -> Optional[UserProfile]:
        """Find user by username"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id FROM users WHERE username = ?
                """, (username,))
                
                row = cursor.fetchone()
                if row:
                    return self.find_by_id(row[0])
                return None
                
        except Exception as e:
            self.logger.error(f"Error finding user by username: {e}")
            return None
    
    def _load_protocol_profiles(self, conn: sqlite3.Connection, user_profile: UserProfile):
        """Load protocol profiles for user"""
        cursor = conn.execute("""
            SELECT p.*, 
                   w.public_key, w.private_key, w.allowed_ips, w.endpoint,
                   o.auth_type, o.username, o.password_hash, o.certificate_path, o.key_path
            FROM protocol_profiles p
            LEFT JOIN wireguard_profiles w ON p.id = w.profile_id
            LEFT JOIN openvpn_profiles o ON p.id = o.profile_id
            WHERE p.user_id = ?
        """, (user_profile.user_id,))
        
        for row in cursor.fetchall():
            protocol = ProtocolType(row[2])
            
            if protocol == ProtocolType.WIREGUARD and row[15]:  # public_key exists
                profile = WireGuardProfile(
                    user_id=row[1],
                    server_id=row[3],
                    public_key=row[15],
                    private_key=row[16],
                    allowed_ips=row[17] or "10.0.0.2/32",
                    endpoint=row[18] or "",
                    is_active=bool(row[4]),
                    daily_used_bytes=row[5],
                    monthly_used_bytes=row[6],
                    total_used_bytes=row[7],
                    daily_limit_bytes=row[8],
                    monthly_limit_bytes=row[9],
                    last_connected=datetime.fromisoformat(row[10]) if row[10] else None,
                    connection_count=row[11],
                    created_at=datetime.fromisoformat(row[12]),
                    updated_at=datetime.fromisoformat(row[13])
                )
                user_profile.add_protocol_profile(profile)
            
            elif protocol == ProtocolType.OPENVPN and row[19]:  # auth_type exists
                profile = OpenVPNProfile(
                    user_id=row[1],
                    server_id=row[3],
                    auth_type=AuthType(row[19]),
                    username=row[20],
                    password_hash=row[21],
                    certificate_path=row[22],
                    key_path=row[23],
                    is_active=bool(row[4]),
                    daily_used_bytes=row[5],
                    monthly_used_bytes=row[6],
                    total_used_bytes=row[7],
                    daily_limit_bytes=row[8],
                    monthly_limit_bytes=row[9],
                    last_connected=datetime.fromisoformat(row[10]) if row[10] else None,
                    connection_count=row[11],
                    created_at=datetime.fromisoformat(row[12]),
                    updated_at=datetime.fromisoformat(row[13])
                )
                user_profile.add_protocol_profile(profile)
    
    def find_all(self) -> List[UserProfile]:
        """Find all users"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT id FROM users ORDER BY created_at DESC")
                user_ids = [row[0] for row in cursor.fetchall()]
                
                users = []
                for user_id in user_ids:
                    user = self.find_by_id(user_id)
                    if user:
                        users.append(user)
                
                return users
                
        except Exception as e:
            self.logger.error(f"Error finding all users: {e}")
            return []
    
    def delete_user(self, user_id: str) -> bool:
        """Delete user and all their profiles"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error deleting user: {e}")
            return False
    
    def update_user(self, user_profile: UserProfile) -> bool:
        """Update user profile"""
        return self.save_user(user_profile)
    
    def count(self) -> int:
        """Count total users"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM users")
                return cursor.fetchone()[0]
                
        except Exception as e:
            self.logger.error(f"Error counting users: {e}")
            return 0
    
    def find_users_by_protocol(self, protocol: ProtocolType) -> List[UserProfile]:
        """Find users who have specific protocol enabled"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT DISTINCT user_id FROM protocol_profiles 
                    WHERE protocol = ? AND is_active = 1
                """, (protocol.value,))
                
                user_ids = [row[0] for row in cursor.fetchall()]
                users = []
                for user_id in user_ids:
                    user = self.find_by_id(user_id)
                    if user:
                        users.append(user)
                
                return users
                
        except Exception as e:
            self.logger.error(f"Error finding users by protocol: {e}")
            return []
    
    def get_protocol_stats(self) -> Dict[str, Any]:
        """Get statistics by protocol"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT protocol, 
                           COUNT(*) as user_count,
                           SUM(daily_used_bytes) as total_daily_used,
                           SUM(monthly_used_bytes) as total_monthly_used,
                           SUM(total_used_bytes) as total_used
                    FROM protocol_profiles 
                    WHERE is_active = 1
                    GROUP BY protocol
                """)
                
                stats = {}
                for row in cursor.fetchall():
                    stats[row[0]] = {
                        "user_count": row[1],
                        "total_daily_used_gb": row[2] / (1024**3) if row[2] else 0,
                        "total_monthly_used_gb": row[3] / (1024**3) if row[3] else 0,
                        "total_used_gb": row[4] / (1024**3) if row[4] else 0
                    }
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error getting protocol stats: {e}")
            return {} 