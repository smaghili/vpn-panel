"""
VPN User Repository
==================

Repository for managing VPN users/clients. These are the end-users who connect
to the VPN service and have bandwidth limits, protocol access, etc.
"""
import sqlite3
import bcrypt
import uuid
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import logging

class VPNUserRepository:
    """Repository for VPN user management"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
    
    def create_user(self, username: str, password: str, admin_id: str, **kwargs) -> Optional[str]:
        """Create new VPN user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if username already exists
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    self.logger.warning(f"Username already exists: {username}")
                    return None
                
                # Hash password
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                # Create user
                user_id = str(uuid.uuid4())
                current_time = datetime.now().isoformat()
                
                # Default values
                daily_limit = kwargs.get('daily_limit_bytes', 1024*1024*1024)  # 1GB
                monthly_limit = kwargs.get('monthly_limit_bytes', 30*1024*1024*1024)  # 30GB
                expire_days = kwargs.get('expire_days', 30)
                allowed_protocols = kwargs.get('allowed_protocols', 'openvpn,wireguard')
                
                expire_date = (datetime.now() + timedelta(days=expire_days)).isoformat()
                
                cursor.execute("""
                    INSERT INTO users (
                        id, username, password_hash, status,
                        daily_limit_bytes, monthly_limit_bytes,
                        daily_used_bytes, monthly_used_bytes, total_used_bytes,
                        expire_date, allowed_protocols,
                        created_at, updated_at, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, username, password_hash, 'active',
                    daily_limit, monthly_limit, 0, 0, 0,
                    expire_date, allowed_protocols,
                    current_time, current_time, admin_id
                ))
                
                conn.commit()
                self.logger.info(f"VPN user created successfully: {username}")
                return user_id
                
        except Exception as e:
            self.logger.error(f"Error creating VPN user: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate VPN user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, username, password_hash, status, expire_date, allowed_protocols,
                           daily_limit_bytes, monthly_limit_bytes, daily_used_bytes, monthly_used_bytes
                    FROM users WHERE username = ?
                """, (username,))
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                user_id, username, password_hash, status, expire_date, allowed_protocols, \
                daily_limit, monthly_limit, daily_used, monthly_used = result
                
                # Check password
                if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                    return None
                
                # Check status
                if status != 'active':
                    return None
                
                # Check expiration
                if expire_date:
                    expire_dt = datetime.fromisoformat(expire_date)
                    if datetime.now() > expire_dt:
                        # Update status to expired
                        cursor.execute("UPDATE users SET status = 'expired' WHERE id = ?", (user_id,))
                        conn.commit()
                        return None
                
                return {
                    'id': user_id,
                    'username': username,
                    'status': status,
                    'expire_date': expire_date,
                    'allowed_protocols': allowed_protocols.split(',') if allowed_protocols else [],
                    'daily_limit_bytes': daily_limit,
                    'monthly_limit_bytes': monthly_limit,
                    'daily_used_bytes': daily_used,
                    'monthly_used_bytes': monthly_used
                }
                
        except Exception as e:
            self.logger.error(f"Error authenticating VPN user: {e}")
            return None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, username, status, daily_limit_bytes, monthly_limit_bytes,
                           daily_used_bytes, monthly_used_bytes, total_used_bytes,
                           last_online, expire_date, allowed_protocols,
                           created_at, updated_at, created_by
                    FROM users WHERE id = ?
                """, (user_id,))
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                return {
                    'id': result[0],
                    'username': result[1],
                    'status': result[2],
                    'daily_limit_bytes': result[3],
                    'monthly_limit_bytes': result[4],
                    'daily_used_bytes': result[5],
                    'monthly_used_bytes': result[6],
                    'total_used_bytes': result[7],
                    'last_online': result[8],
                    'expire_date': result[9],
                    'allowed_protocols': result[10].split(',') if result[10] else [],
                    'created_at': result[11],
                    'updated_at': result[12],
                    'created_by': result[13]
                }
                
        except Exception as e:
            self.logger.error(f"Error getting user by ID: {e}")
            return None
    
    def list_users(self, status: str = None, admin_id: str = None) -> List[Dict[str, Any]]:
        """List VPN users"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT id, username, status, daily_limit_bytes, monthly_limit_bytes,
                           daily_used_bytes, monthly_used_bytes, total_used_bytes,
                           last_online, expire_date, allowed_protocols,
                           created_at, updated_at, created_by
                    FROM users
                """
                params = []
                
                conditions = []
                if status:
                    conditions.append("status = ?")
                    params.append(status)
                
                if admin_id:
                    conditions.append("created_by = ?")
                    params.append(admin_id)
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY created_at DESC"
                
                cursor.execute(query, params)
                results = cursor.fetchall()
                
                return [{
                    'id': row[0],
                    'username': row[1],
                    'status': row[2],
                    'daily_limit_bytes': row[3],
                    'monthly_limit_bytes': row[4],
                    'daily_used_bytes': row[5],
                    'monthly_used_bytes': row[6],
                    'total_used_bytes': row[7],
                    'last_online': row[8],
                    'expire_date': row[9],
                    'allowed_protocols': row[10].split(',') if row[10] else [],
                    'created_at': row[11],
                    'updated_at': row[12],
                    'created_by': row[13]
                } for row in results]
                
        except Exception as e:
            self.logger.error(f"Error listing users: {e}")
            return []
    
    def update_user_bandwidth_limits(self, user_id: str, daily_limit: int = None, monthly_limit: int = None) -> bool:
        """Update user bandwidth limits"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                updates = []
                params = []
                
                if daily_limit is not None:
                    updates.append("daily_limit_bytes = ?")
                    params.append(daily_limit)
                
                if monthly_limit is not None:
                    updates.append("monthly_limit_bytes = ?")
                    params.append(monthly_limit)
                
                if not updates:
                    return False
                
                updates.append("updated_at = ?")
                params.append(datetime.now().isoformat())
                params.append(user_id)
                
                query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, params)
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error updating user bandwidth limits: {e}")
            return False
    
    def update_user_status(self, user_id: str, status: str) -> bool:
        """Update user status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE users SET status = ?, updated_at = ?
                    WHERE id = ?
                """, (status, datetime.now().isoformat(), user_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error updating user status: {e}")
            return False
    
    def extend_user_expiry(self, user_id: str, extend_days: int) -> bool:
        """Extend user expiry date"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get current expiry
                cursor.execute("SELECT expire_date FROM users WHERE id = ?", (user_id,))
                result = cursor.fetchone()
                
                if not result:
                    return False
                
                current_expire = result[0]
                if current_expire:
                    expire_dt = datetime.fromisoformat(current_expire)
                    new_expire = expire_dt + timedelta(days=extend_days)
                else:
                    new_expire = datetime.now() + timedelta(days=extend_days)
                
                cursor.execute("""
                    UPDATE users SET expire_date = ?, updated_at = ?
                    WHERE id = ?
                """, (new_expire.isoformat(), datetime.now().isoformat(), user_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error extending user expiry: {e}")
            return False
    
    def record_bandwidth_usage(self, user_id: str, bytes_used: int) -> bool:
        """Record bandwidth usage"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                today = datetime.now().date().isoformat()
                current_time = datetime.now().isoformat()
                
                # Update daily usage in bandwidth_logs
                cursor.execute("""
                    INSERT OR REPLACE INTO bandwidth_logs (
                        id, user_id, date, bytes_used, created_at
                    ) VALUES (
                        COALESCE((SELECT id FROM bandwidth_logs WHERE user_id = ? AND date = ?), ?),
                        ?, ?, 
                        COALESCE((SELECT bytes_used FROM bandwidth_logs WHERE user_id = ? AND date = ?), 0) + ?,
                        ?
                    )
                """, (user_id, today, str(uuid.uuid4()), user_id, today, user_id, today, bytes_used, current_time))
                
                # Update user totals
                cursor.execute("""
                    UPDATE users SET 
                        daily_used_bytes = daily_used_bytes + ?,
                        monthly_used_bytes = monthly_used_bytes + ?,
                        total_used_bytes = total_used_bytes + ?,
                        updated_at = ?
                    WHERE id = ?
                """, (bytes_used, bytes_used, bytes_used, current_time, user_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error recording bandwidth usage: {e}")
            return False
    
    def reset_daily_usage(self) -> bool:
        """Reset daily usage for all users (should be called daily)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE users SET daily_used_bytes = 0, updated_at = ?
                """, (datetime.now().isoformat(),))
                
                conn.commit()
                self.logger.info("Daily usage reset for all users")
                return True
                
        except Exception as e:
            self.logger.error(f"Error resetting daily usage: {e}")
            return False
    
    def get_user_statistics(self) -> Dict[str, int]:
        """Get user statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total users
                cursor.execute("SELECT COUNT(*) FROM users")
                total_users = cursor.fetchone()[0]
                
                # Active users
                cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
                active_users = cursor.fetchone()[0]
                
                # Expired users
                cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'expired'")
                expired_users = cursor.fetchone()[0]
                
                # Users created today
                today = datetime.now().date().isoformat()
                cursor.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?", (today,))
                today_users = cursor.fetchone()[0]
                
                return {
                    'total_users': total_users,
                    'active_users': active_users,
                    'expired_users': expired_users,
                    'today_users': today_users
                }
                
        except Exception as e:
            self.logger.error(f"Error getting user statistics: {e}")
            return {
                'total_users': 0,
                'active_users': 0,
                'expired_users': 0,
                'today_users': 0
            }