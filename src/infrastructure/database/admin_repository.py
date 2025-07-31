"""
Admin Repository
===============

Repository for managing admin users - system administrators and representatives.
Admins have access to the management panel and can create/manage VPN users.
"""
import sqlite3
import bcrypt
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
import logging

class AdminRepository:
    """Repository for admin user management"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
    
    def create_admin(self, username: str, password: str, role: str = 'representative', created_by: str = None) -> Optional[str]:
        """Create new admin user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if username already exists
                cursor.execute("SELECT id FROM admins WHERE username = ?", (username,))
                if cursor.fetchone():
                    self.logger.warning(f"Admin username already exists: {username}")
                    return None
                
                # Hash password
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                # Create admin
                admin_id = str(uuid.uuid4())
                current_time = datetime.now().isoformat()
                
                cursor.execute("""
                    INSERT INTO admins (
                        id, username, password_hash, role, status,
                        created_at, updated_at, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    admin_id, username, password_hash, role, 'active',
                    current_time, current_time, created_by
                ))
                
                conn.commit()
                self.logger.info(f"Admin created successfully: {username} ({role})")
                return admin_id
                
        except Exception as e:
            self.logger.error(f"Error creating admin: {e}")
            return None
    
    def authenticate_admin(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate admin user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, username, password_hash, role, status, last_login
                    FROM admins WHERE username = ? AND status = 'active'
                """, (username,))
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                admin_id, username, password_hash, role, status, last_login = result
                
                # Verify password
                if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                    return None
                
                # Update last login
                cursor.execute("""
                    UPDATE admins SET last_login = ?, updated_at = ?
                    WHERE id = ?
                """, (datetime.now().isoformat(), datetime.now().isoformat(), admin_id))
                
                conn.commit()
                
                return {
                    'id': admin_id,
                    'username': username,
                    'role': role,
                    'status': status,
                    'last_login': last_login
                }
                
        except Exception as e:
            self.logger.error(f"Error authenticating admin: {e}")
            return None
    
    def get_admin_by_id(self, admin_id: str) -> Optional[Dict[str, Any]]:
        """Get admin by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, username, role, status, created_at, updated_at, last_login, created_by
                    FROM admins WHERE id = ?
                """, (admin_id,))
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                return {
                    'id': result[0],
                    'username': result[1],
                    'role': result[2],
                    'status': result[3],
                    'created_at': result[4],
                    'updated_at': result[5],
                    'last_login': result[6],
                    'created_by': result[7]
                }
                
        except Exception as e:
            self.logger.error(f"Error getting admin by ID: {e}")
            return None
    
    def list_admins(self, role: str = None) -> List[Dict[str, Any]]:
        """List all admins, optionally filtered by role"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if role:
                    cursor.execute("""
                        SELECT id, username, role, status, created_at, updated_at, last_login, created_by
                        FROM admins WHERE role = ? ORDER BY created_at DESC
                    """, (role,))
                else:
                    cursor.execute("""
                        SELECT id, username, role, status, created_at, updated_at, last_login, created_by
                        FROM admins ORDER BY created_at DESC
                    """)
                
                results = cursor.fetchall()
                
                return [{
                    'id': row[0],
                    'username': row[1],
                    'role': row[2],
                    'status': row[3],
                    'created_at': row[4],
                    'updated_at': row[5],
                    'last_login': row[6],
                    'created_by': row[7]
                } for row in results]
                
        except Exception as e:
            self.logger.error(f"Error listing admins: {e}")
            return []
    
    def update_admin_status(self, admin_id: str, status: str) -> bool:
        """Update admin status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE admins SET status = ?, updated_at = ?
                    WHERE id = ?
                """, (status, datetime.now().isoformat(), admin_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error updating admin status: {e}")
            return False
    
    def change_admin_password(self, admin_id: str, new_password: str) -> bool:
        """Change admin password"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Hash new password
                password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                cursor.execute("""
                    UPDATE admins SET password_hash = ?, updated_at = ?
                    WHERE id = ?
                """, (password_hash, datetime.now().isoformat(), admin_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error changing admin password: {e}")
            return False
    
    def delete_admin(self, admin_id: str) -> bool:
        """Delete admin (only for representatives, not main admin)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if it's main admin
                cursor.execute("SELECT role FROM admins WHERE id = ?", (admin_id,))
                result = cursor.fetchone()
                
                if not result:
                    return False
                
                if result[0] == 'admin':
                    self.logger.warning("Cannot delete main admin user")
                    return False
                
                cursor.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
                conn.commit()
                
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error deleting admin: {e}")
            return False
    
    def get_admin_statistics(self) -> Dict[str, int]:
        """Get admin statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total admins
                cursor.execute("SELECT COUNT(*) FROM admins")
                total_admins = cursor.fetchone()[0]
                
                # Active admins
                cursor.execute("SELECT COUNT(*) FROM admins WHERE status = 'active'")
                active_admins = cursor.fetchone()[0]
                
                # Admins by role
                cursor.execute("SELECT role, COUNT(*) FROM admins GROUP BY role")
                role_counts = dict(cursor.fetchall())
                
                return {
                    'total_admins': total_admins,
                    'active_admins': active_admins,
                    'admin_count': role_counts.get('admin', 0),
                    'representative_count': role_counts.get('representative', 0)
                }
                
        except Exception as e:
            self.logger.error(f"Error getting admin statistics: {e}")
            return {
                'total_admins': 0,
                'active_admins': 0,
                'admin_count': 0,
                'representative_count': 0
            }