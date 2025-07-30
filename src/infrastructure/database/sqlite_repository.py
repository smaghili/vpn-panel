import sqlite3
import json
from datetime import datetime
from typing import List, Optional
from ...domain.entities.user import User, UserRole, UserStatus
from ...domain.entities.vpn_server import VPNServer, ProtocolType, ServerStatus
from ...domain.entities.vpn_client import VPNClient, ClientStatus
from ...domain.repositories.user_repository import UserRepository
from ...domain.repositories.server_repository import ServerRepository
from ...domain.repositories.client_repository import ClientRepository

class SQLiteUserRepository(UserRepository):
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT,
                    expire_date TEXT
                )
            """)
    
    def save(self, user: User) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.id, user.username, user.email, user.password_hash,
                    user.role.value, user.status.value,
                    user.created_at.isoformat(), user.updated_at.isoformat(),
                    user.last_login.isoformat() if user.last_login else None,
                    user.expire_date.isoformat() if user.expire_date else None
                ))
                return True
        except:
            return False
    
    def find_by_id(self, user_id: str) -> Optional[User]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return self._row_to_user(row) if row else None
    
    def find_by_username(self, username: str) -> Optional[User]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            return self._row_to_user(row) if row else None
    
    def find_by_email(self, email: str) -> Optional[User]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            return self._row_to_user(row) if row else None
    
    def find_all(self) -> List[User]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM users")
            return [self._row_to_user(row) for row in cursor.fetchall()]
    
    def find_by_role(self, role: str) -> List[User]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE role = ?", (role,))
            return [self._row_to_user(row) for row in cursor.fetchall()]
    
    def find_active_users(self) -> List[User]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE status = ?", (UserStatus.ACTIVE.value,))
            return [self._row_to_user(row) for row in cursor.fetchall()]
    
    def delete(self, user_id: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                return True
        except:
            return False
    
    def update(self, user: User) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE users SET username=?, email=?, password_hash=?, role=?, 
                    status=?, updated_at=?, last_login=?, expire_date=? WHERE id=?
                """, (
                    user.username, user.email, user.password_hash,
                    user.role.value, user.status.value, user.updated_at.isoformat(),
                    user.last_login.isoformat() if user.last_login else None,
                    user.expire_date.isoformat() if user.expire_date else None,
                    user.id
                ))
                return True
        except:
            return False
    
    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM users")
            return cursor.fetchone()[0]
    
    def _row_to_user(self, row) -> User:
        return User(
            id=row[0], username=row[1], email=row[2], password_hash=row[3],
            role=UserRole(row[4]), status=UserStatus(row[5]),
            created_at=datetime.fromisoformat(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
            last_login=datetime.fromisoformat(row[8]) if row[8] else None,
            expire_date=datetime.fromisoformat(row[9]) if row[9] else None
        )

class SQLiteServerRepository(ServerRepository):
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vpn_servers (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    protocol TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    interface TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    config_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
    
    def save(self, server: VPNServer) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO vpn_servers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    server.id, server.name, server.protocol.value, server.port,
                    server.interface, server.private_key, server.public_key,
                    server.status.value, server.config_path,
                    server.created_at.isoformat(), server.updated_at.isoformat()
                ))
                return True
        except:
            return False
    
    def find_by_id(self, server_id: str) -> Optional[VPNServer]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_servers WHERE id = ?", (server_id,))
            row = cursor.fetchone()
            return self._row_to_server(row) if row else None
    
    def find_by_name(self, name: str) -> Optional[VPNServer]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_servers WHERE name = ?", (name,))
            row = cursor.fetchone()
            return self._row_to_server(row) if row else None
    
    def find_by_port(self, port: int) -> Optional[VPNServer]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_servers WHERE port = ?", (port,))
            row = cursor.fetchone()
            return self._row_to_server(row) if row else None
    
    def find_by_protocol(self, protocol: ProtocolType) -> List[VPNServer]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_servers WHERE protocol = ?", (protocol.value,))
            return [self._row_to_server(row) for row in cursor.fetchall()]
    
    def find_running_servers(self) -> List[VPNServer]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_servers WHERE status = ?", (ServerStatus.RUNNING.value,))
            return [self._row_to_server(row) for row in cursor.fetchall()]
    
    def find_all(self) -> List[VPNServer]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_servers")
            return [self._row_to_server(row) for row in cursor.fetchall()]
    
    def delete(self, server_id: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM vpn_servers WHERE id = ?", (server_id,))
                return True
        except:
            return False
    
    def update(self, server: VPNServer) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE vpn_servers SET name=?, protocol=?, port=?, interface=?, 
                    private_key=?, public_key=?, status=?, config_path=?, updated_at=? WHERE id=?
                """, (
                    server.name, server.protocol.value, server.port, server.interface,
                    server.private_key, server.public_key, server.status.value,
                    server.config_path, server.updated_at.isoformat(), server.id
                ))
                return True
        except:
            return False
    
    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM vpn_servers")
            return cursor.fetchone()[0]
    
    def _row_to_server(self, row) -> VPNServer:
        return VPNServer(
            id=row[0], name=row[1], protocol=ProtocolType(row[2]), port=row[3],
            interface=row[4], private_key=row[5], public_key=row[6],
            status=ServerStatus(row[7]), config_path=row[8],
            created_at=datetime.fromisoformat(row[9]),
            updated_at=datetime.fromisoformat(row[10])
        )

class SQLiteClientRepository(ClientRepository):
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vpn_clients (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    server_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    allowed_ips TEXT NOT NULL,
                    bandwidth_limit INTEGER NOT NULL,
                    bandwidth_used INTEGER NOT NULL,
                    expire_date TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_connected TEXT
                )
            """)
    
    def save(self, client: VPNClient) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO vpn_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    client.id, client.user_id, client.server_id, client.name,
                    client.public_key, client.private_key, client.allowed_ips,
                    client.bandwidth_limit, client.bandwidth_used,
                    client.expire_date.isoformat() if client.expire_date else None,
                    client.status.value, client.created_at.isoformat(),
                    client.updated_at.isoformat(),
                    client.last_connected.isoformat() if client.last_connected else None
                ))
                return True
        except:
            return False
    
    def find_by_id(self, client_id: str) -> Optional[VPNClient]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_clients WHERE id = ?", (client_id,))
            row = cursor.fetchone()
            return self._row_to_client(row) if row else None
    
    def find_by_user_id(self, user_id: str) -> List[VPNClient]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_clients WHERE user_id = ?", (user_id,))
            return [self._row_to_client(row) for row in cursor.fetchall()]
    
    def find_by_server_id(self, server_id: str) -> List[VPNClient]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_clients WHERE server_id = ?", (server_id,))
            return [self._row_to_client(row) for row in cursor.fetchall()]
    
    def find_active_clients(self) -> List[VPNClient]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_clients WHERE status = ?", (ClientStatus.ACTIVE.value,))
            return [self._row_to_client(row) for row in cursor.fetchall()]
    
    def find_expired_clients(self) -> List[VPNClient]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_clients WHERE expire_date < ?", (datetime.now().isoformat(),))
            return [self._row_to_client(row) for row in cursor.fetchall()]
    
    def find_by_bandwidth_exceeded(self) -> List[VPNClient]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_clients WHERE bandwidth_used >= bandwidth_limit")
            return [self._row_to_client(row) for row in cursor.fetchall()]
    
    def find_all(self) -> List[VPNClient]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM vpn_clients")
            return [self._row_to_client(row) for row in cursor.fetchall()]
    
    def delete(self, client_id: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM vpn_clients WHERE id = ?", (client_id,))
                return True
        except:
            return False
    
    def update(self, client: VPNClient) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE vpn_clients SET user_id=?, server_id=?, name=?, public_key=?, 
                    private_key=?, allowed_ips=?, bandwidth_limit=?, bandwidth_used=?, 
                    expire_date=?, status=?, updated_at=?, last_connected=? WHERE id=?
                """, (
                    client.user_id, client.server_id, client.name, client.public_key,
                    client.private_key, client.allowed_ips, client.bandwidth_limit,
                    client.bandwidth_used, client.expire_date.isoformat() if client.expire_date else None,
                    client.status.value, client.updated_at.isoformat(),
                    client.last_connected.isoformat() if client.last_connected else None,
                    client.id
                ))
                return True
        except:
            return False
    
    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM vpn_clients")
            return cursor.fetchone()[0]
    
    def _row_to_client(self, row) -> VPNClient:
        return VPNClient(
            id=row[0], user_id=row[1], server_id=row[2], name=row[3],
            public_key=row[4], private_key=row[5], allowed_ips=row[6],
            bandwidth_limit=row[7], bandwidth_used=row[8],
            expire_date=datetime.fromisoformat(row[9]) if row[9] else None,
            status=ClientStatus(row[10]), created_at=datetime.fromisoformat(row[11]),
            updated_at=datetime.fromisoformat(row[12]),
            last_connected=datetime.fromisoformat(row[13]) if row[13] else None
        ) 