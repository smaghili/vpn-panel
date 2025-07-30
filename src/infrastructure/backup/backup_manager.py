import os
import json
import shutil
import zipfile
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import subprocess
import tempfile

@dataclass
class BackupInfo:
    backup_id: str
    timestamp: datetime
    size_bytes: int
    type: str
    description: str
    status: str
    file_path: str

class BackupManager:
    def __init__(self, backup_dir: str = "/var/lib/vpn-panel/backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
        self.db_path = "/var/lib/vpn-panel/users.db"
        self.config_dir = Path("/etc/vpn-panel")
        self.log_dir = Path("/var/log/vpn-panel")
        self.app_dir = Path("/var/lib/vpn-panel")
        
    def create_full_backup(self, description: str = "") -> BackupInfo:
        """Create full system backup"""
        backup_id = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_path = self.backup_dir / f"{backup_id}.zip"
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                self._backup_database(zipf, backup_id)
                self._backup_configs(zipf, backup_id)
                self._backup_logs(zipf, backup_id)
                self._backup_secrets(zipf, backup_id)
                self._backup_wireguard(zipf, backup_id)
                self._backup_openvpn(zipf, backup_id)
                self._backup_metadata(zipf, backup_id, description)
            
            size = backup_path.stat().st_size
            backup_info = BackupInfo(
                backup_id=backup_id,
                timestamp=datetime.now(),
                size_bytes=size,
                type="full",
                description=description,
                status="completed",
                file_path=str(backup_path)
            )
            
            self._save_backup_info(backup_info)
            self.logger.info(f"Full backup created: {backup_id}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
            if backup_path.exists():
                backup_path.unlink()
            raise
    
    def create_database_backup(self, description: str = "") -> BackupInfo:
        """Create database-only backup"""
        backup_id = f"db_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_path = self.backup_dir / f"{backup_id}.zip"
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                self._backup_database(zipf, backup_id)
                self._backup_metadata(zipf, backup_id, description, "database")
            
            size = backup_path.stat().st_size
            backup_info = BackupInfo(
                backup_id=backup_id,
                timestamp=datetime.now(),
                size_bytes=size,
                type="database",
                description=description,
                status="completed",
                file_path=str(backup_path)
            )
            
            self._save_backup_info(backup_info)
            self.logger.info(f"Database backup created: {backup_id}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"Database backup failed: {e}")
            if backup_path.exists():
                backup_path.unlink()
            raise
    
    def create_config_backup(self, description: str = "") -> BackupInfo:
        """Create configuration-only backup"""
        backup_id = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_path = self.backup_dir / f"{backup_id}.zip"
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                self._backup_configs(zipf, backup_id)
                self._backup_secrets(zipf, backup_id)
                self._backup_wireguard(zipf, backup_id)
                self._backup_openvpn(zipf, backup_id)
                self._backup_metadata(zipf, backup_id, description, "config")
            
            size = backup_path.stat().st_size
            backup_info = BackupInfo(
                backup_id=backup_id,
                timestamp=datetime.now(),
                size_bytes=size,
                type="config",
                description=description,
                status="completed",
                file_path=str(backup_path)
            )
            
            self._save_backup_info(backup_info)
            self.logger.info(f"Config backup created: {backup_id}")
            return backup_info
            
        except Exception as e:
            self.logger.error(f"Config backup failed: {e}")
            if backup_path.exists():
                backup_path.unlink()
            raise
    
    def _backup_database(self, zipf: zipfile.ZipFile, backup_id: str):
        """Backup SQLite database"""
        if os.path.exists(self.db_path):
            db_backup_path = f"{backup_id}/database/users.db"
            zipf.write(self.db_path, db_backup_path)
    
    def _backup_configs(self, zipf: zipfile.ZipFile, backup_id: str):
        """Backup configuration files"""
        if self.config_dir.exists():
            for item in self.config_dir.rglob("*"):
                if item.is_file():
                    relative_path = f"{backup_id}/configs/{item.relative_to(self.config_dir)}"
                    zipf.write(item, relative_path)
    
    def _backup_logs(self, zipf: zipfile.ZipFile, backup_id: str):
        """Backup log files"""
        if self.log_dir.exists():
            for item in self.log_dir.rglob("*"):
                if item.is_file():
                    relative_path = f"{backup_id}/logs/{item.relative_to(self.log_dir)}"
                    zipf.write(item, relative_path)
    
    def _backup_secrets(self, zipf: zipfile.ZipFile, backup_id: str):
        """Backup secret files"""
        secrets_file = Path("/etc/vpn-panel/secrets.json")
        if secrets_file.exists():
            zipf.write(secrets_file, f"{backup_id}/secrets/secrets.json")
    
    def _backup_wireguard(self, zipf: zipfile.ZipFile, backup_id: str):
        """Backup WireGuard configuration"""
        wg_dir = Path("/etc/wireguard")
        if wg_dir.exists():
            for item in wg_dir.rglob("*"):
                if item.is_file():
                    relative_path = f"{backup_id}/wireguard/{item.relative_to(wg_dir)}"
                    zipf.write(item, relative_path)
    
    def _backup_openvpn(self, zipf: zipfile.ZipFile, backup_id: str):
        """Backup OpenVPN configuration"""
        ovpn_dir = Path("/etc/openvpn")
        if ovpn_dir.exists():
            for item in ovpn_dir.rglob("*"):
                if item.is_file():
                    relative_path = f"{backup_id}/openvpn/{item.relative_to(ovpn_dir)}"
                    zipf.write(item, relative_path)
    
    def _backup_metadata(self, zipf: zipfile.ZipFile, backup_id: str, description: str, backup_type: str = "full"):
        """Backup metadata information"""
        metadata = {
            "backup_id": backup_id,
            "timestamp": datetime.now().isoformat(),
            "type": backup_type,
            "description": description,
            "version": "1.0.0",
            "system_info": self._get_system_info()
        }
        
        zipf.writestr(f"{backup_id}/metadata.json", json.dumps(metadata, indent=2))
    
    def _get_system_info(self) -> Dict:
        """Get system information"""
        try:
            result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
            uname = result.stdout.strip()
        except:
            uname = "Unknown"
        
        return {
            "uname": uname,
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            "backup_manager_version": "1.0.0"
        }
    
    def _save_backup_info(self, backup_info: BackupInfo):
        """Save backup information to index file"""
        index_file = self.backup_dir / "backup_index.json"
        
        if index_file.exists():
            with open(index_file, 'r') as f:
                index = json.load(f)
        else:
            index = {"backups": []}
        
        index["backups"].append({
            "backup_id": backup_info.backup_id,
            "timestamp": backup_info.timestamp.isoformat(),
            "size_bytes": backup_info.size_bytes,
            "type": backup_info.type,
            "description": backup_info.description,
            "status": backup_info.status,
            "file_path": backup_info.file_path
        })
        
        with open(index_file, 'w') as f:
            json.dump(index, f, indent=2)
    
    def restore_backup(self, backup_id: str, restore_type: str = "full") -> bool:
        """Restore from backup"""
        backup_path = self.backup_dir / f"{backup_id}.zip"
        
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup {backup_id} not found")
        
        try:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                if restore_type == "full" or restore_type == "database":
                    self._restore_database(zipf, backup_id)
                
                if restore_type == "full" or restore_type == "config":
                    self._restore_configs(zipf, backup_id)
                    self._restore_secrets(zipf, backup_id)
                    self._restore_wireguard(zipf, backup_id)
                    self._restore_openvpn(zipf, backup_id)
            
            self.logger.info(f"Backup restored: {backup_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Restore failed: {e}")
            raise
    
    def _restore_database(self, zipf: zipfile.ZipFile, backup_id: str):
        """Restore database"""
        db_backup_path = f"{backup_id}/database/users.db"
        
        if db_backup_path in zipf.namelist():
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(zipf.read(db_backup_path))
                tmp_path = tmp.name
            
            shutil.move(tmp_path, self.db_path)
            os.chmod(self.db_path, 0o600)
    
    def _restore_configs(self, zipf: zipfile.ZipFile, backup_id: str):
        """Restore configuration files"""
        config_prefix = f"{backup_id}/configs/"
        
        for item in zipf.namelist():
            if item.startswith(config_prefix):
                relative_path = item[len(config_prefix):]
                target_path = self.config_dir / relative_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(target_path, 'wb') as f:
                    f.write(zipf.read(item))
    
    def _restore_secrets(self, zipf: zipfile.ZipFile, backup_id: str):
        """Restore secret files"""
        secrets_backup_path = f"{backup_id}/secrets/secrets.json"
        
        if secrets_backup_path in zipf.namelist():
            secrets_file = Path("/etc/vpn-panel/secrets.json")
            secrets_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(secrets_file, 'wb') as f:
                f.write(zipf.read(secrets_backup_path))
            
            os.chmod(secrets_file, 0o600)
    
    def _restore_wireguard(self, zipf: zipfile.ZipFile, backup_id: str):
        """Restore WireGuard configuration"""
        wg_prefix = f"{backup_id}/wireguard/"
        
        for item in zipf.namelist():
            if item.startswith(wg_prefix):
                relative_path = item[len(wg_prefix):]
                target_path = Path("/etc/wireguard") / relative_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(target_path, 'wb') as f:
                    f.write(zipf.read(item))
                
                if target_path.suffix in ['.key', '.pem']:
                    os.chmod(target_path, 0o600)
    
    def _restore_openvpn(self, zipf: zipfile.ZipFile, backup_id: str):
        """Restore OpenVPN configuration"""
        ovpn_prefix = f"{backup_id}/openvpn/"
        
        for item in zipf.namelist():
            if item.startswith(ovpn_prefix):
                relative_path = item[len(ovpn_prefix):]
                target_path = Path("/etc/openvpn") / relative_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(target_path, 'wb') as f:
                    f.write(zipf.read(item))
                
                if target_path.suffix in ['.key', '.pem', '.crt']:
                    os.chmod(target_path, 0o600)
    
    def list_backups(self) -> List[BackupInfo]:
        """List all available backups"""
        index_file = self.backup_dir / "backup_index.json"
        
        if not index_file.exists():
            return []
        
        with open(index_file, 'r') as f:
            index = json.load(f)
        
        backups = []
        for backup_data in index.get("backups", []):
            backup_info = BackupInfo(
                backup_id=backup_data["backup_id"],
                timestamp=datetime.fromisoformat(backup_data["timestamp"]),
                size_bytes=backup_data["size_bytes"],
                type=backup_data["type"],
                description=backup_data["description"],
                status=backup_data["status"],
                file_path=backup_data["file_path"]
            )
            backups.append(backup_info)
        
        return sorted(backups, key=lambda x: x.timestamp, reverse=True)
    
    def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup"""
        backup_path = self.backup_dir / f"{backup_id}.zip"
        
        if backup_path.exists():
            backup_path.unlink()
            
            index_file = self.backup_dir / "backup_index.json"
            if index_file.exists():
                with open(index_file, 'r') as f:
                    index = json.load(f)
                
                index["backups"] = [b for b in index["backups"] if b["backup_id"] != backup_id]
                
                with open(index_file, 'w') as f:
                    json.dump(index, f, indent=2)
            
            self.logger.info(f"Backup deleted: {backup_id}")
            return True
        
        return False
    
    def get_backup_info(self, backup_id: str) -> Optional[BackupInfo]:
        """Get specific backup information"""
        backups = self.list_backups()
        for backup in backups:
            if backup.backup_id == backup_id:
                return backup
        return None
    
    def cleanup_old_backups(self, days: int = 30) -> int:
        """Clean up backups older than specified days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        backups = self.list_backups()
        deleted_count = 0
        
        for backup in backups:
            if backup.timestamp < cutoff_date:
                if self.delete_backup(backup.backup_id):
                    deleted_count += 1
        
        self.logger.info(f"Cleaned up {deleted_count} old backups")
        return deleted_count
    
    def get_backup_stats(self) -> Dict:
        """Get backup statistics"""
        backups = self.list_backups()
        
        total_size = sum(b.size_bytes for b in backups)
        type_counts = {}
        
        for backup in backups:
            type_counts[backup.type] = type_counts.get(backup.type, 0) + 1
        
        return {
            "total_backups": len(backups),
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "type_counts": type_counts,
            "oldest_backup": min(backups, key=lambda x: x.timestamp).timestamp if backups else None,
            "newest_backup": max(backups, key=lambda x: x.timestamp).timestamp if backups else None
        }

backup_manager = BackupManager() 