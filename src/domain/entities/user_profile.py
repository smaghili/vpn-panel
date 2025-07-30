from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import uuid

class ProtocolType(Enum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"
    # Future protocols can be added here
    # SHADOWSOCKS = "shadowsocks"
    # V2RAY = "v2ray"
    # TROJAN = "trojan"

class AuthType(Enum):
    CERTIFICATE_ONLY = "certificate_only"
    USERNAME_PASSWORD = "username_password"
    TOKEN = "token"
    # Future auth types
    # OAUTH = "oauth"
    # LDAP = "ldap"

@dataclass
class ProtocolProfile:
    """Base class for protocol-specific profiles"""
    user_id: str
    protocol: ProtocolType
    server_id: str
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Individual protocol usage tracking
    daily_used_bytes: int = 0
    monthly_used_bytes: int = 0
    total_used_bytes: int = 0
    
    # Connection tracking
    last_connected: Optional[datetime] = None
    connection_count: int = 0

@dataclass
class WireGuardProfile(ProtocolProfile):
    """WireGuard specific profile"""
    public_key: str = ""
    private_key: str = ""
    allowed_ips: str = ""
    endpoint: str = ""
    
    def __post_init__(self):
        self.protocol = ProtocolType.WIREGUARD

@dataclass
class OpenVPNProfile(ProtocolProfile):
    """OpenVPN specific profile"""
    auth_type: AuthType = AuthType.CERTIFICATE_ONLY
    username: Optional[str] = None
    password_hash: Optional[str] = None
    certificate_path: Optional[str] = None
    key_path: Optional[str] = None
    
    def __post_init__(self):
        self.protocol = ProtocolType.OPENVPN

@dataclass
class UserProfile:
    """Unified user profile supporting multiple protocols with combined limits"""
    user_id: str
    username: str
    email: str
    password_hash: str
    role: str = "user"
    status: str = "active"
    
    # Protocol profiles
    protocols: Dict[ProtocolType, ProtocolProfile] = field(default_factory=dict)
    
    # COMBINED limits (total across all protocols)
    total_daily_limit_bytes: int = 0
    total_monthly_limit_bytes: int = 0
    
    # COMBINED usage (sum of all protocols)
    total_daily_used_bytes: int = 0
    total_monthly_used_bytes: int = 0
    total_used_bytes: int = 0
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    expire_date: Optional[datetime] = None
    
    def add_protocol_profile(self, profile: ProtocolProfile):
        """Add a protocol profile to user"""
        self.protocols[profile.protocol] = profile
        self.updated_at = datetime.now()
    
    def remove_protocol_profile(self, protocol: ProtocolType):
        """Remove a protocol profile from user"""
        if protocol in self.protocols:
            del self.protocols[protocol]
            self.updated_at = datetime.now()
    
    def get_protocol_profile(self, protocol: ProtocolType) -> Optional[ProtocolProfile]:
        """Get specific protocol profile"""
        return self.protocols.get(protocol)
    
    def is_protocol_enabled(self, protocol: ProtocolType) -> bool:
        """Check if protocol is enabled for user"""
        profile = self.get_protocol_profile(protocol)
        return profile is not None and profile.is_active
    
    def update_bandwidth_usage(self, protocol: ProtocolType, bytes_used: int):
        """Update bandwidth usage for specific protocol and recalculate totals"""
        profile = self.get_protocol_profile(protocol)
        if profile:
            # Update individual protocol usage
            profile.daily_used_bytes += bytes_used
            profile.monthly_used_bytes += bytes_used
            profile.total_used_bytes += bytes_used
            profile.updated_at = datetime.now()
            
            # Recalculate combined totals
            self._recalculate_total_usage()
    
    def _recalculate_total_usage(self):
        """Recalculate total usage from all protocols"""
        self.total_daily_used_bytes = sum(
            profile.daily_used_bytes for profile in self.protocols.values()
        )
        self.total_monthly_used_bytes = sum(
            profile.monthly_used_bytes for profile in self.protocols.values()
        )
        self.total_used_bytes = sum(
            profile.total_used_bytes for profile in self.protocols.values()
        )
        self.updated_at = datetime.now()
    
    def check_bandwidth_limits(self, protocol: ProtocolType) -> tuple[bool, str]:
        """Check if user has exceeded COMBINED bandwidth limits"""
        profile = self.get_protocol_profile(protocol)
        if not profile:
            return False, "Protocol not enabled"
        
        # Check COMBINED limits (not individual protocol limits)
        if self.total_daily_limit_bytes > 0 and self.total_daily_used_bytes > self.total_daily_limit_bytes:
            return False, f"Daily limit exceeded (Used: {self.total_daily_used_bytes / (1024**3):.2f} GB, Limit: {self.total_daily_limit_bytes / (1024**3):.2f} GB)"
        
        if self.total_monthly_limit_bytes > 0 and self.total_monthly_used_bytes > self.total_monthly_limit_bytes:
            return False, f"Monthly limit exceeded (Used: {self.total_monthly_used_bytes / (1024**3):.2f} GB, Limit: {self.total_monthly_limit_bytes / (1024**3):.2f} GB)"
        
        return True, "Within limits"
    
    def reset_daily_usage(self):
        """Reset daily usage counters for all protocols"""
        self.total_daily_used_bytes = 0
        for profile in self.protocols.values():
            profile.daily_used_bytes = 0
        self.updated_at = datetime.now()
    
    def reset_monthly_usage(self):
        """Reset monthly usage counters for all protocols"""
        self.total_monthly_used_bytes = 0
        for profile in self.protocols.values():
            profile.monthly_used_bytes = 0
        self.updated_at = datetime.now()
    
    def reset_all_usage(self):
        """Reset all usage counters"""
        self.total_daily_used_bytes = 0
        self.total_monthly_used_bytes = 0
        self.total_used_bytes = 0
        for profile in self.protocols.values():
            profile.daily_used_bytes = 0
            profile.monthly_used_bytes = 0
            profile.total_used_bytes = 0
        self.updated_at = datetime.now()
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """Get comprehensive usage summary with individual and combined stats"""
        return {
            # Combined totals
            "combined": {
                "total_used_gb": self.total_used_bytes / (1024**3),
                "daily_used_gb": self.total_daily_used_bytes / (1024**3),
                "monthly_used_gb": self.total_monthly_used_bytes / (1024**3),
                "daily_limit_gb": self.total_daily_limit_bytes / (1024**3),
                "monthly_limit_gb": self.total_monthly_limit_bytes / (1024**3),
                "daily_percentage": (self.total_daily_used_bytes / self.total_daily_limit_bytes * 100) if self.total_daily_limit_bytes > 0 else 0,
                "monthly_percentage": (self.total_monthly_used_bytes / self.total_monthly_limit_bytes * 100) if self.total_monthly_limit_bytes > 0 else 0
            },
            # Individual protocol stats
            "protocols": {
                protocol.value: {
                    "daily_used_gb": profile.daily_used_bytes / (1024**3),
                    "monthly_used_gb": profile.monthly_used_bytes / (1024**3),
                    "total_used_gb": profile.total_used_bytes / (1024**3),
                    "is_active": profile.is_active,
                    "last_connected": profile.last_connected.isoformat() if profile.last_connected else None,
                    "connection_count": profile.connection_count,
                    "server_id": profile.server_id
                }
                for protocol, profile in self.protocols.items()
            },
            # Summary stats
            "summary": {
                "total_protocols": len(self.protocols),
                "active_protocols": len([p for p in self.protocols.values() if p.is_active]),
                "total_connections": sum(p.connection_count for p in self.protocols.values()),
                "last_activity": max([p.last_connected for p in self.protocols.values() if p.last_connected], default=None)
            }
        }
    
    def get_usage_breakdown(self) -> Dict[str, Any]:
        """Get detailed usage breakdown for display"""
        usage_data = self.get_usage_summary()
        
        # Calculate protocol percentages of total usage
        total_used = usage_data["combined"]["total_used_gb"]
        protocol_breakdown = {}
        
        for protocol_name, protocol_data in usage_data["protocols"].items():
            protocol_used = protocol_data["total_used_gb"]
            percentage = (protocol_used / total_used * 100) if total_used > 0 else 0
            
            protocol_breakdown[protocol_name] = {
                **protocol_data,
                "percentage_of_total": percentage,
                "color": self._get_protocol_color(protocol_name)
            }
        
        return {
            "combined": usage_data["combined"],
            "protocols": protocol_breakdown,
            "summary": usage_data["summary"]
        }
    
    def _get_protocol_color(self, protocol: str) -> str:
        """Get color for protocol visualization"""
        colors = {
            "wireguard": "#007bff",  # Blue
            "openvpn": "#28a745",    # Green
            "shadowsocks": "#ffc107", # Yellow
            "v2ray": "#dc3545",      # Red
            "trojan": "#6f42c1"      # Purple
        }
        return colors.get(protocol, "#6c757d")  # Default gray
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response"""
        usage_data = self.get_usage_breakdown()
        
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "enabled_protocols": [p.value for p in self.protocols.keys()],
            "usage_stats": usage_data,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "expire_date": self.expire_date.isoformat() if self.expire_date else None
        } 