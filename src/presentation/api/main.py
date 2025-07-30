from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import Response
import json
import os
import secrets
from datetime import datetime
import time
import logging
from pathlib import Path

# Setup logging
logger = logging.getLogger(__name__)

from ...infrastructure.database.sqlite_repository import (
    SQLiteUserRepository, 
    SQLiteServerRepository, 
    SQLiteClientRepository
)
from ...domain.services.auth_service import AuthService
from ...domain.services.vpn_service import VPNService
from ...application.use_cases.user_use_cases import (
    CreateUserUseCase, 
    UpdateUserUseCase, 
    DeleteUserUseCase, 
    GetUserUseCase, 
    ListUsersUseCase
)
from ...application.dto.auth_dto import (
    LoginRequest, LoginResponse, UserCreateRequest, UserUpdateRequest, 
    UserResponse, ChangePasswordRequest
)
from ...application.dto.vpn_dto import (
    ServerCreateRequest, ServerResponse, ClientCreateRequest, ClientResponse,
    DashboardStatsResponse
)
from ...domain.entities.user import User, UserRole

# Security imports
from ...infrastructure.security.csrf_protection import CSRFProtection
from ...infrastructure.security.rate_limiter import RateLimiter
from ...infrastructure.security.input_sanitizer import InputSanitizer
from ...infrastructure.security.audit_logger import AuditLogger

# Monitoring imports
from ...infrastructure.monitoring.performance_monitor import PerformanceMonitor
from ...infrastructure.monitoring.error_tracker import ErrorTracker

# Caching imports
from ...infrastructure.caching.redis_cache import RedisCache, CacheManager

# WebSocket and monitoring imports
from ...infrastructure.monitoring.websocket_manager import websocket_manager, TrafficData, ServerStatus
from ...infrastructure.monitoring.background_monitor import background_monitor
from ...infrastructure.traffic.bandwidth_manager import bandwidth_manager
from ...infrastructure.protocols.openvpn_auth import openvpn_auth_manager
from ...infrastructure.analytics.traffic_analytics import traffic_analytics, TrafficRecord
from ...infrastructure.security.rate_limiter import rate_limiter
from ...infrastructure.security.secret_manager import secret_manager
from ...infrastructure.security.log_monitor import log_monitor
from ...infrastructure.security.intrusion_detection import intrusion_detection
from ...infrastructure.security.log_aggregator import log_aggregator
from ...infrastructure.security.monitoring_alerts import monitoring_alerts
from ...infrastructure.backup.backup_manager import backup_manager

app = FastAPI(title="VPN Panel API", version="1.0.0")

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    try:
        # Get client identifier
        client_id = rate_limiter._get_client_identifier(request)
        
        # Determine rate limit type based on path
        path = request.url.path
        if path.startswith("/api/auth"):
            limit_type = "login"
        elif path.startswith("/api/admin"):
            limit_type = "admin_actions"
        elif path.startswith("/api/users") and request.method == "POST":
            limit_type = "user_creation"
        elif path.startswith("/api/configs"):
            limit_type = "config_download"
        elif path.startswith("/api/upload"):
            limit_type = "file_upload"
        else:
            limit_type = "api"
        
        # Check rate limit
        rate_limiter.check_client_rate_limit(request, limit_type)
        
        # Add rate limit headers to response
        response = await call_next(request)
        remaining, reset_time = rate_limiter.get_remaining_requests(client_id, limit_type)
        
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
        response.headers["X-RateLimit-Type"] = limit_type
        
        return response
        
    except HTTPException as e:
        if e.status_code == 429:
            # Rate limit exceeded
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": e.detail,
                    "retry_after": e.detail.get("remaining_block_seconds", 60)
                },
                headers={
                    "Retry-After": str(e.detail.get("remaining_block_seconds", 60)),
                    "X-RateLimit-Type": limit_type
                }
            )
        raise e
    except Exception as e:
        logger.error(f"Rate limiting error: {e}")
        return await call_next(request)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gzip compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Security
security = HTTPBearer()
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database
db_path = os.getenv("DB_PATH", "/var/lib/vpn-panel/vpn_panel.db")
user_repository = SQLiteUserRepository(db_path)
server_repository = SQLiteServerRepository(db_path)
client_repository = SQLiteClientRepository(db_path)

# Services
auth_service = AuthService(user_repository, SECRET_KEY)
vpn_service = VPNService(server_repository, client_repository)

# Use cases
create_user_use_case = CreateUserUseCase(user_repository)
update_user_use_case = UpdateUserUseCase(user_repository)
delete_user_use_case = DeleteUserUseCase(user_repository)
get_user_use_case = GetUserUseCase(user_repository)
list_users_use_case = ListUsersUseCase(user_repository)

# Security components
csrf_protection = CSRFProtection()
rate_limiter = RateLimiter()
input_sanitizer = InputSanitizer()
audit_logger = AuditLogger()

# Monitoring components
performance_monitor = PerformanceMonitor()
error_tracker = ErrorTracker()

# Caching components
redis_cache = RedisCache(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    password=os.getenv("REDIS_PASSWORD"),
    db=int(os.getenv("REDIS_DB", "0"))
)
cache_manager = CacheManager(redis_cache)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vpn-panel/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current user with security and monitoring"""
    start_time = time.time()
    
    try:
        user = auth_service.get_current_user(credentials.credentials)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Record performance metrics
        response_time = time.time() - start_time
        performance_monitor.record_request(response_time)
        
        return user
        
    except Exception as e:
        # Track error
        error_tracker.track_error(e, severity='medium')
        performance_monitor.record_request(time.time() - start_time, is_error=True)
        raise

def require_admin(user: User = Depends(get_current_user)) -> User:
    if not auth_service.require_admin(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("dashboard_live.html", {"request": request, "user": user})

@app.get("/servers", response_class=HTMLResponse)
async def servers_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("servers.html", {"request": request, "user": user})

@app.get("/clients", response_class=HTMLResponse)
async def clients_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("clients.html", {"request": request, "user": user})

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, admin: User = Depends(require_admin)):
    return templates.TemplateResponse("users.html", {"request": request, "user": admin})

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, admin: User = Depends(require_admin)):
    return templates.TemplateResponse("settings.html", {"request": request, "user": admin})

@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("analytics.html", {"request": request, "user": user})

@app.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request, user: User = Depends(get_current_user)):
    """Backup management page"""
    return templates.TemplateResponse("backup.html", {"request": request})

@app.get("/security", response_class=HTMLResponse)
async def security_page(request: Request, user: User = Depends(get_current_user)):
    """Security dashboard page"""
    return templates.TemplateResponse("security.html", {"request": request})

@app.post("/api/auth/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Login endpoint with security and monitoring"""
    start_time = time.time()
    
    try:
        # Rate limiting check
        client_ip = rate_limiter.get_client_ip(request)
        is_limited, error_msg = rate_limiter.is_rate_limited(client_ip)
        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=error_msg
            )
        
        # Input sanitization
        sanitized_username = input_sanitizer.sanitize_string(username)
        sanitized_password = input_sanitizer.sanitize_string(password)
        
        # Authentication
        user = auth_service.authenticate_user(sanitized_username, sanitized_password)
        if user is None:
            # Audit logging for failed login
            audit_logger.log_user_login(
                user_id="unknown",
                username=sanitized_username,
                ip_address=client_ip,
                user_agent=request.headers.get("User-Agent", "unknown"),
                success=False,
                error_message="Invalid credentials"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Create access token
        access_token = auth_service.create_access_token(
            data={"sub": user.username}
        )
        
        # Update last login
        user.update_last_login()
        user_repository.update(user)
        
        # Audit logging for successful login
        audit_logger.log_user_login(
            user_id=user.id,
            username=user.username,
            ip_address=client_ip,
            user_agent=request.headers.get("User-Agent", "unknown"),
            success=True
        )
        
        # Cache user data
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "status": user.status.value
        }
        cache_manager.cache_user_data(user.id, user_data)
        
        # Record performance metrics
        response_time = time.time() - start_time
        performance_monitor.record_request(response_time)
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            user=UserResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                role=user.role.value,
                status=user.status.value,
                created_at=user.created_at,
                updated_at=user.updated_at
            )
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Track error
        error_tracker.track_error(e, request, severity='high')
        performance_monitor.record_request(time.time() - start_time, is_error=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/users/me")
async def get_current_user_info(user: User = Depends(get_current_user)):
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role.value,
        status=user.status.value,
        created_at=user.created_at,
        last_login=user.last_login,
        expire_date=user.expire_date
    )

@app.get("/api/users")
async def get_users(admin: User = Depends(require_admin)):
    users = list_users_use_case.execute()
    return {"users": [
        UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role.value,
            status=user.status.value,
            created_at=user.created_at,
            last_login=user.last_login,
            expire_date=user.expire_date
        ).dict() for user in users
    ]}

@app.post("/api/users")
async def create_user(
    user_data: UserCreateRequest,
    admin: User = Depends(require_admin)
):
    user = create_user_use_case.execute(
        user_data.username,
        user_data.email,
        user_data.password,
        user_data.role
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User creation failed"
        )
    return {"message": "User created successfully", "user_id": user.id}

@app.get("/api/users/{user_id}")
async def get_user(user_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    user = get_user_use_case.execute(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role.value,
        status=user.status.value,
        created_at=user.created_at,
        last_login=user.last_login,
        expire_date=user.expire_date
    )

@app.put("/api/users/{user_id}")
async def update_user(
    user_id: str,
    user_data: UserUpdateRequest,
    admin: User = Depends(require_admin)
):
    update_data = {k: v for k, v in user_data.dict().items() if v is not None}
    success = update_user_use_case.execute(user_id, **update_data)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User update failed"
        )
    return {"message": "User updated successfully"}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, admin: User = Depends(require_admin)):
    success = delete_user_use_case.execute(user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User deletion failed"
        )
    return {"message": "User deleted successfully"}

@app.get("/api/servers")
async def get_servers(user: User = Depends(get_current_user)):
    servers = server_repository.find_all()
    return {"servers": [
        ServerResponse(
            id=server.id,
            name=server.name,
            protocol=server.protocol.value,
            port=server.port,
            interface=server.interface,
            status=server.status.value,
            created_at=server.created_at
        ).dict() for server in servers
    ]}

@app.post("/api/servers")
async def create_server(
    server_data: ServerCreateRequest,
    admin: User = Depends(require_admin)
):
    server = vpn_service.create_server(
        server_data.name,
        server_data.protocol,
        server_data.port,
        server_data.interface
    )
    if not server:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server creation failed"
        )
    return {"message": "Server created successfully", "server_id": server.id}

@app.get("/api/servers/{server_id}")
async def get_server(server_id: str, user: User = Depends(get_current_user)):
    server = server_repository.find_by_id(server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found"
        )
    
    return ServerResponse(
        id=server.id,
        name=server.name,
        protocol=server.protocol.value,
        port=server.port,
        interface=server.interface,
        status=server.status.value,
        created_at=server.created_at
    )

@app.post("/api/servers/{server_id}/start")
async def start_server(server_id: str, admin: User = Depends(require_admin)):
    success = vpn_service.start_server(server_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to start server"
        )
    return {"message": "Server started successfully"}

@app.post("/api/servers/{server_id}/stop")
async def stop_server(server_id: str, admin: User = Depends(require_admin)):
    success = vpn_service.stop_server(server_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to stop server"
        )
    return {"message": "Server stopped successfully"}

@app.get("/api/servers/{server_id}/status")
async def get_server_status(server_id: str, user: User = Depends(get_current_user)):
    status_data = vpn_service.get_server_status(server_id)
    return status_data

@app.get("/api/clients")
async def get_clients(user: User = Depends(get_current_user)):
    if user.role == UserRole.ADMIN:
        clients = client_repository.find_all()
    else:
        clients = client_repository.find_by_user_id(user.id)
    
    return {"clients": [
        ClientResponse(
            id=client.id,
            user_id=client.user_id,
            server_id=client.server_id,
            name=client.name,
            allowed_ips=client.allowed_ips,
            bandwidth_limit=client.bandwidth_limit,
            bandwidth_used=client.bandwidth_used,
            status=client.status.value,
            created_at=client.created_at,
            last_connected=client.last_connected,
            expire_date=client.expire_date
        ).dict() for client in clients
    ]}

@app.post("/api/clients")
async def create_client(
    client_data: ClientCreateRequest,
    user: User = Depends(get_current_user)
):
    if user.role != UserRole.ADMIN and user.id != client_data.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    client = vpn_service.create_client(
        client_data.user_id,
        client_data.server_id,
        client_data.name,
        client_data.bandwidth_limit,
        client_data.expire_date
    )
    if not client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client creation failed"
        )
    return {"message": "Client created successfully", "client_id": client.id}

@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: str, user: User = Depends(get_current_user)):
    client = client_repository.find_by_id(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )
    
    if user.role != UserRole.ADMIN and user.id != client.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    success = vpn_service.delete_client(client_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client deletion failed"
        )
    return {"message": "Client deleted successfully"}

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(user: User = Depends(get_current_user)):
    total_servers = server_repository.count()
    total_clients = client_repository.count()
    total_users = user_repository.count()
    
    # Count active connections (simplified)
    active_connections = len(client_repository.find_active_clients())
    
    # Get recent servers
    recent_servers = server_repository.find_all()[:5]
    
    return DashboardStatsResponse(
        total_servers=total_servers,
        total_clients=total_clients,
        total_users=total_users,
        active_connections=active_connections,
        recent_servers=[
            ServerResponse(
                id=server.id,
                name=server.name,
                protocol=server.protocol.value,
                port=server.port,
                interface=server.interface,
                status=server.status.value,
                created_at=server.created_at
            ) for server in recent_servers
        ]
    )

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie("token")
    return response

# WebSocket endpoints
@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates"""
    await websocket.accept()
    
    try:
        # Wait for authentication
        data = await websocket.receive_text()
        auth_data = json.loads(data)
        
        if auth_data.get("type") == "auth":
            token = auth_data.get("token")
            user = auth_service.get_current_user(token)
            
            if user:
                is_admin = auth_service.require_admin(user)
                await websocket_manager.connect(websocket, user.id, is_admin)
                
                # Send initial data
                await websocket.send_text(json.dumps({
                    "type": "connected",
                    "user_id": user.id,
                    "is_admin": is_admin
                }))
                
                # Keep connection alive
                while True:
                    try:
                        await websocket.receive_text()
                    except WebSocketDisconnect:
                        break
            else:
                await websocket.close(code=4001, reason="Authentication failed")
        else:
            await websocket.close(code=4000, reason="Invalid message format")
            
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        websocket_manager.disconnect(websocket, "unknown", False)

# Analytics endpoints
@app.get("/api/analytics/summary")
async def get_analytics_summary(
    period: str = "24h",
    user: User = Depends(get_current_user)
):
    """Get traffic analytics summary"""
    try:
        summary = traffic_analytics.get_traffic_summary(period)
        return {
            "period": summary.period,
            "total_traffic": summary.total_traffic,
            "total_connections": summary.total_connections,
            "avg_bandwidth": summary.avg_bandwidth,
            "peak_bandwidth": summary.peak_bandwidth,
            "top_clients": summary.top_clients[:5],
            "top_servers": summary.top_servers[:5],
            "traffic_by_hour": summary.traffic_by_hour
        }
    except Exception as e:
        logger.error(f"Error getting analytics summary: {e}")
        raise HTTPException(status_code=500, detail="Error getting analytics")

@app.get("/api/analytics/client/{client_id}")
async def get_client_analytics(
    client_id: str,
    period: str = "24h",
    user: User = Depends(get_current_user)
):
    """Get analytics for specific client"""
    try:
        analytics = traffic_analytics.get_client_analytics(client_id, period)
        return analytics
    except Exception as e:
        logger.error(f"Error getting client analytics: {e}")
        raise HTTPException(status_code=500, detail="Error getting client analytics")

@app.get("/api/analytics/server/{server_id}")
async def get_server_analytics(
    server_id: str,
    period: str = "24h",
    user: User = Depends(get_current_user)
):
    """Get analytics for specific server"""
    try:
        analytics = traffic_analytics.get_server_analytics(server_id, period)
        return analytics
    except Exception as e:
        logger.error(f"Error getting server analytics: {e}")
        raise HTTPException(status_code=500, detail="Error getting server analytics")

# Bandwidth management endpoints
@app.post("/api/bandwidth/limit")
async def set_bandwidth_limit(
    client_id: str,
    download_mbps: int,
    upload_mbps: int,
    daily_gb: int = 0,
    monthly_gb: int = 0,
    admin: User = Depends(require_admin)
):
    """Set bandwidth limit for client"""
    try:
        success = bandwidth_manager.set_client_bandwidth_limit(
            client_id, download_mbps, upload_mbps, daily_gb, monthly_gb
        )
        if success:
            return {"message": "Bandwidth limit set successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to set bandwidth limit")
    except Exception as e:
        logger.error(f"Error setting bandwidth limit: {e}")
        raise HTTPException(status_code=500, detail="Error setting bandwidth limit")

@app.delete("/api/bandwidth/limit/{client_id}")
async def remove_bandwidth_limit(
    client_id: str,
    admin: User = Depends(require_admin)
):
    """Remove bandwidth limit for client"""
    try:
        success = bandwidth_manager.remove_client_bandwidth_limit(client_id)
        if success:
            return {"message": "Bandwidth limit removed successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to remove bandwidth limit")
    except Exception as e:
        logger.error(f"Error removing bandwidth limit: {e}")
        raise HTTPException(status_code=500, detail="Error removing bandwidth limit")

# OpenVPN user management endpoints
@app.post("/api/openvpn/users")
async def create_openvpn_user(
    username: str,
    password: str,
    client_id: str = "",
    server_id: str = "",
    bandwidth_limit: int = 0,
    daily_limit: int = 0,
    admin: User = Depends(require_admin)
):
    """Create OpenVPN user"""
    try:
        success = openvpn_auth_manager.create_user(
            username, password, client_id, server_id, bandwidth_limit, daily_limit
        )
        if success:
            return {"message": "OpenVPN user created successfully"}
        else:
            raise HTTPException(status_code=400, detail="User already exists")
    except Exception as e:
        logger.error(f"Error creating OpenVPN user: {e}")
        raise HTTPException(status_code=500, detail="Error creating OpenVPN user")

@app.delete("/api/openvpn/users/{username}")
async def delete_openvpn_user(
    username: str,
    admin: User = Depends(require_admin)
):
    """Delete OpenVPN user"""
    try:
        success = openvpn_auth_manager.delete_user(username)
        if success:
            return {"message": "OpenVPN user deleted successfully"}
        else:
            raise HTTPException(status_code=400, detail="User not found")
    except Exception as e:
        logger.error(f"Error deleting OpenVPN user: {e}")
        raise HTTPException(status_code=500, detail="Error deleting OpenVPN user")

@app.get("/api/openvpn/users")
async def list_openvpn_users(admin: User = Depends(require_admin)):
    """List all OpenVPN users"""
    try:
        users = openvpn_auth_manager.get_all_users()
        return {"users": [asdict(user) for user in users]}
    except Exception as e:
        logger.error(f"Error listing OpenVPN users: {e}")
        raise HTTPException(status_code=500, detail="Error listing OpenVPN users")

# Analytics export endpoint
@app.get("/api/analytics/export")
async def export_analytics(
    start_date: str,
    end_date: str,
    format: str = "json",
    user: User = Depends(get_current_user)
):
    """Export analytics data"""
    try:
        from datetime import datetime
        
        start_dt = datetime.fromisoformat(start_date)
        end_dt = datetime.fromisoformat(end_date)
        
        exported_data = traffic_analytics.export_analytics(start_dt, end_dt, format)
        
        if format == "json":
            return Response(
                content=exported_data,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=vpn-analytics-{start_date}-{end_date}.json"}
            )
        else:
            return Response(
                content=exported_data,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=vpn-analytics-{start_date}-{end_date}.csv"}
            )
            
    except Exception as e:
        logger.error(f"Error exporting analytics: {e}")
        raise HTTPException(status_code=500, detail="Error exporting analytics")

# Rate limiting management endpoints
@app.get("/api/admin/rate-limits")
async def get_rate_limit_stats(user: User = Depends(get_current_user)):
    """Get rate limit statistics (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return rate_limiter.get_all_rate_limit_stats()

@app.post("/api/admin/rate-limits/reset")
async def reset_rate_limit(
    identifier: str,
    limit_type: str,
    user: User = Depends(get_current_user)
):
    """Reset rate limit for specific identifier (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        rate_limiter.reset_rate_limit(identifier, limit_type)
        return {"message": f"Rate limit reset for {identifier}, type: {limit_type}"}
    except Exception as e:
        logger.error(f"Rate limit reset error: {e}")
        raise HTTPException(status_code=500, detail="Reset failed")

@app.put("/api/admin/rate-limits/config")
async def update_rate_limit_config(
    limit_type: str,
    max_requests: int,
    window_seconds: int,
    block_duration: int = 0,
    user: User = Depends(get_current_user)
):
    """Update rate limit configuration (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        from ...infrastructure.security.rate_limiter import RateLimitConfig
        config = RateLimitConfig(max_requests, window_seconds, block_duration)
        rate_limiter.update_rate_limit_config(limit_type, config)
        return {"message": f"Rate limit config updated for {limit_type}"}
    except Exception as e:
        logger.error(f"Rate limit config update error: {e}")
        raise HTTPException(status_code=500, detail="Update failed")

# Secret management endpoints
@app.get("/api/admin/secrets/summary")
async def get_secrets_summary(user: User = Depends(get_current_user)):
    """Get secrets summary (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return secret_manager.get_secrets_summary()

@app.post("/api/admin/secrets/rotate")
async def rotate_secret(
    key: str,
    user: User = Depends(get_current_user)
):
    """Rotate specific secret key (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        secret_manager.rotate_secret(key)
        return {"message": f"Secret key {key} rotated successfully"}
    except Exception as e:
        logger.error(f"Secret rotation error: {e}")
        raise HTTPException(status_code=500, detail="Rotation failed")

@app.post("/api/admin/secrets/rotate-all")
async def rotate_all_secrets(user: User = Depends(get_current_user)):
    """Rotate all secret keys (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        secret_manager.rotate_all_secrets()
        return {"message": "All secret keys rotated successfully"}
    except Exception as e:
        logger.error(f"All secrets rotation error: {e}")
        raise HTTPException(status_code=500, detail="Rotation failed")

# Backup management endpoints
@app.post("/api/admin/backups/full")
async def create_full_backup(
    description: str = "",
    user: User = Depends(get_current_user)
):
    """Create full system backup (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_info = backup_manager.create_full_backup(description)
        return {
            "message": "Full backup created successfully",
            "backup_id": backup_info.backup_id,
            "size_mb": backup_info.size_bytes / (1024 * 1024)
        }
    except Exception as e:
        logger.error(f"Full backup error: {e}")
        raise HTTPException(status_code=500, detail="Backup creation failed")

@app.post("/api/admin/backups/database")
async def create_database_backup(
    description: str = "",
    user: User = Depends(get_current_user)
):
    """Create database-only backup (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_info = backup_manager.create_database_backup(description)
        return {
            "message": "Database backup created successfully",
            "backup_id": backup_info.backup_id,
            "size_mb": backup_info.size_bytes / (1024 * 1024)
        }
    except Exception as e:
        logger.error(f"Database backup error: {e}")
        raise HTTPException(status_code=500, detail="Backup creation failed")

@app.post("/api/admin/backups/config")
async def create_config_backup(
    description: str = "",
    user: User = Depends(get_current_user)
):
    """Create configuration-only backup (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_info = backup_manager.create_config_backup(description)
        return {
            "message": "Config backup created successfully",
            "backup_id": backup_info.backup_id,
            "size_mb": backup_info.size_bytes / (1024 * 1024)
        }
    except Exception as e:
        logger.error(f"Config backup error: {e}")
        raise HTTPException(status_code=500, detail="Backup creation failed")

@app.get("/api/admin/backups")
async def list_backups(user: User = Depends(get_current_user)):
    """List all backups (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backups = backup_manager.list_backups()
        return {
            "backups": [
                {
                    "backup_id": b.backup_id,
                    "timestamp": b.timestamp.isoformat(),
                    "size_mb": b.size_bytes / (1024 * 1024),
                    "type": b.type,
                    "description": b.description,
                    "status": b.status
                }
                for b in backups
            ]
        }
    except Exception as e:
        logger.error(f"List backups error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list backups")

@app.get("/api/admin/backups/{backup_id}")
async def get_backup_info(
    backup_id: str,
    user: User = Depends(get_current_user)
):
    """Get backup information (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_info = backup_manager.get_backup_info(backup_id)
        if not backup_info:
            raise HTTPException(status_code=404, detail="Backup not found")
        
        return {
            "backup_id": backup_info.backup_id,
            "timestamp": backup_info.timestamp.isoformat(),
            "size_mb": backup_info.size_bytes / (1024 * 1024),
            "type": backup_info.type,
            "description": backup_info.description,
            "status": backup_info.status
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get backup info error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup info")

@app.post("/api/admin/backups/{backup_id}/restore")
async def restore_backup(
    backup_id: str,
    restore_type: str = "full",
    user: User = Depends(get_current_user)
):
    """Restore from backup (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        success = backup_manager.restore_backup(backup_id, restore_type)
        if success:
            return {"message": f"Backup {backup_id} restored successfully"}
        else:
            raise HTTPException(status_code=500, detail="Restore failed")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Backup not found")
    except Exception as e:
        logger.error(f"Restore error: {e}")
        raise HTTPException(status_code=500, detail="Restore failed")

@app.delete("/api/admin/backups/{backup_id}")
async def delete_backup(
    backup_id: str,
    user: User = Depends(get_current_user)
):
    """Delete backup (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        success = backup_manager.delete_backup(backup_id)
        if success:
            return {"message": f"Backup {backup_id} deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Backup not found")
    except Exception as e:
        logger.error(f"Delete backup error: {e}")
        raise HTTPException(status_code=500, detail="Delete failed")

@app.get("/api/admin/backups/stats")
async def get_backup_stats(user: User = Depends(get_current_user)):
    """Get backup statistics (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        stats = backup_manager.get_backup_stats()
        return stats
    except Exception as e:
        logger.error(f"Backup stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup stats")

@app.post("/api/admin/backups/cleanup")
async def cleanup_old_backups(
    days: int = 30,
    user: User = Depends(get_current_user)
):
    """Clean up old backups (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        deleted_count = backup_manager.cleanup_old_backups(days)
        return {"message": f"Cleaned up {deleted_count} old backups"}
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        raise HTTPException(status_code=500, detail="Cleanup failed")

@app.get("/api/admin/backups/{backup_id}/download")
async def download_backup(
    backup_id: str,
    user: User = Depends(get_current_user)
):
    """Download backup file (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_info = backup_manager.get_backup_info(backup_id)
        if not backup_info:
            raise HTTPException(status_code=404, detail="Backup not found")
        
        backup_path = Path(backup_info.file_path)
        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        from fastapi.responses import FileResponse
        return FileResponse(
            path=backup_path,
            filename=f"{backup_id}.zip",
            media_type="application/zip"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download backup error: {e}")
        raise HTTPException(status_code=500, detail="Download failed")

# Security monitoring endpoints
@app.get("/api/admin/security/stats")
async def get_security_stats(user: User = Depends(get_current_user)):
    """Get security statistics (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        stats = log_monitor.get_security_stats()
        return stats
    except Exception as e:
        logger.error(f"Security stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security stats")

@app.get("/api/admin/security/events")
async def get_security_events(
    hours: int = 24,
    user: User = Depends(get_current_user)
):
    """Get recent security events (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        events = log_monitor.get_recent_events(hours)
        return {"events": events}
    except Exception as e:
        logger.error(f"Security events error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security events")

@app.get("/api/admin/security/blocked-ips")
async def get_blocked_ips(user: User = Depends(get_current_user)):
    """Get list of blocked IP addresses (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        blocked_ips = log_monitor.get_blocked_ips()
        return {"blocked_ips": blocked_ips}
    except Exception as e:
        logger.error(f"Blocked IPs error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get blocked IPs")

@app.post("/api/admin/security/unblock-ip")
async def unblock_ip(
    ip_address: str,
    user: User = Depends(get_current_user)
):
    """Unblock IP address (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        success = log_monitor.unblock_ip(ip_address)
        if success:
            return {"message": f"IP {ip_address} unblocked successfully"}
        else:
            raise HTTPException(status_code=404, detail="IP not found in blocked list")
    except Exception as e:
        logger.error(f"Unblock IP error: {e}")
        raise HTTPException(status_code=500, detail="Failed to unblock IP")

@app.get("/api/admin/security/permissions")
async def check_security_permissions(user: User = Depends(get_current_user)):
    """Check security permissions (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        permissions = intrusion_detection.check_security_permissions()
        return {"permissions": permissions}
    except Exception as e:
        logger.error(f"Security permissions error: {e}")
        raise HTTPException(status_code=500, detail="Failed to check permissions")

@app.post("/api/admin/security/fix-permissions")
async def fix_security_permissions(user: User = Depends(get_current_user)):
    """Fix security permissions (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        intrusion_detection.fix_permissions()
        return {"message": "Security permissions fixed successfully"}
    except Exception as e:
        logger.error(f"Fix permissions error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fix permissions")

@app.get("/api/admin/security/baseline")
async def get_security_baseline(user: User = Depends(get_current_user)):
    """Get security baseline (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        baseline = intrusion_detection.get_system_baseline()
        return {"baseline": baseline}
    except Exception as e:
        logger.error(f"Security baseline error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security baseline")

@app.get("/api/admin/security/verify-baseline")
async def verify_security_baseline(user: User = Depends(get_current_user)):
    """Verify security baseline (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        verification = intrusion_detection.verify_baseline()
        return {"verification": verification}
    except Exception as e:
        logger.error(f"Baseline verification error: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify baseline")

# Log aggregation endpoints
@app.get("/api/admin/logs/collect")
async def collect_logs(
    hours: int = 24,
    user: User = Depends(get_current_user)
):
    """Collect logs from all sources (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        result = log_aggregator.collect_logs(hours)
        return result
    except Exception as e:
        logger.error(f"Log collection error: {e}")
        raise HTTPException(status_code=500, detail="Failed to collect logs")

@app.get("/api/admin/logs/search")
async def search_logs(
    query: str,
    hours: int = 24,
    level: str = None,
    user: User = Depends(get_current_user)
):
    """Search logs (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        results = log_aggregator.search_logs(query, hours, level)
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Log search error: {e}")
        raise HTTPException(status_code=500, detail="Failed to search logs")

@app.get("/api/admin/logs/stats")
async def get_log_statistics(
    hours: int = 24,
    user: User = Depends(get_current_user)
):
    """Get log statistics (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        stats = log_aggregator.get_log_statistics(hours)
        return stats
    except Exception as e:
        logger.error(f"Log statistics error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get log statistics")

@app.get("/api/admin/logs/export")
async def export_logs(
    format: str = "json",
    hours: int = 24,
    user: User = Depends(get_current_user)
):
    """Export logs (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        file_path = log_aggregator.export_logs(format, hours)
        if file_path:
            return FileResponse(file_path, filename=f"logs_export.{format}")
        else:
            raise HTTPException(status_code=500, detail="Failed to export logs")
    except Exception as e:
        logger.error(f"Log export error: {e}")
        raise HTTPException(status_code=500, detail="Failed to export logs")

# Monitoring alerts endpoints
@app.get("/api/admin/alerts")
async def get_alerts(
    severity: str = None,
    acknowledged: bool = None,
    hours: int = 24,
    user: User = Depends(get_current_user)
):
    """Get monitoring alerts (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        alerts = monitoring_alerts.get_alerts(severity, acknowledged, hours)
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Get alerts error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")

@app.post("/api/admin/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    user: User = Depends(get_current_user)
):
    """Acknowledge an alert (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        success = monitoring_alerts.acknowledge_alert(alert_id)
        if success:
            return {"message": "Alert acknowledged successfully"}
        else:
            raise HTTPException(status_code=404, detail="Alert not found")
    except Exception as e:
        logger.error(f"Acknowledge alert error: {e}")
        raise HTTPException(status_code=500, detail="Failed to acknowledge alert")

@app.post("/api/admin/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    user: User = Depends(get_current_user)
):
    """Resolve an alert (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        success = monitoring_alerts.resolve_alert(alert_id)
        if success:
            return {"message": "Alert resolved successfully"}
        else:
            raise HTTPException(status_code=404, detail="Alert not found")
    except Exception as e:
        logger.error(f"Resolve alert error: {e}")
        raise HTTPException(status_code=500, detail="Failed to resolve alert")

@app.get("/api/admin/alerts/stats")
async def get_alert_statistics(user: User = Depends(get_current_user)):
    """Get alert statistics (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        stats = monitoring_alerts.get_alert_statistics()
        return stats
    except Exception as e:
        logger.error(f"Alert statistics error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alert statistics")

@app.post("/api/admin/alerts/rules/{rule_name}/enable")
async def enable_alert_rule(
    rule_name: str,
    user: User = Depends(get_current_user)
):
    """Enable alert rule (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        monitoring_alerts.enable_alert_rule(rule_name)
        return {"message": f"Alert rule {rule_name} enabled successfully"}
    except Exception as e:
        logger.error(f"Enable alert rule error: {e}")
        raise HTTPException(status_code=500, detail="Failed to enable alert rule")

@app.post("/api/admin/alerts/rules/{rule_name}/disable")
async def disable_alert_rule(
    rule_name: str,
    user: User = Depends(get_current_user)
):
    """Disable alert rule (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        monitoring_alerts.disable_alert_rule(rule_name)
        return {"message": f"Alert rule {rule_name} disabled successfully"}
    except Exception as e:
        logger.error(f"Disable alert rule error: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable alert rule")

@app.get("/api/admin/alerts/rules")
async def get_alert_rules(user: User = Depends(get_current_user)):
    """Get alert rules (admin only)"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        rules = monitoring_alerts.get_alert_rules()
        return {"alert_rules": rules}
    except Exception as e:
        logger.error(f"Get alert rules error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alert rules")

# Start background monitoring
@app.on_event("startup")
async def start_background_monitor():
    await background_monitor.start_monitoring()

if __name__ == "__main__":
    import uvicorn
    import asyncio
    
    # Start background monitoring
    async def start_background_monitor():
        await background_monitor.start_monitoring()
    
    # Run background monitor in separate task
    loop = asyncio.get_event_loop()
    loop.create_task(start_background_monitor())
    
    uvicorn.run(app, host="0.0.0.0", port=8000) 