from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, WebSocket, WebSocketDisconnect
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

app = FastAPI(title="VPN Panel API", version="1.0.0")

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