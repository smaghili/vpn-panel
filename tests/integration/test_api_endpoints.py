import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
import json

from src.presentation.api.main import app
from src.domain.entities.user import User, UserRole, UserStatus

class TestAPIEndpoints:
    @pytest.fixture
    def client(self):
        return TestClient(app)
    
    @pytest.fixture
    def mock_user(self):
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at="2023-01-01T00:00:00",
            updated_at="2023-01-01T00:00:00"
        )
    
    @pytest.fixture
    def mock_admin_user(self):
        return User(
            id="admin-user-id",
            username="admin",
            email="admin@example.com",
            password_hash="hashed_password",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
            created_at="2023-01-01T00:00:00",
            updated_at="2023-01-01T00:00:00"
        )
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
    
    def test_login_success(self, client):
        """Test successful login"""
        with patch('src.presentation.api.main.auth_service.authenticate_user') as mock_auth:
            mock_auth.return_value = self.mock_user()
            
            with patch('src.presentation.api.main.auth_service.create_access_token') as mock_token:
                mock_token.return_value = "test-token"
                
                response = client.post("/api/auth/login", data={
                    "username": "testuser",
                    "password": "testpassword"
                })
                
                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data
                assert data["access_token"] == "test-token"
                assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        with patch('src.presentation.api.main.auth_service.authenticate_user') as mock_auth:
            mock_auth.return_value = None
            
            response = client.post("/api/auth/login", data={
                "username": "testuser",
                "password": "wrongpassword"
            })
            
            assert response.status_code == 401
            data = response.json()
            assert "detail" in data
            assert "Incorrect username or password" in data["detail"]
    
    def test_get_current_user_info(self, client, mock_user):
        """Test getting current user info"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_user
            
            response = client.get("/api/users/me", headers={
                "Authorization": "Bearer test-token"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert data["username"] == "testuser"
            assert data["email"] == "test@example.com"
            assert data["role"] == "user"
    
    def test_get_current_user_unauthorized(self, client):
        """Test getting current user without token"""
        response = client.get("/api/users/me")
        assert response.status_code == 422  # Validation error for missing token
    
    def test_get_users_admin_access(self, client, mock_admin_user):
        """Test getting users list with admin access"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_admin_user
            
            with patch('src.presentation.api.main.list_users_use_case.execute') as mock_list:
                mock_list.return_value = [mock_admin_user]
                
                response = client.get("/api/users", headers={
                    "Authorization": "Bearer admin-token"
                })
                
                assert response.status_code == 200
                data = response.json()
                assert "users" in data
                assert len(data["users"]) == 1
    
    def test_get_users_non_admin_access(self, client, mock_user):
        """Test getting users list without admin access"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_user
            
            response = client.get("/api/users", headers={
                "Authorization": "Bearer user-token"
            })
            
            assert response.status_code == 403
            data = response.json()
            assert "detail" in data
            assert "Admin access required" in data["detail"]
    
    def test_create_user_admin_access(self, client, mock_admin_user):
        """Test creating user with admin access"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_admin_user
            
            with patch('src.presentation.api.main.create_user_use_case.execute') as mock_create:
                mock_create.return_value = self.mock_user()
                
                user_data = {
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "newpassword",
                    "role": "user"
                }
                
                response = client.post("/api/users", 
                    json=user_data,
                    headers={"Authorization": "Bearer admin-token"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert "message" in data
                assert "User created successfully" in data["message"]
    
    def test_create_user_validation_error(self, client, mock_admin_user):
        """Test creating user with validation error"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_admin_user
            
            # Missing required fields
            user_data = {
                "username": "newuser"
                # Missing email and password
            }
            
            response = client.post("/api/users", 
                json=user_data,
                headers={"Authorization": "Bearer admin-token"}
            )
            
            assert response.status_code == 422  # Validation error
    
    def test_get_servers(self, client, mock_user):
        """Test getting servers list"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_user
            
            with patch('src.presentation.api.main.server_repository.find_all') as mock_find:
                mock_find.return_value = []
                
                response = client.get("/api/servers", headers={
                    "Authorization": "Bearer user-token"
                })
                
                assert response.status_code == 200
                data = response.json()
                assert "servers" in data
                assert isinstance(data["servers"], list)
    
    def test_get_clients(self, client, mock_user):
        """Test getting clients list"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_user
            
            with patch('src.presentation.api.main.client_repository.find_by_user_id') as mock_find:
                mock_find.return_value = []
                
                response = client.get("/api/clients", headers={
                    "Authorization": "Bearer user-token"
                })
                
                assert response.status_code == 200
                data = response.json()
                assert "clients" in data
                assert isinstance(data["clients"], list)
    
    def test_dashboard_stats(self, client, mock_user):
        """Test getting dashboard statistics"""
        with patch('src.presentation.api.main.auth_service.get_current_user') as mock_get_user:
            mock_get_user.return_value = mock_user
            
            with patch('src.presentation.api.main.server_repository.count') as mock_server_count:
                mock_server_count.return_value = 5
                
                with patch('src.presentation.api.main.client_repository.count') as mock_client_count:
                    mock_client_count.return_value = 10
                    
                    with patch('src.presentation.api.main.user_repository.count') as mock_user_count:
                        mock_user_count.return_value = 3
                        
                        response = client.get("/api/dashboard/stats", headers={
                            "Authorization": "Bearer user-token"
                        })
                        
                        assert response.status_code == 200
                        data = response.json()
                        assert "total_servers" in data
                        assert "total_clients" in data
                        assert "total_users" in data
                        assert data["total_servers"] == 5
                        assert data["total_clients"] == 10
                        assert data["total_users"] == 3 