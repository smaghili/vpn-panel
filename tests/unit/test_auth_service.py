import pytest
import bcrypt
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import jwt

from src.domain.services.auth_service import AuthService
from src.domain.entities.user import User, UserRole, UserStatus

class TestAuthService:
    @pytest.fixture
    def mock_user_repository(self):
        return Mock()
    
    @pytest.fixture
    def auth_service(self, mock_user_repository):
        return AuthService(mock_user_repository, "test-secret-key")
    
    @pytest.fixture
    def sample_user(self):
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            password_hash=bcrypt.hashpw("testpassword".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    
    def test_hash_password(self, auth_service):
        """Test password hashing"""
        password = "testpassword"
        hashed = auth_service.hash_password(password)
        
        assert hashed != password
        assert bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def test_verify_password_correct(self, auth_service, sample_user):
        """Test password verification with correct password"""
        password = "testpassword"
        result = auth_service.verify_password(password, sample_user.password_hash)
        assert result is True
    
    def test_verify_password_incorrect(self, auth_service, sample_user):
        """Test password verification with incorrect password"""
        password = "wrongpassword"
        result = auth_service.verify_password(password, sample_user.password_hash)
        assert result is False
    
    def test_authenticate_user_success(self, auth_service, sample_user, mock_user_repository):
        """Test successful user authentication"""
        mock_user_repository.find_by_username.return_value = sample_user
        
        result = auth_service.authenticate_user("testuser", "testpassword")
        
        assert result is not None
        assert result.username == "testuser"
        mock_user_repository.find_by_username.assert_called_once_with("testuser")
    
    def test_authenticate_user_invalid_username(self, auth_service, mock_user_repository):
        """Test authentication with invalid username"""
        mock_user_repository.find_by_username.return_value = None
        
        result = auth_service.authenticate_user("nonexistent", "testpassword")
        
        assert result is None
        mock_user_repository.find_by_username.assert_called_once_with("nonexistent")
    
    def test_authenticate_user_invalid_password(self, auth_service, sample_user, mock_user_repository):
        """Test authentication with invalid password"""
        mock_user_repository.find_by_username.return_value = sample_user
        
        result = auth_service.authenticate_user("testuser", "wrongpassword")
        
        assert result is None
        mock_user_repository.find_by_username.assert_called_once_with("testuser")
    
    def test_authenticate_user_inactive_status(self, auth_service, sample_user, mock_user_repository):
        """Test authentication with inactive user"""
        sample_user.status = UserStatus.INACTIVE
        mock_user_repository.find_by_username.return_value = sample_user
        
        result = auth_service.authenticate_user("testuser", "testpassword")
        
        assert result is None
    
    def test_create_access_token(self, auth_service):
        """Test JWT token creation"""
        data = {"sub": "testuser"}
        token = auth_service.create_access_token(data)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Verify token can be decoded
        decoded = jwt.decode(token, auth_service.secret_key, algorithms=[auth_service.algorithm])
        assert decoded["sub"] == "testuser"
    
    def test_create_access_token_with_expiry(self, auth_service):
        """Test JWT token creation with custom expiry"""
        data = {"sub": "testuser"}
        expiry = timedelta(hours=2)
        token = auth_service.create_access_token(data, expires_delta=expiry)
        
        decoded = jwt.decode(token, auth_service.secret_key, algorithms=[auth_service.algorithm])
        assert decoded["sub"] == "testuser"
        
        # Check expiry time
        exp_time = datetime.fromtimestamp(decoded["exp"])
        now = datetime.now()
        assert exp_time > now + timedelta(hours=1)
    
    def test_verify_token_valid(self, auth_service):
        """Test valid token verification"""
        data = {"sub": "testuser"}
        token = auth_service.create_access_token(data)
        
        result = auth_service.verify_token(token)
        
        assert result is not None
        assert result["sub"] == "testuser"
    
    def test_verify_token_invalid(self, auth_service):
        """Test invalid token verification"""
        result = auth_service.verify_token("invalid-token")
        assert result is None
    
    def test_verify_token_expired(self, auth_service):
        """Test expired token verification"""
        data = {"sub": "testuser"}
        token = auth_service.create_access_token(data, expires_delta=timedelta(seconds=-1))
        
        result = auth_service.verify_token(token)
        assert result is None
    
    def test_get_current_user_valid(self, auth_service, sample_user, mock_user_repository):
        """Test getting current user with valid token"""
        token = auth_service.create_access_token({"sub": "testuser"})
        mock_user_repository.find_by_username.return_value = sample_user
        
        result = auth_service.get_current_user(token)
        
        assert result is not None
        assert result.username == "testuser"
        mock_user_repository.find_by_username.assert_called_once_with("testuser")
    
    def test_get_current_user_invalid_token(self, auth_service):
        """Test getting current user with invalid token"""
        result = auth_service.get_current_user("invalid-token")
        assert result is None
    
    def test_get_current_user_user_not_found(self, auth_service, mock_user_repository):
        """Test getting current user when user doesn't exist"""
        token = auth_service.create_access_token({"sub": "nonexistent"})
        mock_user_repository.find_by_username.return_value = None
        
        result = auth_service.get_current_user(token)
        assert result is None
    
    def test_require_admin_admin_user(self, auth_service, sample_user):
        """Test admin requirement with admin user"""
        sample_user.role = UserRole.ADMIN
        result = auth_service.require_admin(sample_user)
        assert result is True
    
    def test_require_admin_regular_user(self, auth_service, sample_user):
        """Test admin requirement with regular user"""
        sample_user.role = UserRole.USER
        result = auth_service.require_admin(sample_user)
        assert result is False 