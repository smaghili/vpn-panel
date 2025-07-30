from fastapi import Request, HTTPException, status
from fastapi.responses import Response
import secrets
import hashlib
from typing import Optional

class CSRFProtection:
    def __init__(self):
        self.token_length = 32
        self.session_tokens = {}
    
    def generate_token(self, session_id: str) -> str:
        """Generate a new CSRF token for the session"""
        token = secrets.token_urlsafe(self.token_length)
        self.session_tokens[session_id] = token
        return token
    
    def validate_token(self, session_id: str, token: str) -> bool:
        """Validate the CSRF token"""
        stored_token = self.session_tokens.get(session_id)
        return stored_token and secrets.compare_digest(stored_token, token)
    
    def get_session_id(self, request: Request) -> str:
        """Extract session ID from request"""
        return request.cookies.get("session_id", "")
    
    def add_csrf_header(self, response: Response, token: str):
        """Add CSRF token to response headers"""
        response.headers["X-CSRF-Token"] = token 