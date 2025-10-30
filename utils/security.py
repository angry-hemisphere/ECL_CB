from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, 
    verify_jwt_in_request, 
    get_jwt_identity,
    get_jwt
)
from models.user_model import User
from utils.db import db
from datetime import datetime, timedelta
import secrets
import re


def hash_password(password):
    """Hash a password using werkzeug's security functions"""
    return generate_password_hash(password, method='pbkdf2:sha256')


def verify_password(password, hashed_password):
    """Verify a password against its hash"""
    return check_password_hash(hashed_password, password)


def generate_jwt_token(identity, additional_claims=None):
    """Generate JWT access token with optional additional claims"""
    return create_access_token(
        identity=identity, 
        additional_claims=additional_claims or {}
    )


def get_current_user():
    """Get current user email from JWT token"""
    try:
        verify_jwt_in_request()
        return get_jwt_identity()
    except Exception:
        return None


def get_current_user_details():
    """Get full user details from database"""
    user_email = get_current_user()
    if user_email:
        user = db.session.query(User).filter(User.email == user_email).first()
        return user
    return None


def get_current_tenant():
    """Get tenant_id of current user"""
    user_email = get_current_user()
    if user_email:
        tenant_id = db.session.query(User.tenant_id).filter(
            User.email == user_email
        ).scalar()
        return tenant_id
    return None


def get_current_user_id():
    """Get user_id of current user"""
    user_email = get_current_user()
    if user_email:
        user_id = db.session.query(User.user_id).filter(
            User.email == user_email
        ).scalar()
        return user_id
    return None


def get_current_user_role():
    """Get role of current user"""
    user_email = get_current_user()
    if user_email:
        role = db.session.query(User.role).filter(
            User.email == user_email
        ).scalar()
        return role
    return None


def normalize_email(email):
    """Normalize email address to lowercase"""
    return email.strip().lower()


def check_failed_attempts(current_attempts, max_attempts=3):
    """Check if user has exceeded maximum failed login attempts"""
    return current_attempts >= max_attempts


def generate_reset_token():
    """Generate secure random token for password reset"""
    return secrets.token_urlsafe(32)


def calculate_token_expiry(minutes=15):
    """Calculate token expiry time"""
    return datetime.utcnow() + timedelta(minutes=minutes)


def is_token_valid(token, stored_token, expiry_time):
    """Validate reset token"""
    if not token or not stored_token or not expiry_time:
        return False
    return (
        token == stored_token and 
        expiry_time > datetime.utcnow()
    )


def validate_password_strength(password):
    """
    Validate password strength
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"