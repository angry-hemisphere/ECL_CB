from datetime import datetime
from utils.db import db
from models.user_model import User
from utils.security import (
    hash_password, 
    verify_password, 
    generate_jwt_token,
    normalize_email,
    check_failed_attempts,
    generate_reset_token,
    calculate_token_expiry,
    is_token_valid
)
from utils.validator import (
    validate_email_format,
    validate_required_fields
)
from config import Config
import logging


logger = logging.getLogger(__name__)


class AuthService:
    """Authentication service for ECL System"""
    
    @staticmethod
    def login(email, password, remember_me=False):
        """
        Authenticate user and return JWT token
        
        Args:
            email (str): User email
            password (str): User password
            remember_me (bool): Extend token expiry
            
        Returns:
            dict: Response with success status, token, and user data
        """
        try:
            # Validate input
            if not email or not password:
                return {
                    'success': False,
                    'error': 'Email and password are required'
                }, 400
            
            # Normalize email
            email = normalize_email(email)
            
            # Validate email format
            is_valid, normalized_email, error = validate_email_format(email)
            if not is_valid:
                return {
                    'success': False,
                    'error': 'Invalid email format'
                }, 400
            
            # Find user
            user = User.query.filter_by(email=normalized_email).first()
            
            if not user:
                logger.warning(f"Login attempt for non-existent user: {normalized_email}")
                return {
                    'success': False,
                    'error': 'Invalid email or password'
                }, 401
            
            # Check if account is locked
            if user.status == 'locked':
                logger.warning(f"Login attempt for locked account: {normalized_email}")
                return {
                    'success': False,
                    'error': 'Account is locked. Please contact administrator.'
                }, 403
            
            # Check if account is inactive
            if user.status == 'inactive':
                logger.warning(f"Login attempt for inactive account: {normalized_email}")
                return {
                    'success': False,
                    'error': 'Account is inactive. Please contact administrator.'
                }, 403
            
            # Verify password
            if not verify_password(password, user.password_hash):
                # Increment failed attempts
                user.failed_attempts += 1
                
                # Lock account if max attempts exceeded
                if check_failed_attempts(user.failed_attempts, Config.MAX_LOGIN_ATTEMPTS):
                    user.status = 'locked'
                    db.session.commit()
                    logger.warning(f"Account locked due to failed attempts: {normalized_email}")
                    return {
                        'success': False,
                        'error': f'Account locked due to {Config.MAX_LOGIN_ATTEMPTS} failed login attempts. Please contact administrator.'
                    }, 403
                
                db.session.commit()
                remaining = Config.MAX_LOGIN_ATTEMPTS - user.failed_attempts
                logger.warning(f"Failed login attempt for {normalized_email}. Attempts remaining: {remaining}")
                
                return {
                    'success': False,
                    'error': 'Invalid email or password',
                    'attemptsRemaining': remaining
                }, 401
            
            # Successful login - reset failed attempts
            user.failed_attempts = 0
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Generate JWT token with user claims
            additional_claims = {
                'user_id': user.user_id,
                'tenant_id': user.tenant_id,
                'role': user.role,
                'email': user.email
            }
            
            access_token = generate_jwt_token(
                identity=user.email,
                additional_claims=additional_claims
            )
            
            logger.info(f"Successful login for user: {normalized_email}")
            
            return {
                'success': True,
                'message': 'Login successful',
                'accessToken': access_token,
                'user': user.to_dict()
            }, 200
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'error': 'An error occurred during login. Please try again.'
            }, 500
    
    @staticmethod
    def logout():
        """
        Logout user (client-side cookie deletion)
        Server-side token blacklisting can be added later
        """
        return {
            'success': True,
            'message': 'Logout successful'
        }, 200
    
    @staticmethod
    def get_user_profile(user_email):
        """Get user profile by email"""
        try:
            user = User.query.filter_by(email=user_email).first()
            
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }, 404
            
            return {
                'success': True,
                'user': user.to_dict()
            }, 200
            
        except Exception as e:
            logger.error(f"Get profile error: {str(e)}")
            return {
                'success': False,
                'error': 'An error occurred'
            }, 500
    
    @staticmethod
    def request_password_reset(email):
        """
        Generate password reset token
        TODO: Send email with reset link
        """
        try:
            email = normalize_email(email)
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Don't reveal if user exists
                return {
                    'success': True,
                    'message': 'If the email exists, a reset link will be sent.'
                }, 200
            
            # Generate reset token
            token = generate_reset_token()
            user.password_reset_token = token
            user.token_expiry = calculate_token_expiry(minutes=15)
            db.session.commit()
            
            # TODO: Send email with reset link
            # reset_link = f"{Config.FRONTEND_BASE_URL}/reset-password?token={token}"
            # send_password_reset_email(user.email, reset_link)
            
            logger.info(f"Password reset requested for: {email}")
            
            return {
                'success': True,
                'message': 'Password reset link sent to your email',
                'token': token  # Remove this in production
            }, 200
            
        except Exception as e:
            logger.error(f"Password reset request error: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'error': 'An error occurred'
            }, 500
    
    @staticmethod
    def reset_password(token, new_password):
        """Reset password using token"""
        try:
            user = User.query.filter_by(password_reset_token=token).first()
            
            if not user:
                return {
                    'success': False,
                    'error': 'Invalid or expired reset token'
                }, 400
            
            if not is_token_valid(token, user.password_reset_token, user.token_expiry):
                return {
                    'success': False,
                    'error': 'Reset token has expired'
                }, 400
            
            # Update password
            user.password_hash = hash_password(new_password)
            user.password_reset_token = None
            user.token_expiry = None
            user.failed_attempts = 0
            if user.status == 'locked':
                user.status = 'active'
            
            db.session.commit()
            
            logger.info(f"Password reset successful for user: {user.email}")
            
            return {
                'success': True,
                'message': 'Password reset successful'
            }, 200
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'error': 'An error occurred'
            }, 500
    
    @staticmethod
    def verify_token(user_email):
        """Verify if JWT token is valid and user still has access"""
        try:
            user = User.query.filter_by(email=user_email).first()
            
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }, 404
            
            if user.status != 'active':
                return {
                    'success': False,
                    'error': 'Account is not active'
                }, 403
            
            return {
                'success': True,
                'user': user.to_dict()
            }, 200
            
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return {
                'success': False,
                'error': 'An error occurred'
            }, 500