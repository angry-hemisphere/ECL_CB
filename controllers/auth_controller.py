from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity, unset_jwt_cookies
from services.auth_service import AuthService
from utils.security import get_current_user_details
import logging


auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login endpoint
    
    Request Body:
    {
        "email": "user@example.com",
        "password": "password123",
        "rememberMe": false
    }
    
    Response:
    {
        "success": true,
        "message": "Login successful",
        "accessToken": "jwt_token_here",
        "user": {
            "userId": 1,
            "email": "user@example.com",
            "firstName": "John",
            "lastName": "Doe",
            "role": "super_admin",
            "tenantId": 1,
            ...
        }
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Request body is required'
            }), 400
        
        email = data.get('email')
        password = data.get('password')
        remember_me = data.get('rememberMe', False)
        
        # Call authentication service
        response_data, status_code = AuthService.login(email, password, remember_me)
        
        # Create response
        response = make_response(jsonify(response_data), status_code)
        
        # Set JWT token in cookie if login successful
        if response_data.get('success') and 'accessToken' in response_data:
            response.set_cookie(
                'access_token_cookie',
                value=response_data['accessToken'],
                httponly=True,
                secure=False,  # Set to True in production with HTTPS
                samesite='Lax',
                max_age=28800 if not remember_me else 604800  # 8 hours or 7 days
            )
        
        return response
        
    except Exception as e:
        logger.error(f"Login endpoint error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logout endpoint
    Requires valid JWT token
    
    Response:
    {
        "success": true,
        "message": "Logout successful"
    }
    """
    try:
        user_email = get_jwt_identity()
        logger.info(f"User logged out: {user_email}")
        
        response_data, status_code = AuthService.logout()
        response = make_response(jsonify(response_data), status_code)
        
        # Clear JWT cookie
        unset_jwt_cookies(response)
        
        return response
        
    except Exception as e:
        logger.error(f"Logout endpoint error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """
    Get current user profile
    Requires valid JWT token
    
    Response:
    {
        "success": true,
        "user": {
            "userId": 1,
            "email": "user@example.com",
            ...
        }
    }
    """
    try:
        user_email = get_jwt_identity()
        response_data, status_code = AuthService.get_user_profile(user_email)
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Get current user error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    """
    Verify JWT token validity
    
    Response:
    {
        "success": true,
        "user": {...}
    }
    """
    try:
        user_email = get_jwt_identity()
        response_data, status_code = AuthService.verify_token(user_email)
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Verify token error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@auth_bp.route('/request-reset', methods=['POST'])
def request_password_reset():
    """
    Request password reset
    
    Request Body:
    {
        "email": "user@example.com"
    }
    
    Response:
    {
        "success": true,
        "message": "Password reset link sent to your email"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'email' not in data:
            return jsonify({
                'success': False,
                'error': 'Email is required'
            }), 400
        
        email = data.get('email')
        response_data, status_code = AuthService.request_password_reset(email)
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Request password reset error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Reset password using token
    
    Request Body:
    {
        "token": "reset_token_here",
        "newPassword": "new_password_123"
    }
    
    Response:
    {
        "success": true,
        "message": "Password reset successful"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'token' not in data or 'newPassword' not in data:
            return jsonify({
                'success': False,
                'error': 'Token and new password are required'
            }), 400
        
        token = data.get('token')
        new_password = data.get('newPassword')
        
        response_data, status_code = AuthService.reset_password(token, new_password)
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


# Health check for auth module
@auth_bp.route('/health', methods=['GET'])
def auth_health():
    """Auth module health check"""
    return jsonify({
        'status': 'healthy',
        'module': 'authentication'
    }), 200