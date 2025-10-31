import os
from datetime import timedelta


class Config:
    """Configuration class for ECL System"""
    
    # Database Configuration
    # TODO: Once DB is setup, uncomment and configure these values
    # DB_USER = 'postgres'
    # DB_PASSWORD = 'your_db_password'
    # DB_NAME = 'ecl_system'
    # DB_HOST = 'your_db_host'
    # DB_PORT = '5432'
    # DB_SCHEMA = 'dbo'
    
    # Placeholder for development (uses SQLite)
    DB_USER = 'postgres'
    DB_PASSWORD = '1029'  # Replace with actual password
    DB_NAME = 'users'
    DB_HOST = 'localhost'  # Replace with actual host
    DB_PORT = '5432'
    DB_SCHEMA = 'dbo'
    
    # Database URI
    SQLALCHEMY_DATABASE_URI = (
        f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/"
        f"{DB_NAME}?sslmode=disable&options=-csearch_path%3D{DB_SCHEMA}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # JWT Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'ecl-super-secret-key-change-in-production')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'ecl-jwt-secret-key-change-in-production')
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_ACCESS_COOKIE_NAME = 'access_token_cookie'
    JWT_COOKIE_SECURE = False  # Set to True in production with HTTPS
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_SAMESITE = 'Lax'  # Use 'Strict' in production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)  # 8 hour session
    JWT_COOKIE_CSRF_PROTECT = False  # Enable in production
    
    # Security Settings
    MAX_LOGIN_ATTEMPTS = 3
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)
    PASSWORD_RESET_EXPIRY = timedelta(minutes=15)
    
    # Email Configuration (for future use)
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@eclsystem.com')
    
    # Application Settings
    FRONTEND_BASE_URL = os.getenv('FRONTEND_BASE_URL', 'http://localhost:3000')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')


config = Config()