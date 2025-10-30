from flask import Flask, request
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from config import Config
from utils.db import db
from controllers.auth_controller import auth_bp
import logging
from datetime import datetime


# Setup logging
logging.basicConfig(
    filename='access.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)


app = Flask(__name__)
app.config.from_object(Config)


# CORS Configuration
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    # Add production URLs as needed
]

CORS(app, origins=allowed_origins, supports_credentials=True)


# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)


# Register Blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')


# Request logging middleware
@app.before_request
def log_request_info():
    logging.info(
        f"{request.remote_addr} - {request.method} - {request.path} - "
        f"{request.headers.get('User-Agent')} - {datetime.utcnow()}"
    )


# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return {
        'success': False,
        'error': 'Token has expired',
        'message': 'Please login again'
    }, 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return {
        'success': False,
        'error': 'Invalid token',
        'message': 'Please login again'
    }, 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return {
        'success': False,
        'error': 'Authorization required',
        'message': 'Please login to access this resource'
    }, 401


# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'ECL System API'
    }, 200


# Database initialization
with app.app_context():
    db.create_all()
    logging.info("Database tables created successfully")


if __name__ == "__main__":
    app.run(debug=True, port=8000, host='0.0.0.0')