from datetime import datetime
from utils.db import db


class User(db.Model):
    """
    User model for ECL System
    Supports three roles: Super Admin, Preparer, User
    Multi-tenant architecture
    """
    __tablename__ = 'users'
    __table_args__ = {'schema': 'dbo'}
    
    # Primary Key
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # Multi-tenancy
    tenant_id = db.Column(
        db.Integer, 
        db.ForeignKey('dbo.tenant.tenant_id'), 
        nullable=False,
        comment="Organization/tenant identifier for multi-tenancy"
    )
    
    # User Information
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone_number = db.Column(db.String(20), nullable=True)
    designation = db.Column(db.String(100), nullable=True)
    
    # Authentication
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Role-based Access Control
    # Roles: 'super_admin', 'preparer', 'user'
    role = db.Column(
        db.String(50), 
        nullable=False, 
        default='user',
        comment="Role: super_admin, preparer, user"
    )
    
    # Account Status
    # Status: 'active', 'inactive', 'locked'
    status = db.Column(
        db.String(20), 
        nullable=False, 
        default='active',
        comment="Account status: active, inactive, locked"
    )
    
    # Security & Audit
    failed_attempts = db.Column(
        db.Integer, 
        default=0, 
        nullable=False,
        comment="Failed login attempts counter"
    )
    last_login = db.Column(
        db.DateTime, 
        nullable=True,
        comment="Last successful login timestamp"
    )
    date_added = db.Column(
        db.DateTime, 
        default=datetime.utcnow, 
        nullable=False,
        comment="Account creation timestamp"
    )
    date_modified = db.Column(
        db.DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow,
        comment="Last modification timestamp"
    )
    
    # Password Reset
    password_reset_token = db.Column(
        db.String(255), 
        nullable=True,
        comment="Token for password reset functionality"
    )
    token_expiry = db.Column(
        db.DateTime, 
        nullable=True,
        comment="Password reset token expiry"
    )
    
    # Email Verification (for future use)
    email_verified = db.Column(
        db.Boolean, 
        default=False,
        comment="Email verification status"
    )
    verification_token = db.Column(
        db.String(255), 
        nullable=True
    )
    
    def __repr__(self):
        return f'<User {self.email} - {self.role}>'
    
    def to_dict(self, include_sensitive=False):
        """Convert user object to dictionary"""
        data = {
            'userId': self.user_id,
            'tenantId': self.tenant_id,
            'firstName': self.first_name,
            'lastName': self.last_name,
            'email': self.email,
            'phoneNumber': self.phone_number,
            'designation': self.designation,
            'role': self.role,
            'status': self.status,
            'lastLogin': self.last_login.isoformat() if self.last_login else None,
            'dateAdded': self.date_added.isoformat() if self.date_added else None,
            'emailVerified': self.email_verified
        }
        
        if include_sensitive:
            data['failedAttempts'] = self.failed_attempts
            data['dateModified'] = self.date_modified.isoformat() if self.date_modified else None
        
        return data


class Tenant(db.Model):
    """
    Tenant model for multi-tenant architecture
    Each tenant represents an organization
    """
    __tablename__ = 'tenant'
    __table_args__ = {'schema': 'dbo'}
    
    tenant_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_name = db.Column(db.String(255), nullable=False, unique=True)
    tenant_domain = db.Column(
        db.String(255), 
        nullable=True,
        comment="Email domain for tenant (e.g., company.com)"
    )
    tenant_type = db.Column(
        db.String(50), 
        nullable=True,
        comment="Type of organization: bank, nbfc, financial_institution"
    )
    HQ = db.Column(
        db.String(255), 
        nullable=True,
        comment="Headquarters location"
    )
    borrower_count = db.Column(
        db.Integer, 
        default=0,
        comment="Number of borrowers managed by tenant"
    )
    status = db.Column(
        db.String(20), 
        nullable=False, 
        default='active',
        comment="Tenant status: active, inactive, suspended"
    )
    aud_date = db.Column(
        db.DateTime, 
        default=datetime.utcnow,
        comment="Audit timestamp"
    )
    
    # Relationships
    users = db.relationship('User', backref='tenant', lazy=True)
    
    def __repr__(self):
        return f'<Tenant {self.tenant_name}>'
    
    def to_dict(self):
        return {
            'tenantId': self.tenant_id,
            'tenantName': self.tenant_name,
            'tenantDomain': self.tenant_domain,
            'tenantType': self.tenant_type,
            'HQ': self.HQ,
            'borrowerCount': self.borrower_count,
            'status': self.status,
            'audDate': self.aud_date.isoformat() if self.aud_date else None
        }