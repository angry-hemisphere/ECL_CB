import re
from email_validator import validate_email, EmailNotValidError


def validate_email_format(email):
    """
    Validate email format using email-validator library
    Returns: (is_valid: bool, normalized_email: str, error_message: str)
    """
    try:
        # Validate and normalize
        valid = validate_email(email, check_deliverability=False)
        return True, valid.normalized, None
    except EmailNotValidError as e:
        return False, None, str(e)


def validate_phone_number(phone):
    """
    Validate phone number format
    Accepts: +1234567890, 1234567890, (123) 456-7890, etc.
    """
    if not phone:
        return True, None  # Phone is optional
    
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    
    # Check if it's a valid format (10-15 digits, optional + prefix)
    if re.match(r'^\+?\d{10,15}$', cleaned):
        return True, None
    
    return False, "Invalid phone number format"


def validate_required_fields(data, required_fields):
    """
    Validate that all required fields are present and non-empty
    Returns: (is_valid: bool, missing_fields: list)
    """
    missing = []
    for field in required_fields:
        if field not in data or not data[field] or str(data[field]).strip() == '':
            missing.append(field)
    
    if missing:
        return False, missing
    return True, []


def validate_role(role):
    """Validate user role"""
    valid_roles = ['super_admin', 'preparer', 'user']
    if role not in valid_roles:
        return False, f"Invalid role. Must be one of: {', '.join(valid_roles)}"
    return True, None


def sanitize_string(value, max_length=None):
    """Sanitize string input"""
    if not value:
        return ""
    
    # Strip whitespace
    sanitized = str(value).strip()
    
    # Truncate if needed
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized