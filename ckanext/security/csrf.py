import hmac
import base64
import hashlib
import logging
import secrets
from datetime import datetime, timedelta

from ckan.plugins.toolkit import request, config, _, c, g
from ckan.common import session

log = logging.getLogger(__name__)

def _get_csrf_token_key():
    """Get the session key for the CSRF token."""
    return 'csrf_token'

def _get_csrf_token_header():
    """Get the header name for the CSRF token."""
    return 'X-CSRF-Token'

def generate_csrf_token():
    """Generate a new CSRF token using cryptographically secure random bytes."""
    # Generate a random token using secrets module (more secure than datetime-based)
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Store in session
    session[_get_csrf_token_key()] = token
    session.save()
    
    return token

def validate_csrf_token(token=None):
    """Validate the CSRF token from either the request header or form data."""
    try:
        if not token:
            # Try to get token from header
            token = request.headers.get(_get_csrf_token_header())
            
            # If not in header, try form data
            if not token:
                token = request.form.get(_get_csrf_token_key())
        
        stored_token = session.get(_get_csrf_token_key())
        
        if not stored_token or not token:
            log.warning('CSRF validation failed: missing token')
            return False
            
        # Use constant-time comparison
        is_valid = hmac.compare_digest(stored_token, token)
        if not is_valid:
            log.warning('CSRF validation failed: invalid token')
            
        return is_valid
    except Exception as e:
        log.error('CSRF validation error: %s', str(e))
        return False

def csrf_protect():
    """Decorator for CSRF protection."""
    def decorator(f):
        def wrapped(*args, **kwargs):
            # Skip CSRF check for GET, HEAD, OPTIONS
            if request.method not in ('GET', 'HEAD', 'OPTIONS'):
                if not validate_csrf_token():
                    raise ValueError(_('CSRF validation failed. Please try again.'))
            return f(*args, **kwargs)
        return wrapped
    return decorator 