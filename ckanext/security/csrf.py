import hmac
import base64
import hashlib
import logging
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
    """Generate a new CSRF token."""
    # Generate a random token
    token = base64.b64encode(hashlib.sha256(str(datetime.now().timestamp()).encode()).digest()).decode()
    
    # Store in session
    session[_get_csrf_token_key()] = token
    session.save()
    
    return token

def validate_csrf_token(token=None):
    """Validate the CSRF token from either the request header or form data."""
    if not token:
        # Try to get token from header
        token = request.headers.get(_get_csrf_token_header())
        
        # If not in header, try form data
        if not token:
            token = request.form.get(_get_csrf_token_key())
    
    stored_token = session.get(_get_csrf_token_key())
    
    if not stored_token or not token:
        return False
        
    return hmac.compare_digest(stored_token, token)

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