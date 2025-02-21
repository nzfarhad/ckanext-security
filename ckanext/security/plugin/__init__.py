import logging
import ckan.plugins as p

from ckanext.security import schema as ext_schema
from ckan.plugins import toolkit as tk
from ckan.logic import schema as core_schema
from ckanext.security.model import define_security_tables
from ckanext.security.resource_upload_validator import (
    validate_upload
)
from ckanext.security.logic import auth, action
from ckanext.security.helpers import security_enable_totp
from ckanext.security.csrf import generate_csrf_token, validate_csrf_token, csrf_protect
from ckanext.security.plugin.flask_plugin import MixinPlugin

log = logging.getLogger(__name__)


class CkanSecurityPlugin(MixinPlugin, p.SingletonPlugin):
    p.implements(p.IConfigurer)
    p.implements(p.IResourceController, inherit=True)
    p.implements(p.IActions)
    p.implements(p.IAuthFunctions)
    p.implements(p.ITemplateHelpers)
    p.implements(p.IMiddleware, inherit=True)

    # BEGIN Hooks for IConfigurer

    def update_config(self, config):
        define_security_tables()  # map security models to db schema

        # Monkeypatching all user schemas in order to enforce a stronger
        # password policy. I tried monkeypatching
        # `ckan.logic.validators.user_password_validator` instead
        # without success.
        core_schema.default_user_schema = \
            ext_schema.default_user_schema
        core_schema.user_new_form_schema = \
            ext_schema.user_new_form_schema
        core_schema.user_edit_form_schema = \
            ext_schema.user_edit_form_schema
        core_schema.default_update_user_schema = \
            ext_schema.default_update_user_schema

        tk.add_template_directory(config, '../templates')
        tk.add_resource('../fanstatic', 'security')

    # END Hooks for IConfigurer

    # BEGIN Hooks for IResourceController

    # CKAN < 2.10
    def before_create(self, context, resource):
        validate_upload(resource)

    def before_update(self, context, current, resource):
        validate_upload(resource)

    # CKAN >= 2.10
    def before_resource_create(self, context, resource):
        validate_upload(resource)

    def before_resource_update(self, context, current, resource):
        validate_upload(resource)

    # END Hooks for IResourceController

    # BEGIN Hooks for IMiddleware

    def make_middleware(self, app, config):
        """Add CSRF protection middleware."""
        return CSRFMiddleware(app)

    # END Hooks for IMiddleware

    # BEGIN Hooks for IActions

    def get_actions(self):
        return {
            'security_reset_totp': action.security_reset_totp,
            'security_throttle_user_show': action.security_throttle_user_show,
            'security_throttle_address_show': action.security_throttle_address_show,
            'security_throttle_user_reset': action.security_throttle_user_reset,
            'security_throttle_address_reset': action.security_throttle_address_reset
        }

    # END Hooks for IActions

    # BEGIN Hooks for IAuthFunctions

    def get_auth_functions(self):
        return {
            'security_reset_totp': auth.security_reset_totp,
            'security_throttle_user_show': auth.security_throttle_user_show,
            'security_throttle_address_show': auth.security_throttle_address_show,
            'security_throttle_user_reset': auth.security_throttle_user_reset,
            'security_throttle_address_reset': auth.security_throttle_address_reset
        }

    # END Hooks for IAuthFunctions

    # ITemplateHelpers

    def get_helpers(self):
        return {
            'check_ckan_version': tk.check_ckan_version,
            'security_enable_totp': security_enable_totp,
            'get_csrf_token': generate_csrf_token
        }


class CSRFMiddleware:
    """WSGI middleware that adds CSRF protection."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Skip CSRF check for safe methods
        if environ['REQUEST_METHOD'] not in ('GET', 'HEAD', 'OPTIONS'):
            # Get the token from headers or form data
            token = environ.get('HTTP_X_CSRF_TOKEN')
            if not token and 'wsgi.input' in environ:
                from ckan.common import request
                token = request.form.get('csrf_token')

            # Validate token
            if not validate_csrf_token(token):
                # Return 403 Forbidden if validation fails
                status = '403 Forbidden'
                headers = [('Content-Type', 'text/plain')]
                start_response(status, headers)
                return [b'CSRF validation failed']

        return self.app(environ, start_response)
