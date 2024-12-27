# -*- coding: utf-8 -*-

import ckan.plugins as p
from ckanext.security import views, cli, authenticator
from ckan.common import session
from flask import session as flask_session


class MixinPlugin(p.SingletonPlugin):
    p.implements(p.IClick)
    p.implements(p.IBlueprint)
    p.implements(p.IAuthenticator, inherit=True)

    # IBlueprint

    def get_blueprint(self):
        return views.get_blueprints()

    # ICLick

    def get_commands(self):
        return cli.get_commands()

    # IAuthenticator

    def login(self):
        return authenticator.login()

    # Delete session cookie information
    def logout(self):
        # Clear all session data
        flask_session.clear()
        # Ensure specific CKAN-related session keys are removed
        for key in list(session.keys()):
            del session[key]
