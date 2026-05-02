"""
routes/__init__.py — Registers all blueprints onto the Flask app.
"""

from routes.main import main_bp
from routes.auth import auth_bp
from routes.security import security_bp


def register_blueprints(app):
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(security_bp)
