"""
extensions.py — Flask extension instances.

Instantiated here (without an app) so that models and blueprints can import
them without triggering circular imports.  Call `init_extensions(app)` from
app.py after the Flask app is created.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_mail import Mail

db           = SQLAlchemy()
login_manager = LoginManager()
socketio     = SocketIO()
mail         = Mail()


def init_extensions(app):
    """Bind all extensions to *app*."""
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)
    mail.init_app(app)

    login_manager.login_view    = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'

    @login_manager.user_loader
    def load_user(user_id):
        from core.models import User
        try:
            return db.session.get(User, int(user_id))
        except Exception as e:
            print(f"User loading error: {e}")
            return None
