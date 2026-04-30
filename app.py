"""
app.py — Application factory and entry point.

Wiring order:
  1. Create Flask app & configure
  2. Initialise extensions (db, login, socketio, mail)
  3. Register models (imports trigger SQLAlchemy metadata)
  4. Register blueprints
  5. Add security-header after-request hook
  6. Initialise / migrate the database
"""

import os

from flask import Flask

from core.extensions import db, init_extensions
from routes import register_blueprints
from services.email_verification import EmailVerification


def create_app():
    app = Flask(__name__)

    # -----------------------------------------------------------------------
    # Configuration
    # -----------------------------------------------------------------------
    app.config['SECRET_KEY']                  = os.environ.get('SECRET_KEY', 'change-me-in-production')
    app.config['SQLALCHEMY_DATABASE_URI']     = os.environ.get('DATABASE_URL', 'sqlite:///ip_lookup.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.config.update(
        MAIL_SERVER='smtp.gmail.com',
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME='secoraapp@gmail.com',
        MAIL_PASSWORD=os.environ.get('APP_KEY'),
        MAIL_DEFAULT_SENDER='Secora <secoraapp@gmail.com>',
    )

    # -----------------------------------------------------------------------
    # Extensions
    # -----------------------------------------------------------------------
    init_extensions(app)

    # -----------------------------------------------------------------------
    # Email verifier (needs mail extension already bound to app)
    # -----------------------------------------------------------------------
    from core.extensions import mail
    email_verifier = EmailVerification(mail)
    # Store on app so blueprints can retrieve it via current_app.extensions
    app.extensions['email_verifier'] = email_verifier

    # -----------------------------------------------------------------------
    # Models — import to register SQLAlchemy metadata
    # -----------------------------------------------------------------------
    import core.models  # noqa: F401

    # -----------------------------------------------------------------------
    # Blueprints
    # -----------------------------------------------------------------------
    register_blueprints(app)

    # -----------------------------------------------------------------------
    # Security headers
    # -----------------------------------------------------------------------
    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
            "font-src 'self' cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        response.headers['X-Content-Type-Options']  = 'nosniff'
        response.headers['X-Frame-Options']         = 'DENY'
        response.headers['X-XSS-Protection']        = '1; mode=block'
        response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
        response.headers.pop('Server', None)
        return response

    return app


def init_db(app):
    """Create / migrate the database schema."""
    with app.app_context():
        try:
            inspector = db.inspect(db.engine)
            if inspector.has_table('user'):
                columns = [c['name'] for c in inspector.get_columns('user')]
                if 'oauth_provider' in columns and 'password_hash' not in columns:
                    print("🔄 Migrating from OAuth to password authentication…")
                    db.drop_all()
                    db.create_all()
                    print("✅ Database migrated successfully!")
                elif 'password_hash' not in columns:
                    print("🔄 Fixing database schema…")
                    db.drop_all()
                    db.create_all()
                    print("✅ Database schema fixed!")
                else:
                    db.create_all()
                    print("✅ Database schema verified!")
            else:
                db.create_all()
                print("✅ Database initialised successfully!")
        except Exception as e:
            print(f"❌ Database initialisation error: {e}")
            try:
                db.drop_all()
                db.create_all()
                print("✅ Database forcefully recreated!")
            except Exception as e2:
                print(f"❌ Failed to recreate database: {e2}")
                print("💡 Delete instance/ip_lookup.db and restart.")


if __name__ == '__main__':
    from core.extensions import socketio
    application = create_app()
    init_db(application)
    print("Starting Secora IP Intelligence…")
    socketio.run(application, debug=True)
