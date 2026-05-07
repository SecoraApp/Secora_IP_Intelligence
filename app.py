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

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask

from core.extensions import db, csrf, init_extensions
from routes import register_blueprints
from services.email_verification import EmailVerification


def setup_logging(app):
    """Write app errors to /var/secora_app/logs/app.log with rotation."""
    log_dir = '/var/secora_app/logs'
    log_path = os.path.join(log_dir, 'app.log')

    # Fall back to current directory if log dir doesn't exist (dev mode)
    if not os.path.isdir(log_dir):
        log_path = 'app.log'

    handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=5,
        encoding='utf-8',
    )
    handler.setLevel(logging.WARNING)
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.WARNING)

    # Also log to stderr so journalctl catches it
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))
    app.logger.addHandler(stream_handler)


def create_app():
    app = Flask(__name__)

    # -----------------------------------------------------------------------
    # Configuration
    # -----------------------------------------------------------------------
    app.config['SECRET_KEY']                  = os.environ.get('SECRET_KEY', 'change-me-in-production')
    app.config['SQLALCHEMY_DATABASE_URI']     = os.environ.get('DATABASE_URL', 'sqlite:///ip_lookup.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ── Session & cookie security ─────────────────────────────────────────
    app.config['SESSION_COOKIE_HTTPONLY']  = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE']   = os.environ.get('FLASK_ENV') == 'production'
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SECURE']  = os.environ.get('FLASK_ENV') == 'production'
    app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'

    # ── CSRF ──────────────────────────────────────────────────────────────
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour token lifetime

    app.config.update(
        MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
        MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
        MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
        MAIL_USERNAME=os.environ.get('MAIL_USERNAME', ''),
        MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD', ''),
        MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'Secora <noreply@secora.app>'),
    )

    # WebAuthn config (read from env so deployment file is the single source)
    app.config['WEBAUTHN_RP_ID']  = os.environ.get('WEBAUTHN_RP_ID',  'localhost')
    app.config['WEBAUTHN_ORIGIN'] = os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:5000')

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

    # ── CSRF exemptions for JSON API endpoints ────────────────────────────
    # These endpoints receive application/json bodies from JS fetch() calls.
    # CSRF tokens in JSON APIs are redundant when SameSite=Lax is set on
    # cookies, but we exempt explicitly to avoid 400s from the decorator.
    from routes.main import (lookup, shorten_url, get_my_ip, report_ip,
                             get_ip_reports)
    from routes.security import (passkey_register_begin, passkey_register_complete,
                                  passkey_authenticate_begin, passkey_authenticate_complete)
    for view in [lookup, shorten_url, get_my_ip, report_ip, get_ip_reports,
                 passkey_register_begin, passkey_register_complete,
                 passkey_authenticate_begin, passkey_authenticate_complete]:
        csrf.exempt(view)

    # -----------------------------------------------------------------------
    # Security headers
    # -----------------------------------------------------------------------
    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
            "font-src 'self' cdnjs.cloudflare.com; "
            "img-src 'self' data: https://www.abuseipdb.com; "
            "connect-src 'self' wss:;"
        )
        response.headers['X-Content-Type-Options']  = 'nosniff'
        response.headers['X-Frame-Options']         = 'DENY'
        response.headers['X-XSS-Protection']        = '1; mode=block'
        response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
        response.headers.pop('Server', None)
        return response

    setup_logging(app)
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


# Module-level app instance — used by gunicorn (app:application)
application = create_app()
init_db(application)

if __name__ == '__main__':
    from core.extensions import socketio
    print("🚀 Starting Secora IP Intelligence…")
    socketio.run(application, debug=True)
