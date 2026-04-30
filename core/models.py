"""
models.py — SQLAlchemy database models.

Import `db` from extensions.py, not directly from here.
"""

from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_login import UserMixin
from core.extensions import db


class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active     = db.Column(db.Boolean, default=True)
    email_confirmed = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = PasswordHasher().hash(password)

    def check_password(self, password):
        try:
            PasswordHasher().verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def __repr__(self):
        return f'<User {self.username}>'


class SearchHistory(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address   = db.Column(db.String(45), nullable=True)
    search_type  = db.Column(db.String(20), default='ip_lookup')
    url_shortened= db.Column(db.Text, nullable=True)
    timestamp    = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('searches', lazy=True))


class IPReport(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    ip_address  = db.Column(db.String(45), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    comment     = db.Column(db.Text, nullable=False)
    timestamp   = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('reports', lazy=True))
