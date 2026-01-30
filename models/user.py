from . import db
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timezone

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    email_confirmed = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = PasswordHasher().hash(password)


    def check_password(self, password):
        """Check if provided password matches hash"""
        try:
            PasswordHasher().verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def __repr__(self):
        return f'<User {self.username}>'
