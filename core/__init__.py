"""
core/__init__.py — Re-exports extensions, models, utils, and crypto.

    from core import db, User, is_valid_ip, encrypt, decrypt
    from core.extensions import socketio   # also fine for specifics
"""

from core.extensions import db, login_manager, socketio, mail, init_extensions
from core.models import User, SearchHistory, IPReport, PasskeyCredential
from core.utils import is_valid_ip, is_valid_url, sanitize_string, validate_password_complexity
from core.crypto import encrypt, decrypt

__all__ = [
    # extensions
    'db', 'login_manager', 'socketio', 'mail', 'init_extensions',
    # models
    'User', 'SearchHistory', 'IPReport', 'PasskeyCredential',
    # utils
    'is_valid_ip', 'is_valid_url', 'sanitize_string', 'validate_password_complexity',
    # crypto
    'encrypt', 'decrypt',
]
