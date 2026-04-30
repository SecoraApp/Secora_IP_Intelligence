"""
core/__init__.py — Re-exports extensions, models, and utils so callers can do:

    from core import db, User, is_valid_ip
    from core.extensions import socketio   # also fine for specifics
"""

from core.extensions import db, login_manager, socketio, mail, init_extensions
from core.models import User, SearchHistory, IPReport
from core.utils import is_valid_ip, is_valid_url, sanitize_string

__all__ = [
    # extensions
    'db', 'login_manager', 'socketio', 'mail', 'init_extensions',
    # models
    'User', 'SearchHistory', 'IPReport',
    # utils
    'is_valid_ip', 'is_valid_url', 'sanitize_string',
]