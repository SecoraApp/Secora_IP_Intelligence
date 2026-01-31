from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

from .user import User
from .search_history import SearchHistory
from .ip_report import IPReport
