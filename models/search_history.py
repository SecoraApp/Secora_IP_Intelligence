from . import db
from datetime import datetime, timezone

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6 (null for URL shortening)
    search_type = db.Column(db.String(20), default='ip_lookup')  # 'ip_lookup' or 'url_shorten'
    url_shortened = db.Column(db.Text, nullable=True)  # For URL shortening history
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('searches', lazy=True))

