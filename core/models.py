"""
models.py — SQLAlchemy database models.

Sensitive fields (totp_secret, totp_backup_codes, ms_tenant_id,
ms_account_email) are stored encrypted via core.crypto.  The raw DB
columns hold ciphertext; use the accessor properties to read/write
plain text.
"""

import json
import secrets
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_login import UserMixin

from core.extensions import db
from core.crypto import encrypt, decrypt


class User(UserMixin, db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80), unique=True, nullable=False)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password_hash   = db.Column(db.String(128), nullable=False)
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active       = db.Column(db.Boolean, default=True)
    email_confirmed = db.Column(db.Boolean, default=False, nullable=False)

    # ── Microsoft (encrypted at rest) ─────────────────────────────────────
    _ms_tenant_id     = db.Column('ms_tenant_id',     db.String(512), nullable=True, default=None)
    _ms_account_email = db.Column('ms_account_email', db.String(512), nullable=True, default=None)
    ms_linked_at      = db.Column(db.DateTime, nullable=True, default=None)
    ms_admin_consent  = db.Column(db.Boolean,  nullable=True, default=False)

    # ── TOTP (encrypted at rest) ──────────────────────────────────────────
    _totp_secret       = db.Column('totp_secret',       db.String(512), nullable=True, default=None)
    _totp_backup_codes = db.Column('totp_backup_codes', db.Text,        nullable=True, default=None)
    totp_enabled       = db.Column(db.Boolean, nullable=False, default=False)

    # ── Passkeys ──────────────────────────────────────────────────────────
    passkeys_enabled = db.Column(db.Boolean, nullable=False, default=False)

    # ── Change-rate tracking ──────────────────────────────────────────────
    # Timestamps of the last N changes, stored as JSON lists so we can
    # enforce sliding-window limits without an extra table.
    # username : max 2 changes per 30 days  (Discord-style)
    # email    : max 2 changes per 24 hours
    # password : max 2 changes per 24 hours
    _username_change_log = db.Column('username_change_log', db.Text, nullable=True, default=None)
    _email_change_log    = db.Column('email_change_log',    db.Text, nullable=True, default=None)
    _password_change_log = db.Column('password_change_log', db.Text, nullable=True, default=None)

    # ── Encrypted accessors ───────────────────────────────────────────────

    @property
    def ms_tenant_id(self):
        return decrypt(self._ms_tenant_id)

    @ms_tenant_id.setter
    def ms_tenant_id(self, value):
        self._ms_tenant_id = encrypt(value)

    @property
    def ms_account_email(self):
        return decrypt(self._ms_account_email)

    @ms_account_email.setter
    def ms_account_email(self, value):
        self._ms_account_email = encrypt(value)

    @property
    def totp_secret(self):
        return decrypt(self._totp_secret)

    @totp_secret.setter
    def totp_secret(self, value):
        self._totp_secret = encrypt(value)

    @property
    def totp_backup_codes(self):
        raw = decrypt(self._totp_backup_codes)
        if not raw:
            return []
        try:
            return json.loads(raw)
        except Exception:
            return []

    @totp_backup_codes.setter
    def totp_backup_codes(self, codes):
        self._totp_backup_codes = encrypt(json.dumps(codes))

    # ── Derived auth properties ───────────────────────────────────────────

    @property
    def ms_linked(self):
        return bool(self._ms_tenant_id and self.ms_admin_consent)

    @property
    def has_2fa(self):
        return self.totp_enabled or self.passkeys_enabled

    @property
    def preferred_2fa(self):
        if self.passkeys_enabled:
            return 'passkey'
        if self.totp_enabled:
            return 'totp'
        return None

    # ── Microsoft helpers ─────────────────────────────────────────────────

    def unlink_microsoft(self):
        self._ms_tenant_id     = None
        self._ms_account_email = None
        self.ms_linked_at      = None
        self.ms_admin_consent  = False

    # ── TOTP helpers ──────────────────────────────────────────────────────

    def generate_backup_codes(self, count=8):
        """Generate fresh backup codes, store them, return plain-text list."""
        codes = [secrets.token_hex(5).upper() for _ in range(count)]
        self.totp_backup_codes = codes
        return codes

    def consume_backup_code(self, code):
        """Remove and return True if code matches; False otherwise."""
        code = code.strip().upper().replace('-', '').replace(' ', '')
        codes = self.totp_backup_codes
        if code in codes:
            codes.remove(code)
            self.totp_backup_codes = codes
            return True
        return False

    # ── Change-rate helpers ──────────────────────────────────────────────

    def _get_change_log(self, field):
        import json
        raw = getattr(self, field)
        if not raw:
            return []
        try:
            return json.loads(raw)
        except Exception:
            return []

    def _set_change_log(self, field, log):
        import json
        setattr(self, field, json.dumps(log))

    def _record_change(self, log_field):
        """Append the current UTC timestamp to a change log."""
        from datetime import datetime, timezone
        log = self._get_change_log(log_field)
        log.append(datetime.now(timezone.utc).isoformat())
        self._set_change_log(log_field, log)


    def can_change_username(self):
        """Max 2 username changes per 30 days."""
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        log = self._get_change_log('_username_change_log')
        recent = [ts for ts in log if self._parse_ts(ts) and self._parse_ts(ts) > cutoff]
        return len(recent) < 2

    def can_change_email(self):
        """Max 2 email changes per 24 hours."""
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        log = self._get_change_log('_email_change_log')
        recent = [ts for ts in log if self._parse_ts(ts) and self._parse_ts(ts) > cutoff]
        return len(recent) < 2

    def can_change_password(self):
        """Max 2 password changes per 24 hours."""
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        log = self._get_change_log('_password_change_log')
        recent = [ts for ts in log if self._parse_ts(ts) and self._parse_ts(ts) > cutoff]
        return len(recent) < 2

    def username_changes_remaining(self):
        """How many username changes are left in the current 30-day window."""
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        log = self._get_change_log('_username_change_log')
        recent = sum(1 for ts in log if self._parse_ts(ts) and self._parse_ts(ts) > cutoff)
        return max(0, 2 - recent)

    def next_username_change_at(self):
        """Return the datetime when the oldest recent change exits the 30-day window."""
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        log = self._get_change_log('_username_change_log')
        recent = sorted([self._parse_ts(ts) for ts in log if self._parse_ts(ts) and self._parse_ts(ts) > cutoff])
        if not recent:
            return None
        return recent[0] + timedelta(days=30)

    @staticmethod
    def _parse_ts(ts):
        from datetime import datetime, timezone
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def record_username_change(self):
        self._record_change('_username_change_log')

    def record_email_change(self):
        self._record_change('_email_change_log')

    def record_password_change(self):
        self._record_change('_password_change_log')

    # ── Password helpers ──────────────────────────────────────────────────

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


class PasskeyCredential(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.LargeBinary(1024), unique=True, nullable=False)
    public_key    = db.Column(db.LargeBinary(1024), nullable=False)
    sign_count    = db.Column(db.Integer, nullable=False, default=0)
    device_name   = db.Column(db.String(100), nullable=True, default='Passkey')
    aaguid        = db.Column(db.String(36),  nullable=True, default=None)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at  = db.Column(db.DateTime, nullable=True, default=None)

    user = db.relationship('User', backref=db.backref('passkey_credentials', lazy=True))


class SearchHistory(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address    = db.Column(db.String(45), nullable=True)
    search_type   = db.Column(db.String(20), default='ip_lookup')
    url_shortened = db.Column(db.Text, nullable=True)
    timestamp     = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('searches', lazy=True))


class IPReport(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    ip_address  = db.Column(db.String(45), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    comment     = db.Column(db.Text, nullable=False)
    timestamp   = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('reports', lazy=True))
