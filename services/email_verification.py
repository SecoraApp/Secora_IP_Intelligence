import concurrent.futures
import json

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Message
from flask import current_app, url_for
import redis


# ---------------------------------------------------------------------------
# Redis (resend cooldown)
# ---------------------------------------------------------------------------

def get_redis():
    return redis.Redis(
        host='localhost',
        port=6379,
        db=0,
        decode_responses=True,
        socket_connect_timeout=2,
    )


RESEND_COOLDOWN  = 300   # seconds between resends
TOKEN_EXPIRATION = 3600  # seconds until token expires
MAIL_TIMEOUT     = 10    # seconds before giving up on SMTP


class EmailVerification:
    """Handles email confirmation tokens and sending."""

    def __init__(self, mail):
        self.mail = mail

    # -----------------------------------------------------------------------
    # Token helpers
    # -----------------------------------------------------------------------

    def _serializer(self):
        return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    def generate_token(self, email):
        return self._serializer().dumps(email, salt='email-confirm-salt')

    def confirm_token(self, token):
        try:
            return self._serializer().loads(
                token, salt='email-confirm-salt', max_age=TOKEN_EXPIRATION
            )
        except (BadSignature, SignatureExpired):
            return None

    # -----------------------------------------------------------------------
    # Resend rate limiting (Redis)
    # -----------------------------------------------------------------------

    def can_resend(self, email):
        """Return True if a send is allowed. Fails open if Redis is down."""
        try:
            r   = get_redis()
            key = f'email_resend:{email}'
            if r.exists(key):
                return False
            r.setex(key, RESEND_COOLDOWN, '1')
            return True
        except Exception as e:
            current_app.logger.warning(f'Redis unavailable for resend check: {e}')
            return True

    # -----------------------------------------------------------------------
    # Internal send helper — runs in a thread with a timeout
    # -----------------------------------------------------------------------

    def _send(self, msg):
        """
        Send *msg* in a background thread with a hard timeout.
        Raises TimeoutError if SMTP doesn't respond in MAIL_TIMEOUT seconds.
        Raises any SMTP/connection exception on failure.
        """
        app = current_app._get_current_object()

        def _do_send():
            with app.app_context():
                self.mail.send(msg)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_do_send)
            try:
                future.result(timeout=MAIL_TIMEOUT)
            except concurrent.futures.TimeoutError:
                raise TimeoutError(
                    f'SMTP timed out after {MAIL_TIMEOUT}s — '
                    'check MAIL_SERVER, MAIL_PORT, and firewall rules.'
                )

    # -----------------------------------------------------------------------
    # Registration confirmation
    # -----------------------------------------------------------------------

    def send_confirmation(self, user):
        if not self.can_resend(user.email):
            return False

        token       = self.generate_token(user.email)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)

        msg = Message(
            subject='Confirm your Secora account',
            recipients=[user.email],
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )
        msg.body = f"""\
Hello {user.username},

Thanks for signing up for Secora!
Please confirm your email by clicking the link below:

{confirm_url}

This link will expire in 1 hour.
If you did not create this account, you can safely ignore this email.
"""
        self._send(msg)
        return True

    # -----------------------------------------------------------------------
    # Email address change
    # -----------------------------------------------------------------------

    def generate_email_change_token(self, user_id, new_email):
        return self._serializer().dumps(
            {'user_id': user_id, 'new_email': new_email},
            salt='email-change-salt',
        )

    def confirm_email_change_token(self, token):
        try:
            data = self._serializer().loads(
                token, salt='email-change-salt', max_age=TOKEN_EXPIRATION
            )
            return data['user_id'], data['new_email']
        except (BadSignature, SignatureExpired, KeyError):
            return None

    def send_email_change_confirmation(self, user, new_email):
        if not self.can_resend(new_email):
            return False

        token       = self.generate_email_change_token(user.id, new_email)
        confirm_url = url_for(
            'auth.confirm_email_change', token=token, _external=True
        )

        msg = Message(
            subject='Confirm your new Secora email address',
            recipients=[new_email],
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )
        msg.body = f"""\
Hello {user.username},

We received a request to change your Secora email address to this one.
Click the link below to confirm:

{confirm_url}

This link will expire in 1 hour.
If you did not request this change you can safely ignore this email —
your original address will remain unchanged.
"""
        self._send(msg)
        return True

    # -----------------------------------------------------------------------
    # Password reset
    # -----------------------------------------------------------------------

    # Rate limit: max 3 reset requests per hour per email
    RESET_COOLDOWN   = 1800   # 30 min between requests per email
    RESET_EXPIRATION = 300    # token valid for 5 minutes

    def generate_reset_token(self, user_id):
        """Sign a password reset token containing the user ID."""
        return self._serializer().dumps(
            {'user_id': user_id, 'purpose': 'password-reset'},
            salt='password-reset-salt',
        )

    def confirm_reset_token(self, token):
        """
        Validate a reset token.
        Returns user_id on success, None if invalid or expired.
        """
        try:
            data = self._serializer().loads(
                token,
                salt='password-reset-salt',
                max_age=self.RESET_EXPIRATION,
            )
            if data.get('purpose') != 'password-reset':
                return None
            return data['user_id']
        except (BadSignature, SignatureExpired, KeyError):
            return None

    def can_send_reset(self, email):
        """
        Return (allowed: bool, seconds_remaining: int).
        Fails open if Redis is down.
        """
        try:
            r   = get_redis()
            key = f'pw_reset:{email}'
            ttl = r.ttl(key)
            if ttl > 0:
                return False, ttl
            r.setex(key, self.RESET_COOLDOWN, '1')
            return True, 0
        except Exception as e:
            current_app.logger.warning(f'Redis unavailable for reset rate limit: {e}')
            return True, 0

    def send_password_reset(self, user):
        """
        Send a password reset link to *user*.
        Returns (sent: bool, seconds_remaining: int).
        seconds_remaining is 0 when sent, >0 when rate-limited.
        """
        allowed, ttl = self.can_send_reset(user.email)
        if not allowed:
            return False, ttl

        token      = self.generate_reset_token(user.id)
        reset_url  = url_for('auth.password_reset', token=token, _external=True)

        msg = Message(
            subject='Reset your Secora password',
            recipients=[user.email],
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )
        msg.body = f"""\
Hello {user.username},

We received a request to reset the password for your Secora account.
Click the link below to set a new password:

{reset_url}

This link will expire in 5 minutes.
If you did not request a password reset, you can safely ignore this email.
Your password will not be changed unless you click the link above.
"""
        self._send(msg)
        return True, 0

    def send_password_changed_alert(self, user):
        """Notify the user that their password was successfully changed."""
        msg = Message(
            subject='Your Secora password has been changed',
            recipients=[user.email],
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )
        msg.body = f"""\
Hello {user.username},

Your Secora password was just changed successfully.

If you made this change, no action is needed.

If you did NOT change your password, your account may be compromised.
Please contact us immediately.
"""
        try:
            self._send(msg)
        except Exception as e:
            current_app.logger.error(f'Password change alert failed for {user.email}: {e}')
