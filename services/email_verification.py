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

We received a request to change your Secora email address.
Click the link below to confirm:

{confirm_url}

This link will expire in 1 hour.
If you did not request this change you can safely ignore this email —
your original address will remain unchanged.
"""
        self._send(msg)
        return True
