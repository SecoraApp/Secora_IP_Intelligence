from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Message
from flask import current_app, url_for
import redis

# Redis (Docker)
def get_redis():
    return redis.Redis(
        host="localhost",   # Docker port-mapped Redis
        port=6379,
        db=0,
        decode_responses=True,
        socket_connect_timeout=2
    )

RESEND_COOLDOWN = 300     # seconds
TOKEN_EXPIRATION = 3600   # seconds


class EmailVerification:
    """Handles email confirmation tokens + sending emails"""

    def __init__(self, mail):
        self.mail = mail

    # Token handling
    def _serializer(self):
        return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

    def generate_token(self, email):
        return self._serializer().dumps(
            email,
            salt="email-confirm-salt"
        )

    def confirm_token(self, token):
        try:
            return self._serializer().loads(
                token,
                salt="email-confirm-salt",
                max_age=TOKEN_EXPIRATION
            )
        except (BadSignature, SignatureExpired):
            return None


    # Resend protection (Redis)
    def can_resend(self, email):
        """
        Returns True if resend is allowed.
        Fails OPEN if Redis is unavailable.
        """
        try:
            r = get_redis()
            key = f"email_resend:{email}"

            if r.exists(key):
                return False

            r.setex(key, RESEND_COOLDOWN, "1")
            return True

        except Exception as e:
            #Don't block user if redis is down.
            print("Redis unavailable:", e)
            return True


    def send_confirmation(self, user):
        if not self.can_resend(user.email):
            return False

        token = self.generate_token(user.email)
        confirm_url = url_for(
            "auth.confirm_email",
            token=token,
            _external=True
        )

        msg = Message(
            subject="Confirm your Secora account",
            recipients=[user.email],
            sender=current_app.config.get("MAIL_DEFAULT_SENDER")
        )

        msg.body = f"""
Hello {user.username},

Thanks for signing up for Secora!
Please confirm your email by clicking the link below:


Confirmation Link: {confirm_url}


This link will expire in 1 hour.
If you did not create this account, you can safely ignore this email.
"""
        self.mail.send(msg)
        return True

    # -----------------------------------------------------------------------
    # Email address change
    # -----------------------------------------------------------------------

    def generate_email_change_token(self, user_id, new_email):
        """Encode both the user ID and the desired new email into a signed token."""
        return self._serializer().dumps(
            {'user_id': user_id, 'new_email': new_email},
            salt='email-change-salt'
        )

    def confirm_email_change_token(self, token):
        """
        Validate a change token.
        Returns (user_id, new_email) on success, or None if invalid/expired.
        """
        try:
            data = self._serializer().loads(
                token,
                salt='email-change-salt',
                max_age=TOKEN_EXPIRATION
            )
            return data['user_id'], data['new_email']
        except (BadSignature, SignatureExpired, KeyError):
            return None

    def send_email_change_confirmation(self, user, new_email):
        """
        Send a confirmation link to *new_email*.
        The address only changes once the user clicks the link.
        Respects the same resend cooldown as registration confirmations,
        keyed on the *new* address so the old address is unaffected.
        """
        if not self.can_resend(new_email):
            return False

        token = self.generate_email_change_token(user.id, new_email)
        confirm_url = url_for(
            'auth.confirm_email_change',
            token=token,
            _external=True
        )

        msg = Message(
            subject='Confirm your new Secora email address',
            recipients=[new_email],
            sender=current_app.config.get('MAIL_DEFAULT_SENDER')
        )

        msg.body = f"""
Hello {user.username},

We received a request to change your Secora email address to this one.
Click the link below to confirm the change:


Confirmation Link: {confirm_url}


This link will expire in 1 hour.
If you did not request this change, you can safely ignore this email —
your original address will remain unchanged.
"""
        self.mail.send(msg)
        return True
