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
            "confirm_email",
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
