"""
routes/security.py — TOTP and passkey (WebAuthn) setup, verification, and
management.

Blueprint prefix: /security
"""

import base64
import io
import json
import os
import secrets
from datetime import datetime, timezone

import pyotp
import qrcode
import qrcode.image.svg
from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_login import current_user, login_required, login_user
from webauthn import (generate_authentication_options,
                      generate_registration_options, options_to_json,
                      verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers.structs import (
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from core.extensions import db
from core.models import PasskeyCredential, User

security_bp = Blueprint(
    'security',
    __name__,
    url_prefix='/security',
    template_folder='../templates',
)

APP_NAME = 'Secora'


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _rp_id():
    return current_app.config.get('WEBAUTHN_RP_ID', 'localhost')


def _origin():
    return current_app.config.get('WEBAUTHN_ORIGIN', 'http://localhost:5000')


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------

def _b64url_to_bytes(value: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    padded = value + '=' * (4 - len(value) % 4)
    return base64.urlsafe_b64decode(padded)


# ---------------------------------------------------------------------------
# Identity verification helper
# ---------------------------------------------------------------------------

def _verify_auth(password=None, totp_code=None, backup_code=None):
    """
    Verify the current user's identity before a sensitive action.

    Priority:
      1. If TOTP enabled  → require TOTP code (or backup code)
      2. Otherwise        → require password

    Returns (ok: bool, error_message: str | None).
    """
    if current_user.totp_enabled:
        if backup_code:
            if not current_user.consume_backup_code(backup_code):
                return False, 'Invalid backup code.'
            db.session.commit()
            return True, None
        if not totp_code:
            return False, 'TOTP code required.'
        totp = pyotp.TOTP(current_user.totp_secret)
        if not totp.verify(totp_code.strip(), valid_window=1):
            return False, 'Invalid or expired TOTP code.'
        return True, None

    if not password:
        return False, 'Password required.'
    if not current_user.check_password(password):
        return False, 'Incorrect password.'
    return True, None


# ---------------------------------------------------------------------------
# Security notification emails
# ---------------------------------------------------------------------------

def _send_security_alert(user, event_type, extra=None):
    """
    Send a security alert email to the user.

    event_type: '2fa_enabled_totp' | '2fa_disabled_totp' |
                'passkey_added'    | 'passkey_removed'
    extra: optional dict of additional context (e.g. device_name)
    """
    try:
        from flask_mail import Message
        from core.extensions import mail

        subjects = {
            '2fa_enabled_totp':  'Authenticator app enabled on your Secora account',
            '2fa_disabled_totp': 'Authenticator app removed from your Secora account',
            'passkey_added':     'New passkey added to your Secora account',
            'passkey_removed':   'Passkey removed from your Secora account',
        }

        bodies = {
            '2fa_enabled_totp': f"""
Hello {user.username},

Two-factor authentication (authenticator app) has just been enabled on your
Secora account.

If this was you, no action is needed — your account is now more secure.

If you did NOT do this, your account may be compromised. Please contact us
immediately and change your password.
""",
            '2fa_disabled_totp': f"""
Hello {user.username},

Two-factor authentication has been removed from your Secora account.

If this was you, no action is needed.

If you did NOT do this, your account may be compromised. Please contact us
immediately and change your password.
""",
            'passkey_added': f"""
Hello {user.username},

A new passkey has been registered on your Secora account.
Device: {(extra or {}).get('device_name', 'Unknown device')}

If this was you, no action is needed.

If you did NOT register this passkey, your account may be compromised.
Please contact us immediately and remove the passkey from your account settings.
""",
            'passkey_removed': f"""
Hello {user.username},

A passkey has been removed from your Secora account.
Device: {(extra or {}).get('device_name', 'Unknown device')}

If this was you, no action is needed.

If you did NOT do this, please contact us immediately.
""",
        }

        subject = subjects.get(event_type, 'Security alert — Secora')
        body    = bodies.get(event_type, 'A security event occurred on your account.')

        msg = Message(
            subject=subject,
            recipients=[user.email],
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )
        msg.body = body.strip()
        mail.send(msg)

    except Exception as e:
        # Never let a notification failure break the actual operation
        current_app.logger.error(f'Security alert email failed ({event_type}): {e}')


# ===========================================================================
# TOTP — Setup
# ===========================================================================

@security_bp.route('/totp/setup', methods=['GET'])
@login_required
def totp_setup():
    if current_user.totp_enabled:
        flash('TOTP is already enabled on your account.', 'info')
        return redirect(url_for('auth.profile'))

    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    db.session.commit()

    totp    = pyotp.TOTP(secret)
    uri     = totp.provisioning_uri(name=current_user.email, issuer_name=APP_NAME)

    qr      = qrcode.QRCode(image_factory=qrcode.image.svg.SvgPathImage)
    qr.add_data(uri)
    qr.make(fit=True)
    buf     = io.BytesIO()
    qr.make_image().save(buf)
    qr_svg  = buf.getvalue().decode('utf-8')

    preview_codes = [secrets.token_hex(5).upper() for _ in range(8)]
    session['totp_pending_secret'] = secret
    session['totp_pending_codes']  = preview_codes

    return render_template('security/totp_setup.html',
                           secret=secret, qr_svg=qr_svg,
                           backup_codes=preview_codes)


@security_bp.route('/totp/verify-setup', methods=['POST'])
@login_required
def totp_verify_setup():
    if current_user.totp_enabled:
        return jsonify({'ok': False, 'error': 'TOTP already enabled'}), 400

    code   = request.form.get('code', '').strip().replace(' ', '')
    secret = session.get('totp_pending_secret')
    codes  = session.get('totp_pending_codes', [])

    if not secret or secret != current_user.totp_secret:
        flash('Setup session expired. Please start again.', 'error')
        return redirect(url_for('security.totp_setup'))

    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        flash('Incorrect code — please try again.', 'error')
        return redirect(url_for('security.totp_setup'))

    current_user.totp_backup_codes = codes
    current_user.totp_enabled      = True
    db.session.commit()

    session.pop('totp_pending_secret', None)
    session.pop('totp_pending_codes',  None)

    _send_security_alert(current_user, '2fa_enabled_totp')

    flash('Two-factor authentication enabled successfully.', 'success')
    return redirect(url_for('security.totp_backup_codes_view'))


@security_bp.route('/totp/backup-codes')
@login_required
def totp_backup_codes_view():
    if not current_user.totp_enabled:
        return redirect(url_for('auth.profile'))
    return render_template('security/totp_backup_codes.html')


@security_bp.route('/totp/new-backup-codes')
@login_required
def totp_new_codes_view():
    """Show freshly generated backup codes exactly once via session."""
    codes = session.pop('new_backup_codes', None)
    if not codes:
        # No codes in session — nothing to show
        flash('No new backup codes to display.', 'info')
        return redirect(url_for('security.totp_backup_codes_view'))
    return render_template('security/totp_new_codes.html', codes=codes)


@security_bp.route('/totp/regenerate-backup-codes', methods=['POST'])
@login_required
def totp_regenerate_backup_codes():
    if not current_user.totp_enabled:
        return redirect(url_for('auth.profile'))

    code = request.form.get('code', '').strip()
    ok, err = _verify_auth(totp_code=code)
    if not ok:
        flash(err, 'error')
        return redirect(url_for('auth.profile'))

    new_codes = current_user.generate_backup_codes()
    db.session.commit()
    # Store new codes in session for one-time display
    session['new_backup_codes'] = new_codes
    return redirect(url_for('security.totp_new_codes_view'))


@security_bp.route('/totp/disable', methods=['POST'])
@login_required
def totp_disable():
    if not current_user.totp_enabled:
        flash('TOTP is not enabled.', 'info')
        return redirect(url_for('auth.profile'))

    code     = request.form.get('code', '').strip()
    password = request.form.get('password', '')
    ok, err  = _verify_auth(password=password or None, totp_code=code or None)
    if not ok:
        flash(err, 'error')
        return redirect(url_for('auth.profile'))

    current_user._totp_secret       = None
    current_user._totp_backup_codes = None
    current_user.totp_enabled       = False
    db.session.commit()

    _send_security_alert(current_user, '2fa_disabled_totp')

    flash('Two-factor authentication has been disabled.', 'success')
    return redirect(url_for('auth.profile'))


# ===========================================================================
# Passkeys — Registration
# ===========================================================================

@security_bp.route('/passkeys/register/begin', methods=['POST'])
@login_required
def passkey_register_begin():
    exclude = [
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in current_user.passkey_credentials
    ]

    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name=APP_NAME,
        user_name=current_user.username,
        user_id=str(current_user.id).encode(),
        user_display_name=current_user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=exclude,
    )

    session['passkey_reg_challenge'] = base64.b64encode(options.challenge).decode()
    return jsonify(json.loads(options_to_json(options)))


@security_bp.route('/passkeys/register/complete', methods=['POST'])
@login_required
def passkey_register_complete():
    challenge_b64 = session.pop('passkey_reg_challenge', None)
    if not challenge_b64:
        return jsonify({'ok': False, 'error': 'No pending registration'}), 400

    expected_challenge = base64.b64decode(challenge_b64)
    data               = request.get_json(silent=True) or {}
    device_name        = str(data.get('device_name', 'Passkey'))[:100]
    cred_data          = data.get('credential', {})

    if not cred_data:
        return jsonify({'ok': False, 'error': 'Missing credential data'}), 400

    try:
        resp = cred_data.get('response', {})

        credential = RegistrationCredential(
            id=cred_data['id'],
            raw_id=_b64url_to_bytes(cred_data['rawId']),
            response=AuthenticatorAttestationResponse(
                client_data_json=_b64url_to_bytes(resp['clientDataJSON']),
                attestation_object=_b64url_to_bytes(resp['attestationObject']),
            ),
        )

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
        )
    except Exception as e:
        current_app.logger.error(f'Passkey registration error: {e}')
        return jsonify({'ok': False, 'error': 'Registration verification failed'}), 400

    cred = PasskeyCredential(
        user_id       = current_user.id,
        credential_id = verification.credential_id,
        public_key    = verification.credential_public_key,
        sign_count    = verification.sign_count,
        device_name   = device_name,
        aaguid        = verification.aaguid if verification.aaguid else None,
    )
    db.session.add(cred)
    current_user.passkeys_enabled = True
    db.session.commit()

    _send_security_alert(current_user, 'passkey_added', {'device_name': device_name})

    return jsonify({'ok': True, 'device_name': device_name})


# ===========================================================================
# Passkeys — Authentication
# ===========================================================================

@security_bp.route('/passkeys/authenticate/begin', methods=['POST'])
def passkey_authenticate_begin():
    username = ''
    if request.is_json:
        username = (request.get_json(silent=True) or {}).get('username', '').strip()

    allow = []
    if username:
        user = User.query.filter_by(username=username).first()
        if user and user.passkeys_enabled:
            allow = [
                PublicKeyCredentialDescriptor(id=cred.credential_id)
                for cred in user.passkey_credentials
            ]

    options = generate_authentication_options(
        rp_id=_rp_id(),
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    session['passkey_auth_challenge'] = base64.b64encode(options.challenge).decode()
    if username:
        session['passkey_auth_username'] = username

    return jsonify(json.loads(options_to_json(options)))


@security_bp.route('/passkeys/authenticate/complete', methods=['POST'])
def passkey_authenticate_complete():
    challenge_b64 = session.pop('passkey_auth_challenge', None)
    session.pop('passkey_auth_username', None)
    remember      = session.pop('pending_2fa_remember', False)

    if not challenge_b64:
        return jsonify({'ok': False, 'error': 'No pending authentication'}), 400

    expected_challenge = base64.b64decode(challenge_b64)
    data               = request.get_json(silent=True) or {}

    try:
        resp = data.get('response', {})

        user_handle_raw = resp.get('userHandle')
        user_handle     = _b64url_to_bytes(user_handle_raw) if user_handle_raw else None

        credential = AuthenticationCredential(
            id=data['id'],
            raw_id=_b64url_to_bytes(data['rawId']),
            response=AuthenticatorAssertionResponse(
                client_data_json=_b64url_to_bytes(resp['clientDataJSON']),
                authenticator_data=_b64url_to_bytes(resp['authenticatorData']),
                signature=_b64url_to_bytes(resp['signature']),
                user_handle=user_handle,
            ),
        )

        # Look up stored credential by credential_id (bytes)
        cred_id_bytes = _b64url_to_bytes(data['rawId'])
        db_cred = PasskeyCredential.query.filter_by(
            credential_id=cred_id_bytes
        ).first()
        if not db_cred:
            return jsonify({'ok': False, 'error': 'Unknown credential'}), 400

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
            credential_public_key=db_cred.public_key,
            credential_current_sign_count=db_cred.sign_count,
            require_user_verification=False,
        )
    except Exception as e:
        current_app.logger.error(f'Passkey authentication error: {e}')
        return jsonify({'ok': False, 'error': 'Authentication verification failed'}), 400

    db_cred.sign_count   = verification.new_sign_count
    db_cred.last_used_at = datetime.now(timezone.utc)
    db.session.commit()

    user = db_cred.user

    # Step-up auth (logged-in user confirming a sensitive action)
    if current_user.is_authenticated:
        session['passkey_verified'] = True
        return jsonify({'ok': True, 'step_up': True})

    # Full login
    login_user(user, remember=remember)
    flash(f'Welcome back, {user.username}!', 'success')
    return jsonify({'ok': True, 'step_up': False, 'redirect': url_for('main.index')})


# ===========================================================================
# Passkeys — Management
# ===========================================================================

@security_bp.route('/passkeys/<int:cred_id>/rename', methods=['POST'])
@login_required
def passkey_rename(cred_id):
    cred = PasskeyCredential.query.filter_by(
        id=cred_id, user_id=current_user.id
    ).first_or_404()

    new_name = (request.form.get('device_name', '') or '').strip()[:100]
    if not new_name:
        return jsonify({'ok': False, 'error': 'Name cannot be empty'}), 400

    cred.device_name = new_name
    db.session.commit()
    return jsonify({'ok': True})


@security_bp.route('/passkeys/<int:cred_id>/delete', methods=['POST'])
@login_required
def passkey_delete(cred_id):
    cred = PasskeyCredential.query.filter_by(
        id=cred_id, user_id=current_user.id
    ).first_or_404()

    code     = request.form.get('code', '').strip()
    password = request.form.get('password', '')
    ok, err  = _verify_auth(password=password or None, totp_code=code or None)
    if not ok:
        flash(err, 'error')
        return redirect(url_for('auth.profile'))

    device_name = cred.device_name
    db.session.delete(cred)

    remaining = PasskeyCredential.query.filter_by(user_id=current_user.id).count()
    if remaining == 0:
        current_user.passkeys_enabled = False

    db.session.commit()

    _send_security_alert(current_user, 'passkey_removed', {'device_name': device_name})

    flash(f'Passkey "{device_name}" removed.', 'success')
    return redirect(url_for('auth.profile'))
