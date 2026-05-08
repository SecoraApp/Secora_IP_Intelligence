"""
routes/auth.py — Authentication blueprint: login, register, email
confirmation, logout, profile, and history.
"""

from datetime import datetime, timezone

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from sqlalchemy import or_
from core.extensions import db, socketio
from core.models import IPReport, SearchHistory, User
from services import mail_check
from services.email_verification import EmailVerification
from core.utils import is_valid_ip, sanitize_string, validate_password_complexity

# Imported lazily inside routes to avoid circular imports at module load:
# from routes.security import _verify_auth

auth_bp = Blueprint('auth', __name__)

# EmailVerification is set up by app.py after mail is initialised.
# Access it via current_app at runtime to avoid circular imports.


def _email_verifier():
    from flask import current_app
    return current_app.extensions['email_verifier']


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    show_resend  = False
    pending_user = None

    username_param = request.args.get('username')
    if username_param:
        user = User.query.filter(
            or_(User.username == username_param, User.email == username_param.lower())
        ).first()
        if user and not user.email_confirmed:
            show_resend  = True
            pending_user = user

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('auth/login.html',
                                   show_resend=show_resend,
                                   pending_user=pending_user)

        # Accept username or email
        user = User.query.filter(
            or_(User.username == username, User.email == username.lower())
        ).first()

        if user:
            if not user.email_confirmed:
                flash('Please confirm your email before logging in.', 'error')
                show_resend  = True
                pending_user = user
                return render_template('auth/login.html',
                                       show_resend=show_resend,
                                       pending_user=pending_user)

            if user.check_password(password):
                # ── Second factor check ───────────────────────────────────
                # Passkeys replace the password step entirely so they are
                # handled via /login/passkey — if we reach here the user
                # authenticated with a password, so only TOTP applies.
                if user.totp_enabled:
                    from flask import session
                    session['pending_2fa_user']   = user.id
                    session['pending_2fa_remember'] = bool(remember)
                    return redirect(url_for('auth.login_totp'))

                # No second factor — log straight in
                login_user(user, remember=remember)
                flash(f'Welcome back, {user.username}!', 'success')
                next_page = request.args.get('next')
                # Prevent open redirect: reject //host and /\host patterns
                if not next_page or not next_page.startswith('/'):
                    next_page = url_for('main.index')
                elif len(next_page) > 1 and next_page[1] in ('/', '\\'):
                    next_page = url_for('main.index')
                return redirect(next_page)

        flash('Invalid username or password.', 'error')
        if user and not user.email_confirmed:
            show_resend  = True
            pending_user = user

    return render_template('auth/login.html',
                           show_resend=show_resend,
                           pending_user=pending_user)


@auth_bp.route('/login/totp', methods=['GET', 'POST'])
def login_totp():
    """
    Step 2 of login when TOTP is enabled.
    The user already proved their password — we just need the 6-digit code.
    Session key 'pending_2fa_user' holds the user ID until verified.
    """
    from flask import session
    user_id  = session.get('pending_2fa_user')
    remember = session.get('pending_2fa_remember', False)

    if not user_id:
        # No pending auth — send back to login
        return redirect(url_for('auth.login'))

    user = db.session.get(User, user_id)
    if not user:
        session.pop('pending_2fa_user', None)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code       = request.form.get('code', '').strip().replace(' ', '')
        use_backup = request.form.get('use_backup', '')

        if use_backup:
            backup_code = request.form.get('backup_code', '').strip()
            if not backup_code:
                flash('Please enter a backup code.', 'error')
                return render_template('auth/login_totp.html',
                                       username=user.username, show_backup=True)
            if not user.consume_backup_code(backup_code):
                flash('Invalid backup code.', 'error')
                return render_template('auth/login_totp.html',
                                       username=user.username, show_backup=True)
            db.session.commit()
        else:
            if not code or len(code) != 6 or not code.isdigit():
                flash('Please enter the 6-digit code from your authenticator app.', 'error')
                return render_template('auth/login_totp.html', username=user.username)

            import pyotp
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(code, valid_window=1):
                flash('Invalid or expired code. Please try again.', 'error')
                return render_template('auth/login_totp.html', username=user.username)

        session.pop('pending_2fa_user', None)
        session.pop('pending_2fa_remember', None)
        login_user(user, remember=remember)
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('main.index'))

    return render_template('auth/login_totp.html', username=user.username)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


# ---------------------------------------------------------------------------
# Registration & email confirmation
# ---------------------------------------------------------------------------

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username         = request.form.get('username', '').strip()
        email            = request.form.get('email', '').strip()
        password         = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not all([username, email, password, confirm_password]):
            flash('Please fill in all fields.', 'error')
            return render_template('auth/register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')

        pw_ok, pw_err = validate_password_complexity(password)
        if not pw_ok:
            flash(pw_err, 'error')
            return render_template('auth/register.html')

        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('auth/register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html')

        if not mail_check(email):
            flash('Email domain is not allowed. Please use a different provider.',
                  'error')
            return render_template('auth/register.html')

        user = User(username=username, email=email)
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Registration DB error for {username!r}: {e}')
            flash('Registration failed. Please try again or contact support.', 'error')
            return render_template('auth/register.html')

        # Email send is separate — a mail failure shouldn't undo the account
        try:
            _email_verifier().send_confirmation(user)
        except Exception as e:
            current_app.logger.error(f'Confirmation email failed for {username!r}: {e}')
            flash(
                'Account created but we could not send a confirmation email. '
                'Please use the resend option on the login page.',
                'error'
            )
            return redirect(url_for('auth.login', username=username))

        flash('Account created! Please check your email to verify.', 'success')
        return redirect(url_for('auth.login', username=username))

    return render_template('auth/register.html')


@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    email = _email_verifier().confirm_token(token)
    if not email:
        flash('Confirmation link is invalid or expired.', 'error')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first_or_404()

    if not user.email_confirmed:
        user.email_confirmed = True
        user.is_active = True
        db.session.commit()
        flash('Email confirmed! You can now log in.', 'success')
    else:
        flash('Your email was already confirmed.', 'info')

    return redirect(url_for('auth.login'))


@auth_bp.route('/resend-confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    # GET — show a simple form to enter email and request resend
    if request.method == 'GET':
        return render_template('auth/resend_confirmation.html')

    email = request.form.get('email', '').strip().lower()
    if not email:
        flash('Please enter your email address.', 'error')
        return render_template('auth/resend_confirmation.html')

    user = User.query.filter_by(email=email).first()

    # Don't reveal whether the email exists — same response either way
    if not user or user.email_confirmed:
        flash('If that email is registered and unconfirmed, a new link is on its way.', 'info')
        return redirect(url_for('auth.login'))

    try:
        sent = _email_verifier().send_confirmation(user)
        if sent:
            flash('Confirmation email sent. Check your inbox and spam folder.', 'success')
        else:
            flash('Please wait a few minutes before requesting another confirmation email.', 'error')
    except Exception as e:
        current_app.logger.error(f'Resend confirmation failed for {email!r}: {e}')
        flash('Could not send email right now. Please try again shortly.', 'error')

    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------------------
# Profile & history
# ---------------------------------------------------------------------------

@auth_bp.route('/profile')
@login_required
def profile():
    recent = (SearchHistory.query
              .filter_by(user_id=current_user.id)
              .order_by(SearchHistory.timestamp.desc())
              .limit(10).all())
    return render_template('auth/profile.html', recent_searches=recent)


@auth_bp.route('/history')
@login_required
def history():
    page    = request.args.get('page', 1, type=int)
    per_page = 20
    searches = (SearchHistory.query
                .filter_by(user_id=current_user.id)
                .order_by(SearchHistory.timestamp.desc())
                .paginate(page=page, per_page=per_page, error_out=False))
    return render_template('auth/history.html', searches=searches)


@auth_bp.route('/history/delete/<int:history_id>', methods=['POST'])
@login_required
def delete_history(history_id):
    try:
        entry = SearchHistory.query.filter_by(
            id=history_id, user_id=current_user.id
        ).first()
        if not entry:
            return jsonify({'error': 'History entry not found'}), 404
        db.session.delete(entry)
        db.session.commit()
        return jsonify({'success': True, 'message': 'History entry deleted'})
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete history entry'}), 500


@auth_bp.route('/history/load_more')
@login_required
def load_more_history():
    try:
        page     = request.args.get('page', 1, type=int)
        per_page = 20
        searches = (SearchHistory.query
                    .filter_by(user_id=current_user.id)
                    .order_by(SearchHistory.timestamp.desc())
                    .paginate(page=page, per_page=per_page, error_out=False))

        rows = ''
        for s in searches.items:
            activity_type = 'IP Lookup' if s.search_type == 'ip_lookup' else 'URL Shortening'
            activity_data = s.ip_address if s.search_type == 'ip_lookup' else s.url_shortened
            activity_icon = 'fas fa-search' if s.search_type == 'ip_lookup' else 'fas fa-link'

            rows += f'''
            <tr class="border-b border-gray-700 hover:bg-gray-700 transition-colors duration-200"
                data-history-id="{s.id}">
                <td class="px-4 py-3">
                    <div class="flex items-center space-x-2">
                        <i class="{activity_icon} text-blue-400"></i>
                        <span class="text-white font-medium">{activity_type}</span>
                    </div>
                </td>
                <td class="px-4 py-3">
                    <span class="text-gray-300 break-all">{activity_data}</span>
                </td>
                <td class="px-4 py-3">
                    <span class="text-gray-400 text-sm">
                        {s.timestamp.strftime('%m/%d/%Y %I:%M %p')}
                    </span>
                </td>
                <td class="px-4 py-3 text-center">
                    <button onclick="deleteHistory({s.id})"
                            class="text-red-400 hover:text-red-300 transition-colors p-1"
                            title="Delete this entry">
                        <i class="fas fa-trash text-sm"></i>
                    </button>
                </td>
            </tr>
            '''

        return jsonify({
            'html':      rows,
            'has_next':  searches.has_next,
            'next_page': searches.next_num if searches.has_next else None,
        })
    except Exception:
        return jsonify({'error': 'Failed to load more history'}), 500


# ---------------------------------------------------------------------------
# Account settings — username, email, password, delete
# ---------------------------------------------------------------------------

def _get_verify_auth():
    from routes.security import _verify_auth
    return _verify_auth


@auth_bp.route('/settings/username', methods=['POST'])
@login_required
def update_username():
    new_username = request.form.get('new_username', '').strip()

    if not new_username:
        flash('Please enter a new username.', 'error')
        return redirect(url_for('auth.profile'))

    if len(new_username) < 3:
        flash('Username must be at least 3 characters.', 'error')
        return redirect(url_for('auth.profile'))

    # Rate limit: max 2 changes per 30 days
    if not current_user.can_change_username():
        next_at = current_user.next_username_change_at()
        when    = next_at.strftime('%B %d at %I:%M %p UTC') if next_at else 'later'
        flash(
            f'You have used both username changes for this 30-day period. '
            f'You can change it again after {when}.',
            'error'
        )
        return redirect(url_for('auth.profile'))

    if User.query.filter_by(username=new_username).first():
        flash('That username is already taken.', 'error')
        return redirect(url_for('auth.profile'))

    try:
        current_user.username = new_username
        current_user.record_username_change()
        db.session.commit()
        flash('Username updated successfully.', 'success')
    except Exception:
        db.session.rollback()
        flash('Failed to update username. Please try again.', 'error')

    return redirect(url_for('auth.profile'))


@auth_bp.route('/settings/email', methods=['POST'])
@login_required
def update_email():
    new_email        = request.form.get('new_email', '').strip()
    confirm_password = request.form.get('confirm_password', '')

    if not new_email or not confirm_password:
        flash('All fields are required.', 'error')
        return redirect(url_for('auth.profile'))

    # Rate limit: max 2 email changes per 24 hours
    if not current_user.can_change_email():
        flash('You can only change your email address twice per day. Please try again tomorrow.', 'error')
        return redirect(url_for('auth.profile'))

    verify_auth = _get_verify_auth()
    code = request.form.get('totp_code', '').strip()
    ok, err = verify_auth(
        password=confirm_password or None,
        totp_code=code or None,
    )
    if not ok:
        flash(err, 'error')
        return redirect(url_for('auth.profile'))

    if User.query.filter_by(email=new_email).first():
        flash('That email address is already in use.', 'error')
        return redirect(url_for('auth.profile'))

    if not mail_check(new_email):
        flash('That email domain is not allowed.', 'error')
        return redirect(url_for('auth.profile'))

    try:
        current_user.pending_email = new_email
        current_user.record_email_change()
        db.session.commit()
        _email_verifier().send_email_change_confirmation(current_user, new_email)
        flash('Confirmation email sent. Check your inbox to complete the change.', 'success')
    except Exception:
        db.session.rollback()
        flash('Failed to send confirmation email. Please try again.', 'error')

    return redirect(url_for('auth.profile'))


@auth_bp.route('/settings/confirm-email-change/<token>')
def confirm_email_change(token):
    result = _email_verifier().confirm_email_change_token(token)
    if not result:
        flash('Confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('auth.profile'))

    user_id, new_email = result
    user = db.session.get(User, user_id)
    if not user:
        flash('Account not found.', 'error')
        return redirect(url_for('auth.login'))

    if User.query.filter_by(email=new_email).first():
        flash('That email address is already in use.', 'error')
        return redirect(url_for('auth.profile'))

    try:
        user.email           = new_email
        user.email_confirmed = True
        if hasattr(user, 'pending_email'):
            user.pending_email = None
        db.session.commit()
        flash('Email address updated successfully.', 'success')
    except Exception:
        db.session.rollback()
        flash('Failed to update email. Please try again.', 'error')

    return redirect(url_for('auth.profile'))


@auth_bp.route('/settings/password', methods=['POST'])
@login_required
def update_password():
    current_password     = request.form.get('current_password', '')
    new_password         = request.form.get('new_password', '')
    confirm_new_password = request.form.get('confirm_new_password', '')
    totp_code            = request.form.get('totp_code', '').strip()

    if not all([current_password, new_password, confirm_new_password]):
        flash('All fields are required.', 'error')
        return redirect(url_for('auth.profile'))

    # Rate limit: max 2 password changes per 24 hours
    if not current_user.can_change_password():
        flash('You can only change your password twice per day. Please try again tomorrow.', 'error')
        return redirect(url_for('auth.profile'))

    # Current password is always required to change your password —
    # it proves you know the credential you are replacing.
    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('auth.profile'))

    # If 2FA is also enabled, require that as an additional gate.
    if current_user.totp_enabled:
        verify_auth = _get_verify_auth()
        ok, err = verify_auth(totp_code=totp_code or None)
        if not ok:
            flash(err, 'error')
            return redirect(url_for('auth.profile'))

    if new_password != confirm_new_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('auth.profile'))

    pw_ok, pw_err = validate_password_complexity(new_password)
    if not pw_ok:
        flash(pw_err, 'error')
        return redirect(url_for('auth.profile'))

    if current_password == new_password:
        flash('New password must be different from your current password.', 'error')
        return redirect(url_for('auth.profile'))

    try:
        current_user.set_password(new_password)
        current_user.record_password_change()
        db.session.commit()
        flash('Password updated successfully.', 'success')
    except Exception:
        db.session.rollback()
        flash('Failed to update password. Please try again.', 'error')

    return redirect(url_for('auth.profile'))


@auth_bp.route('/settings/delete', methods=['POST'])
@login_required
def delete_account():
    confirm_username = request.form.get('confirm_username', '').strip()
    confirm_password = request.form.get('confirm_password', '')

    if confirm_username != current_user.username:
        flash('Username confirmation did not match.', 'error')
        return redirect(url_for('auth.profile'))

    verify_auth = _get_verify_auth()
    code = request.form.get('totp_code', '').strip()
    ok, err = verify_auth(
        password=confirm_password or None,
        totp_code=code or None,
    )
    if not ok:
        flash(err, 'error')
        return redirect(url_for('auth.profile'))

    try:
        # Delete all associated data first
        SearchHistory.query.filter_by(user_id=current_user.id).delete()
        IPReport.query.filter_by(user_id=current_user.id).delete()
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Your account and all associated data have been permanently deleted.', 'info')
        return redirect(url_for('main.index'))
    except Exception:
        db.session.rollback()
        flash('Failed to delete account. Please try again or contact support.', 'error')
        return redirect(url_for('auth.profile'))


# ---------------------------------------------------------------------------
# Microsoft admin consent OAuth flow
# ---------------------------------------------------------------------------

import os
import secrets
import requests as http_requests
from urllib.parse import urlencode

MS_CLIENT_ID    = os.environ.get('MS_CLIENT_ID', '')
MS_CLIENT_SECRET = os.environ.get('MS_CLIENT_SECRET', '')
MS_REDIRECT_URI = os.environ.get('MS_REDIRECT_URI', '')   # e.g. https://secora.app/auth/callback
MS_GRAPH_SCOPES = 'https://graph.microsoft.com/.default'

# Admin consent endpoint — Microsoft enforces that only org admins can complete this
_MS_CONSENT_BASE = 'https://login.microsoftonline.com/organizations/v2.0/adminconsent'
_MS_TOKEN_URL    = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
_MS_GRAPH_ME     = 'https://graph.microsoft.com/v1.0/me'


@auth_bp.route('/microsoft/link')
@login_required
def microsoft_link():
    """
    Start the Microsoft admin consent flow.
    Generates a CSRF state token, stores it in the session, then
    redirects the user to Microsoft's admin consent screen.
    Only org admins can complete the flow — everyone else sees an
    error page on the Microsoft side.
    """
    if not MS_CLIENT_ID or not MS_REDIRECT_URI:
        flash('Microsoft integration is not configured yet.', 'error')
        return redirect(url_for('auth.profile'))

    if current_user.ms_linked:
        flash('A Microsoft organisation account is already linked.', 'info')
        return redirect(url_for('auth.profile'))

    # CSRF protection — tie the state to this user's session
    state = secrets.token_urlsafe(32)
    from flask import session
    session['ms_oauth_state'] = state
    session['ms_oauth_user']  = current_user.id

    params = {
        'client_id':    MS_CLIENT_ID,
        'redirect_uri': MS_REDIRECT_URI,
        'state':        state,
        'scope':        MS_GRAPH_SCOPES,
    }
    consent_url = f'{_MS_CONSENT_BASE}?{urlencode(params)}'
    return redirect(consent_url)


@auth_bp.route('/callback')
@login_required
def microsoft_callback():
    """
    Microsoft redirects here after admin consent.
    Validates state, exchanges the code for tokens, fetches the user's
    Microsoft profile, then stores tenant + account info on the Secora user.
    """
    from flask import session

    # ── Error returned by Microsoft (e.g. user is not an org admin) ──────
    ms_error       = request.args.get('error')
    ms_error_desc  = request.args.get('error_description', '')

    if ms_error:
        # Common case: non-admin clicked through — give a clear message
        if 'AADSTS65004' in ms_error_desc or 'admin' in ms_error_desc.lower():
            flash(
                'Your Microsoft account does not have organisation admin privileges. '
                'Only Azure AD administrators can link a Microsoft organisation.',
                'error'
            )
        else:
            flash(f'Microsoft authorisation failed: {ms_error_desc or ms_error}', 'error')
        return redirect(url_for('auth.profile'))

    # ── CSRF state check ─────────────────────────────────────────────────
    returned_state  = request.args.get('state', '')
    expected_state  = session.pop('ms_oauth_state', None)
    expected_user   = session.pop('ms_oauth_user', None)

    if not returned_state or returned_state != expected_state:
        flash('Invalid OAuth state. Please try linking again.', 'error')
        return redirect(url_for('auth.profile'))

    if expected_user != current_user.id:
        flash('Session mismatch. Please try linking again.', 'error')
        return redirect(url_for('auth.profile'))

    # ── Exchange code for tokens ──────────────────────────────────────────
    code = request.args.get('code')
    if not code:
        flash('No authorisation code received from Microsoft.', 'error')
        return redirect(url_for('auth.profile'))

    try:
        token_resp = http_requests.post(_MS_TOKEN_URL, data={
            'client_id':     MS_CLIENT_ID,
            'client_secret': MS_CLIENT_SECRET,
            'code':          code,
            'redirect_uri':  MS_REDIRECT_URI,
            'grant_type':    'authorization_code',
            'scope':         MS_GRAPH_SCOPES,
        }, timeout=10)
        token_resp.raise_for_status()
        token_data = token_resp.json()
    except Exception as e:
        current_app.logger.error(f'MS token exchange failed: {e}')
        flash('Failed to complete Microsoft authorisation. Please try again.', 'error')
        return redirect(url_for('auth.profile'))

    access_token = token_data.get('access_token')
    if not access_token:
        flash('Microsoft did not return a valid access token.', 'error')
        return redirect(url_for('auth.profile'))

    # ── Fetch org / tenant info from Graph API ────────────────────────────
    try:
        me_resp = http_requests.get(
            _MS_GRAPH_ME,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        me_resp.raise_for_status()
        me_data = me_resp.json()
    except Exception as e:
        current_app.logger.error(f'MS Graph /me failed: {e}')
        flash('Linked with Microsoft but could not fetch account details.', 'error')
        return redirect(url_for('auth.profile'))

    tenant_id    = me_data.get('id') or token_data.get('tid')
    ms_email     = me_data.get('mail') or me_data.get('userPrincipalName', '')

    # Pull tenant ID from the ID token claims if Graph didn't surface it
    if not tenant_id:
        # Decode the middle (payload) section of the JWT without verifying —
        # we only need the tid claim for storage; Microsoft already verified the token
        import base64, json as _json
        try:
            id_token = token_data.get('id_token', '')
            if id_token:
                payload = id_token.split('.')[1]
                payload += '=' * (4 - len(payload) % 4)  # fix padding
                claims  = _json.loads(base64.b64decode(payload))
                tenant_id = claims.get('tid', '')
        except Exception:
            pass

    if not tenant_id:
        flash('Could not determine your Microsoft tenant ID. Please try again.', 'error')
        return redirect(url_for('auth.profile'))

    # ── Persist to database ───────────────────────────────────────────────
    try:
        current_user.ms_tenant_id     = tenant_id
        current_user.ms_account_email = ms_email
        current_user.ms_linked_at     = datetime.now(timezone.utc)
        current_user.ms_admin_consent = True
        db.session.commit()
        flash(
            f'Microsoft organisation account linked successfully'
            f'{" (" + ms_email + ")" if ms_email else ""}.',
            'success'
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Failed to save MS link: {e}')
        flash('Authorisation succeeded but we could not save the link. Please try again.', 'error')

    return redirect(url_for('auth.profile'))


@auth_bp.route('/microsoft/unlink', methods=['POST'])
@login_required
def microsoft_unlink():
    """Remove the Microsoft organisation link from this account."""
    if not current_user.ms_linked:
        flash('No Microsoft account is currently linked.', 'info')
        return redirect(url_for('auth.profile'))

    confirm_password = request.form.get('confirm_password', '')
    verify_auth = _get_verify_auth()
    code = request.form.get('totp_code', '').strip()
    ok, err = verify_auth(
        password=confirm_password or None,
        totp_code=code or None,
    )
    if not ok:
        flash(err, 'error')
        return redirect(url_for('auth.profile'))

    try:
        current_user.unlink_microsoft()
        db.session.commit()
        flash('Microsoft organisation account unlinked.', 'success')
    except Exception:
        db.session.rollback()
        flash('Failed to unlink. Please try again.', 'error')

    return redirect(url_for('auth.profile'))



# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """
    Step 1 — collect the user's email and send a reset link.
    Never reveals whether the email exists in the database.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        on_cooldown = False
        if email:
            # Check rate limit first — do this before querying the user so
            # we don't accidentally leak whether an account exists via timing
            rate_ok = _email_verifier().can_send_reset(email)
            if not rate_ok:
                on_cooldown = True
            else:
                user = User.query.filter_by(email=email).first()
                if user and user.email_confirmed:
                    try:
                        _email_verifier().send_password_reset(user)
                    except Exception as e:
                        current_app.logger.error(f'Password reset send failed for {email!r}: {e}')

        if on_cooldown:
            flash(
                'A reset link was already sent to that address recently. '
                'Please wait before requesting another — '
                'check your inbox and spam folder for the existing link (valid for 5 minutes).',
                'error'
            )
        else:
            flash(
                'If an account with that email exists, a reset link is on its way. '
                'Check your inbox and spam folder. The link expires in 5 minutes.',
                'info'
            )
        return redirect(url_for('auth.forgot_password'))

    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def password_reset(token):
    """
    Step 2 — validate the token and set a new password.
    If the user has 2FA enabled, also require a TOTP code.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    # Validate token on every request
    user_id = _email_verifier().confirm_reset_token(token)
    if not user_id:
        flash('This reset link is invalid or has expired (links expire after 5 minutes). Please request a new one.', 'error')
        return redirect(url_for('auth.forgot_password'))

    user = db.session.get(User, user_id)
    if not user:
        flash('Account not found.', 'error')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        new_password         = request.form.get('new_password', '')
        confirm_new_password = request.form.get('confirm_new_password', '')
        totp_code            = request.form.get('totp_code', '').strip()

        # Password complexity
        pw_ok, pw_err = validate_password_complexity(new_password)
        if not pw_ok:
            flash(pw_err, 'error')
            return render_template('auth/password_reset.html',
                                   token=token, user=user)

        if new_password != confirm_new_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/password_reset.html',
                                   token=token, user=user)

        # If 2FA is enabled, verify TOTP before applying the reset
        if user.totp_enabled:
            if not totp_code:
                flash('Please enter your authenticator code to confirm.', 'error')
                return render_template('auth/password_reset.html',
                                       token=token, user=user)
            import pyotp
            if not pyotp.TOTP(user.totp_secret).verify(totp_code, valid_window=1):
                flash('Invalid or expired authenticator code.', 'error')
                return render_template('auth/password_reset.html',
                                       token=token, user=user)

        try:
            user.set_password(new_password)
            user.record_password_change()
            db.session.commit()

            # Notify the user their password changed
            try:
                _email_verifier().send_password_changed_alert(user)
            except Exception as e:
                current_app.logger.error(f'Password change alert failed: {e}')

            flash('Password reset successfully. You can now sign in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Password reset DB error: {e}')
            flash('Failed to reset password. Please try again.', 'error')

    return render_template('auth/password_reset.html', token=token, user=user)
