"""
routes/auth.py — Authentication blueprint: login, register, email
confirmation, logout, profile, and history.
"""

from datetime import datetime, timezone

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from core.extensions import db, socketio
from core.models import IPReport, SearchHistory, User
from services import mail_check
from services.email_verification import EmailVerification
from core.utils import is_valid_ip, sanitize_string

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
        user = User.query.filter_by(username=username_param).first()
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

        user = User.query.filter_by(username=username).first()

        if user:
            if not user.email_confirmed:
                flash('Please confirm your email before logging in.', 'error')
                show_resend  = True
                pending_user = user
                return render_template('auth/login.html',
                                       show_resend=show_resend,
                                       pending_user=pending_user)

            if user.check_password(password):
                login_user(user, remember=remember)
                flash(f'Welcome back, {user.username}!', 'success')
                next_page = request.args.get('next')
                if not next_page or not next_page.startswith('/'):
                    next_page = url_for('main.index')
                return redirect(next_page)

        flash('Invalid username or password.', 'error')
        if user and not user.email_confirmed:
            show_resend  = True
            pending_user = user

    return render_template('auth/login.html',
                           show_resend=show_resend,
                           pending_user=pending_user)


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

        if len(password) < 15:
            flash('Password must be at least 15 characters long.', 'error')
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
            _email_verifier().send_confirmation(user)
            flash('Account created! Please check your email to verify.', 'success')
            return redirect(url_for('auth.login', username=username))
        except Exception:
            db.session.rollback()
            flash('Registration failed. Please try again or contact support.', 'error')

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


@auth_bp.route('/resend-confirmation', methods=['POST'])
def resend_confirmation():
    email = request.form.get('email')
    if not email:
        flash('Invalid request.', 'error')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first()

    if not user or user.email_confirmed:
        flash('Your email is already confirmed.', 'info')
        return redirect(url_for('auth.login'))

    if _email_verifier().send_confirmation(user):
        flash('Confirmation email resent. Check your spam folder if needed.', 'success')
    else:
        flash('Please wait before resending the confirmation email.', 'error')

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
