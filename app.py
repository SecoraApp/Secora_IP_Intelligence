from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
import json
import re
import concurrent.futures
import time
import html
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
from functools import wraps
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import ipaddress
import threading
from flask_socketio import SocketIO, emit, join_room
from flask_mail import Mail
from email_verification import EmailVerification
from utils import *
from services import *
from models import *

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ip_lookup.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
socketio = SocketIO(app)

app_pass = os.environ.get('APP_KEY')
mail = Mail()
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME="secoraapp@gmail.com",
    MAIL_PASSWORD=app_pass,
    MAIL_DEFAULT_SENDER="Secora <your@gmail.com>"
)
mail.init_app(app)
email_verifier = EmailVerification(mail)

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        # If there's a schema error, return None to log out the user
        print(f"User loading error (schema mismatch): {e}")
        return None

@app.after_request
def after_request(response):
    """Add security headers"""
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
        "font-src 'self' cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )

    # Other security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Remove server information
    response.headers.pop('Server', None)

    return response

@app.route('/')
def index():
    """Main page with IP lookup form"""
    lookups_today = 0
    if current_user.is_authenticated:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).date()
        lookups_today = SearchHistory.query.filter(
            SearchHistory.user_id == current_user.id,
            SearchHistory.search_type == 'ip_lookup',
            db.func.date(SearchHistory.timestamp) == today
        ).count()
    return render_template('index.html', lookups_today=lookups_today)

@app.route('/my-ip', methods=['GET'])
@rate_limit(max_requests=5, window_seconds=60)  # Limit to 5 requests per minute
def get_my_ip():
    """Get the client's actual public IP address"""
    try:
        # First try to get from request headers (for deployed apps)
        client_ip = get_client_ip()

        # If it's a private/localhost IP, use external service
        if client_ip in ['127.0.0.1', 'localhost'] or not is_valid_ip(client_ip):
            # Use external service to get real public IP
            ip_services = [
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip',
                'https://ipinfo.io/json'
            ]

            for service in ip_services:
                try:
                    headers = {
                        'User-Agent': 'Secora-Intelligence-Platform/1.0',
                        'Accept': 'application/json'
                    }
                    response = requests.get(service, timeout=5, headers=headers, verify=True)

                    if response.status_code == 200:
                        data = response.json()

                        # Different services return IP in different formats
                        user_ip = None
                        if 'ip' in data:
                            user_ip = sanitize_string(str(data['ip']))
                        elif 'origin' in data:  # httpbin format
                            user_ip = sanitize_string(str(data['origin']))

                        # Validate the IP
                        if user_ip and is_valid_ip(user_ip):
                            return jsonify({
                                'success': True,
                                'ip': user_ip,
                                'service': sanitize_string(service)
                            })

                except (requests.RequestException, json.JSONDecodeError, KeyError):
                    continue

            # If all external services fail, return error
            return jsonify({'error': 'Could not determine your public IP address'}), 400
        else:
            # Use the client IP from headers if it's valid
            return jsonify({
                'success': True,
                'ip': client_ip
            })

    except Exception as e:
        app.logger.error(f"Error getting client IP: {str(e)}")
        return jsonify({'error': 'Could not determine your IP address'}), 500

@app.route('/lookup', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)  # Limit to 20 lookups per minute
def lookup():
    """Handle IP lookup requests"""
    try:
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        # Validate and sanitize input
        ip_address = data.get('ip_address', '')
        if not isinstance(ip_address, str):
            return jsonify({'error': 'IP address must be a string'}), 400

        ip_address = sanitize_string(ip_address.strip())

        if not ip_address:
            return jsonify({'error': 'Please enter an IP address'}), 400

        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Please enter a valid public IP address'}), 400

        # Perform the lookup
        result = lookup_ip(ip_address)

        # Log activity if user is authenticated
        if current_user.is_authenticated:
            try:
                search_record = SearchHistory(
                    user_id=current_user.id,
                    ip_address=ip_address,
                    search_type='ip_lookup'
                )
                db.session.add(search_record)
                db.session.commit()
                from datetime import datetime, timezone
                today = datetime.now(timezone.utc).date()
                lookups_today = SearchHistory.query.filter(
                    SearchHistory.user_id == current_user.id,
                    SearchHistory.search_type == 'ip_lookup',
                    db.func.date(SearchHistory.timestamp) == today
                ).count()
                result['lookups_today'] = lookups_today
                # Emit WebSocket update
                socketio.emit(
                    'lookup_count_update',
                    {'lookups_today': lookups_today},
                    room=f'user_{current_user.id}'
                )
            except Exception as log_error:
                app.logger.error(f"Failed to log search: {log_error}")
                db.session.rollback()

        return jsonify(result)

    except Exception as e:
        # Log the error (in production, use proper logging)
        app.logger.error(f"Lookup error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/report-ip', methods=['POST'])
@login_required
@rate_limit(max_requests=5, window_seconds=60)  # Limit to 5 reports per minute
def report_ip():
    """Handle IP reporting requests"""
    try:
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        # Validate and sanitize input
        ip_address = data.get('ip_address', '')
        report_type = data.get('report_type', '')
        comment = data.get('comment', '')

        if not isinstance(ip_address, str) or not isinstance(report_type, str) or not isinstance(comment, str):
            return jsonify({'error': 'All fields must be strings'}), 400

        ip_address = sanitize_string(ip_address.strip())
        report_type = sanitize_string(report_type.strip())
        comment = sanitize_string(comment.strip(), max_length=1000)

        if not ip_address:
            return jsonify({'error': 'Please enter an IP address'}), 400

        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Please enter a valid public IP address'}), 400

        if not report_type:
            return jsonify({'error': 'Please select a report type'}), 400

        if not comment:
            return jsonify({'error': 'Please provide a comment'}), 400

        # Check if user already reported this IP recently (within 24 hours)
        yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)
        existing_report = IPReport.query.filter_by(
            user_id=current_user.id,
            ip_address=ip_address
        ).filter(IPReport.timestamp > yesterday).first()

        if existing_report:
            return jsonify({'error': 'You have already reported this IP address recently'}), 400

        # Create the report
        report = IPReport(
            user_id=current_user.id,
            ip_address=ip_address,
            report_type=report_type,
            comment=comment
        )

        db.session.add(report)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'IP address reported successfully'
        })

    except Exception as e:
        app.logger.error(f"Report error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/get-ip-reports/<ip_address>', methods=['GET'])
def get_ip_reports(ip_address):
    """Get reports for a specific IP address"""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Invalid IP address'}), 400

        # Get all reports for this IP (limit to recent ones for performance)
        reports = IPReport.query.filter_by(ip_address=ip_address)\
                               .order_by(IPReport.timestamp.desc())\
                               .limit(10).all()

        reports_data = []
        for report in reports:
            reports_data.append({
                'id': report.id,
                'report_type': report.report_type,
                'comment': report.comment,
                'timestamp': report.timestamp.isoformat(),
                'username': report.user.username
            })

        return jsonify({
            'success': True,
            'reports': reports_data,
            'total_reports': len(reports_data)
        })

    except Exception as e:
        app.logger.error(f"Get reports error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/shortener')
def shortener():
    """URL shortener page"""
    return render_template('shortener.html')

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    show_resend = False
    pending_user = None

    # Check if coming from registration with username
    username_param = request.args.get('username')
    if username_param:
        user = User.query.filter_by(username=username_param).first()
        if user and not user.email_confirmed:
            show_resend = True
            pending_user = user

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('auth/login.html', show_resend=show_resend, pending_user=pending_user)

        user = User.query.filter_by(username=username).first()

        if user:
            if not user.email_confirmed:
                flash("Please confirm your email before logging in.", "error")
                show_resend = True
                pending_user = user
                return render_template('auth/login.html', show_resend=show_resend, pending_user=pending_user)

            # Confirmed user, check password
            if user.check_password(password):
                login_user(user, remember=remember)
                flash(f'Welcome back, {user.username}!', 'success')
                next_page = request.args.get('next')
                if not next_page or not next_page.startswith('/'):
                    next_page = url_for('index')
                return redirect(next_page)

        flash('Invalid username or password.', 'error')
        # Preserve user data if login failed but the user still exists
        if user and not user.email_confirmed:
            show_resend = True
            pending_user = user

    return render_template('auth/login.html', show_resend=show_resend, pending_user=pending_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
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

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html')


        # Filter out blacklisted email domains and temp mail domains.
        mail_check_flag = mail_check(email)
        if not mail_check_flag:
            flash('Email domain provided is not allowed. Please use a different email provider and try again.', 'error')
            return render_template('auth/register.html')



        # Create new user (unconfirmed)
        user = User(username=username, email=email)
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()

            email_verifier.send_confirmation(user)

            flash("Account has been created! Please check your email to verify.", "success")
            # Pass username to show resend button immediately
            return redirect(url_for("login", username=username))

        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again or contact support.', 'error')

    return render_template('auth/register.html')

@app.route("/confirm/<token>")
def confirm_email(token):
    email = email_verifier.confirm_token(token)

    if not email:
        flash("Confirmation link is invalid or expired.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first_or_404()

    if not user.email_confirmed:
        user.email_confirmed = True
        user.is_active = True
        db.session.commit()
        flash("Your email has been confirmed! You can now log in.", "success")
    else:
        flash("Your email was already confirmed.", "info")

    return redirect(url_for("login"))

@app.route('/resend-confirmation', methods=['POST'])
def resend_confirmation():
    email = request.form.get('email')

    if not email:
        flash("Invalid request.", "error")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if not user or user.email_confirmed:
        flash("Your email is already confirmed, there is no need to re confirm.", "info")
        return redirect(url_for('login'))

    if email_verifier.send_confirmation(user):
        flash("A confirmation email has been resent. If you do not see it, check your spam folder as it may have been sent there instead.", "success")
    else:
        flash("Please wait a bit before resending the confirmation email.", "error")

    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    recent_searches = SearchHistory.query.filter_by(user_id=current_user.id)\
                                        .order_by(SearchHistory.timestamp.desc())\
                                        .limit(10).all()
    return render_template('auth/profile.html', recent_searches=recent_searches)

@app.route('/history')
@login_required
def history():
    """User activity history page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20

    # Get all searches for the current user with pagination
    searches = SearchHistory.query.filter_by(user_id=current_user.id)\
                                 .order_by(SearchHistory.timestamp.desc())\
                                 .paginate(page=page, per_page=per_page, error_out=False)

    return render_template('auth/history.html', searches=searches)

@app.route('/history/delete/<int:history_id>', methods=['POST'])
@login_required
def delete_history(history_id):
    """Delete a specific history entry"""
    try:
        # Find the history entry
        history_entry = SearchHistory.query.filter_by(
            id=history_id,
            user_id=current_user.id
        ).first()

        if not history_entry:
            return jsonify({'error': 'History entry not found'}), 404

        # Delete the entry
        db.session.delete(history_entry)
        db.session.commit()

        return jsonify({'success': True, 'message': 'History entry deleted'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete history entry'}), 500

@app.route('/history/load_more')
@login_required
def load_more_history():
    """Load more history entries via AJAX"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20

        # Get searches for current page
        searches = SearchHistory.query.filter_by(user_id=current_user.id)\
                                     .order_by(SearchHistory.timestamp.desc())\
                                     .paginate(page=page, per_page=per_page, error_out=False)

        # Render just the table rows
        history_html = ""
        for search in searches.items:
            activity_type = "IP Lookup" if search.search_type == 'ip_lookup' else "URL Shortening"
            activity_data = search.ip_address if search.search_type == 'ip_lookup' else search.url_shortened
            activity_icon = "fas fa-search" if search.search_type == 'ip_lookup' else "fas fa-link"

            history_html += f'''
            <tr class="border-b border-gray-700 hover:bg-gray-700 transition-colors duration-200" data-history-id="{search.id}">
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
                    <span class="text-gray-400 text-sm">{search.timestamp.strftime('%m/%d/%Y %I:%M %p')}</span>
                </td>
                <td class="px-4 py-3 text-center">
                    <button onclick="deleteHistory({search.id})"
                            class="text-red-400 hover:text-red-300 transition-colors duration-200 p-1"
                            title="Delete this entry">
                        <i class="fas fa-trash text-sm"></i>
                    </button>
                </td>
            </tr>
            '''

        return jsonify({
            'html': history_html,
            'has_next': searches.has_next,
            'next_page': searches.next_num if searches.has_next else None
        })

    except Exception as e:
        return jsonify({'error': 'Failed to load more history'}), 500

@app.route('/shorten', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)  # Limit to 10 shortening requests per minute
def shorten_url():
    """Handle URL shortening requests"""
    try:
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        # Validate and sanitize input
        url = data.get('url', '')
        if not isinstance(url, str):
            return jsonify({'error': 'URL must be a string'}), 400

        url = sanitize_string(url.strip())

        if not url:
            return jsonify({'error': 'Please enter a URL'}), 400

        # Validate URL format
        if not is_valid_url(url):
            return jsonify({'error': 'Please enter a valid URL'}), 400

        # Perform the shortening
        result = shorten_with_multiple_services(url)

        # Log activity if user is authenticated
        if current_user.is_authenticated:
            try:
                search_record = SearchHistory(
                    user_id=current_user.id,
                    ip_address=None,  # Not applicable for URL shortening
                    search_type='url_shorten',
                    url_shortened=url
                )
                db.session.add(search_record)
                db.session.commit()
            except Exception as log_error:
                # Don't fail the request if logging fails
                app.logger.error(f"Failed to log URL shortening: {log_error}")
                db.session.rollback()

        return jsonify(result)

    except Exception as e:
        # Log the error (in production, use proper logging)
        app.logger.error(f"Shortening error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/lookup-count', methods=['GET'])
@login_required
def lookup_count():
    try:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).date()
        lookups_today = SearchHistory.query.filter(
            SearchHistory.user_id == current_user.id,
            SearchHistory.search_type == 'ip_lookup',
            db.func.date(SearchHistory.timestamp) == today
        ).count()
        return jsonify({'success': True, 'lookups_today': lookups_today, 'user_id': current_user.id, 'date': str(today)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# WebSocket join handler
@socketio.on('join')
def on_join(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')

if __name__ == '__main__':
    print("🚀 Starting Secora IP Lookup App with SocketIO...")
    socketio.run(app, debug=True)
