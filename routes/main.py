import os
"""
routes/main.py — Main blueprint: IP lookup, reporting, URL shortener, and
client-IP detection.
"""

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps

import requests
from flask import (Blueprint, current_app, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required
from flask_socketio import emit, join_room

from core.extensions import db, socketio
from core.models import IPReport, SearchHistory
from services import lookup_ip, shorten_with_multiple_services
from core.utils import (is_valid_ip, is_valid_url, sanitize_string,
                        validate_report_type, ALLOWED_REPORT_TYPES)

main_bp = Blueprint('main', __name__)

# ---------------------------------------------------------------------------
# Rate limiting (in-process; swap for Redis in production)
# ---------------------------------------------------------------------------

_rate_limit_storage: dict[str, deque] = defaultdict(deque)


# Set TRUST_PROXY_HEADERS=true in env only when running behind a known
# reverse proxy (nginx, Cloudflare, etc.). When false, XFF is ignored
# entirely so clients cannot spoof their IP for rate-limit bypass.
_TRUST_PROXY = os.environ.get('TRUST_PROXY_HEADERS', '').lower() == 'true'


def _get_client_ip():
    if _TRUST_PROXY:
        forwarded = request.environ.get('HTTP_X_FORWARDED_FOR', '')
        if forwarded:
            # Take the leftmost (client) IP; proxies append their own
            first = forwarded.split(',')[0].strip()
            if is_valid_ip(first):
                return first
    remote = request.environ.get('REMOTE_ADDR', '127.0.0.1')
    return remote if is_valid_ip(remote) else '127.0.0.1'


def rate_limit(max_requests=10, window_seconds=60):
    """Decorator: enforce a sliding-window rate limit per client IP."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            client_ip    = _get_client_ip()
            now          = time.time()
            bucket       = _rate_limit_storage[client_ip]

            while bucket and now - bucket[0] > window_seconds:
                bucket.popleft()

            if len(bucket) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

            bucket.append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@main_bp.route('/')
def index():
    lookups_today = 0
    if current_user.is_authenticated:
        today = datetime.now(timezone.utc).date()
        lookups_today = SearchHistory.query.filter(
            SearchHistory.user_id == current_user.id,
            SearchHistory.search_type == 'ip_lookup',
            db.func.date(SearchHistory.timestamp) == today,
        ).count()
    return render_template('index.html', lookups_today=lookups_today)


@main_bp.route('/shortener')
def shortener():
    return render_template('shortener.html')


@main_bp.route('/my-ip', methods=['GET'])
@rate_limit(max_requests=5, window_seconds=60)
def get_my_ip():
    """Return the requester's public IP address."""
    try:
        client_ip = _get_client_ip()

        if client_ip in ('127.0.0.1', 'localhost') or not is_valid_ip(client_ip):
            ip_services = [
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip',
                'https://ipinfo.io/json',
            ]
            headers = {
                'User-Agent': 'Secora-Intelligence-Platform/1.0',
                'Accept':     'application/json',
            }
            for svc in ip_services:
                try:
                    r = requests.get(svc, timeout=5, headers=headers, verify=True)
                    if r.status_code == 200:
                        data     = r.json()
                        user_ip  = sanitize_string(str(data.get('ip') or data.get('origin', '')))
                        if user_ip and is_valid_ip(user_ip):
                            return jsonify({'success': True, 'ip': user_ip,
                                            'service': sanitize_string(svc)})
                except Exception:
                    continue
            return jsonify({'error': 'Could not determine your public IP address'}), 400

        return jsonify({'success': True, 'ip': client_ip})

    except Exception as e:
        current_app.logger.error(f"Error getting client IP: {e}")
        return jsonify({'error': 'Could not determine your IP address'}), 500


@main_bp.route('/lookup', methods=['POST'])
@login_required
@rate_limit(max_requests=20, window_seconds=60)
def lookup():
    """Perform an IP intelligence lookup."""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        ip_address = data.get('ip_address', '')
        if not isinstance(ip_address, str):
            return jsonify({'error': 'IP address must be a string'}), 400

        ip_address = sanitize_string(ip_address.strip())
        if not ip_address:
            return jsonify({'error': 'Please enter an IP address'}), 400
        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Please enter a valid public IP address'}), 400

        result = lookup_ip(ip_address)

        if current_user.is_authenticated:
            try:
                db.session.add(SearchHistory(
                    user_id=current_user.id,
                    ip_address=ip_address,
                    search_type='ip_lookup',
                ))
                db.session.commit()

                today         = datetime.now(timezone.utc).date()
                lookups_today = SearchHistory.query.filter(
                    SearchHistory.user_id == current_user.id,
                    SearchHistory.search_type == 'ip_lookup',
                    db.func.date(SearchHistory.timestamp) == today,
                ).count()

                result['lookups_today'] = lookups_today
                socketio.emit(
                    'lookup_count_update',
                    {'lookups_today': lookups_today},
                    room=f'user_{current_user.id}',
                )
            except Exception as log_err:
                current_app.logger.error(f"Failed to log search: {log_err}")
                db.session.rollback()

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Lookup error: {e}")
        return jsonify({'error': 'An internal error occurred'}), 500


@main_bp.route('/report-ip', methods=['POST'])
@login_required
@rate_limit(max_requests=5, window_seconds=60)
def report_ip():
    """Submit a community report for an IP address."""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        ip_address  = data.get('ip_address', '')
        report_type = data.get('report_type', '')
        comment     = data.get('comment', '')

        if not all(isinstance(v, str) for v in (ip_address, report_type, comment)):
            return jsonify({'error': 'All fields must be strings'}), 400

        ip_address  = sanitize_string(ip_address.strip())
        report_type = sanitize_string(report_type.strip())
        comment     = sanitize_string(comment.strip(), max_length=1000)

        if not ip_address or not is_valid_ip(ip_address):
            return jsonify({'error': 'Please enter a valid public IP address'}), 400
        rt_ok, rt_err = validate_report_type(report_type)
        if not rt_ok:
            return jsonify({'error': rt_err}), 400
        if not comment:
            return jsonify({'error': 'Please provide a comment'}), 400
        if len(comment) > 1000:
            return jsonify({'error': 'Comment must be 1000 characters or fewer'}), 400

        window_start = datetime.now(timezone.utc) - timedelta(hours=24)
        if IPReport.query.filter_by(
            user_id=current_user.id, ip_address=ip_address
        ).filter(IPReport.timestamp > window_start).first():
            return jsonify({'error': 'You have already reported this IP address in the last 24 hours'}), 400

        db.session.add(IPReport(
            user_id=current_user.id,
            ip_address=ip_address,
            report_type=report_type,
            comment=comment,
        ))
        db.session.commit()
        return jsonify({'success': True, 'message': 'IP address reported successfully'})

    except Exception as e:
        current_app.logger.error(f"Report error: {e}")
        db.session.rollback()
        return jsonify({'error': 'An internal error occurred'}), 500


@main_bp.route('/get-ip-reports/<ip_address>', methods=['GET'])
@rate_limit(max_requests=30, window_seconds=60)
def get_ip_reports(ip_address):
    """Return recent community reports for *ip_address*."""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Invalid IP address'}), 400

        reports = (IPReport.query
                   .filter_by(ip_address=ip_address)
                   .order_by(IPReport.timestamp.desc())
                   .limit(10).all())

        return jsonify({
            'success':      True,
            'reports':      [
                {
                    'id':          r.id,
                    'report_type': r.report_type,
                    'comment':     r.comment,
                    'timestamp':   r.timestamp.isoformat(),
                }
                for r in reports
            ],
            'total_reports': len(reports),
        })

    except Exception as e:
        current_app.logger.error(f"Get reports error: {e}")
        return jsonify({'error': 'An internal error occurred'}), 500


@main_bp.route('/shorten', methods=['POST'])
@login_required
@rate_limit(max_requests=10, window_seconds=60)
def shorten_url():
    """Shorten a URL using multiple external services."""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        url = data.get('url', '')
        if not isinstance(url, str):
            return jsonify({'error': 'URL must be a string'}), 400

        url = sanitize_string(url.strip())
        if not url:
            return jsonify({'error': 'Please enter a URL'}), 400
        if not is_valid_url(url):
            return jsonify({'error': 'Please enter a valid URL'}), 400

        result = shorten_with_multiple_services(url)

        if current_user.is_authenticated:
            try:
                db.session.add(SearchHistory(
                    user_id=current_user.id,
                    ip_address=None,
                    search_type='url_shorten',
                    url_shortened=url,
                ))
                db.session.commit()
            except Exception as log_err:
                current_app.logger.error(f"Failed to log URL shortening: {log_err}")
                db.session.rollback()

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Shortening error: {e}")
        return jsonify({'error': 'An internal error occurred'}), 500


@main_bp.route('/lookup-count', methods=['GET'])
@login_required
def lookup_count():
    try:
        today         = datetime.now(timezone.utc).date()
        lookups_today = SearchHistory.query.filter(
            SearchHistory.user_id == current_user.id,
            SearchHistory.search_type == 'ip_lookup',
            db.func.date(SearchHistory.timestamp) == today,
        ).count()
        return jsonify({
            'success':       True,
            'lookups_today': lookups_today,
            'date':          str(today),
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@socketio.on('join')
def on_join(data):
    # Only allow a logged-in user to join their own room.
    # Ignore any client-supplied user_id — use the session identity.
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
