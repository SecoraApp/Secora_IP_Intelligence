import time
from collections import defaultdict, deque
from functools import wraps
from flask import request, jsonify
from utils import is_valid_ip

# Rate limiting storage (in production, use Redis or database)
rate_limit_storage = defaultdict(lambda: deque())

def get_client_ip():
    """Safely get client IP address"""
    # Check for forwarded headers (but validate them)
    forwarded_ips = request.environ.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded_ips:
        # Take the first IP, but validate it
        first_ip = forwarded_ips.split(',')[0].strip()
        if is_valid_ip(first_ip):
            return first_ip

    # Fallback to remote addr
    remote_addr = request.environ.get('REMOTE_ADDR', '127.0.0.1')
    return remote_addr if is_valid_ip(remote_addr) else '127.0.0.1'

def rate_limit(max_requests=10, window_seconds=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = get_client_ip()
            current_time = time.time()

            # Clean old requests
            requests_for_ip = rate_limit_storage[client_ip]
            while requests_for_ip and current_time - requests_for_ip[0] > window_seconds:
                requests_for_ip.popleft()

            # Check rate limit
            if len(requests_for_ip) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

            # Add current request
            requests_for_ip.append(current_time)

            return f(*args, **kwargs)
        return decorated_function
    return decorator

