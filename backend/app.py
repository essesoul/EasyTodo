import os
import re
import smtplib
import ssl
import secrets
import json
import hmac
import hashlib
import base64
import urllib.parse
import urllib.request
from datetime import timedelta, datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, session, render_template, redirect, url_for, send_from_directory, make_response
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_conn, init_db


def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    # Persist a dev secret key so local sessions survive restarts.
    # If production sets SECRET_KEY, we use it and never touch the dev key file.
    secret_from_env = os.environ.get('SECRET_KEY')
    if secret_from_env:
        app.config['SECRET_KEY'] = secret_from_env
    else:
        dev_key_path = os.path.join(os.path.dirname(__file__), '.dev-secret-key')
        try:
            if os.path.exists(dev_key_path):
                with open(dev_key_path, 'r', encoding='utf-8') as f:
                    app.config['SECRET_KEY'] = f.read().strip()
            else:
                # Allow disabling file creation explicitly if someone really runs without env on prod
                if os.environ.get('EASYTODO_DISABLE_DEV_KEY') == '1':
                    app.config['SECRET_KEY'] = secrets.token_hex(32)
                else:
                    key = secrets.token_hex(32)
                    with open(dev_key_path, 'w', encoding='utf-8') as f:
                        f.write(key)
                    app.config['SECRET_KEY'] = key
        except Exception:
            # Fallback if file not writable for any reason
            app.config['SECRET_KEY'] = secrets.token_hex(32)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # Set in deployment behind HTTPS
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    # JWT settings
    app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET') or app.config['SECRET_KEY']
    # TTL in seconds; default 7 days
    try:
        app.config['JWT_TTL_SECONDS'] = int(os.environ.get('JWT_TTL_SECONDS', str(7*24*60*60)))
    except Exception:
        app.config['JWT_TTL_SECONDS'] = 7*24*60*60
    # Auth cookie flags
    app.config['AUTH_COOKIE_NAME'] = os.environ.get('AUTH_COOKIE_NAME', 'access_token')
    app.config['AUTH_COOKIE_SECURE'] = os.environ.get('AUTH_COOKIE_SECURE', 'false').lower() == 'true' or app.config['SESSION_COOKIE_SECURE']
    app.config['AUTH_COOKIE_SAMESITE'] = os.environ.get('AUTH_COOKIE_SAMESITE', 'Strict')
    app.config['AUTH_COOKIE_DOMAIN'] = os.environ.get('AUTH_COOKIE_DOMAIN')  # optional

    init_db()

    # Same-origin app, no CORS needed

    @app.after_request
    def set_security_headers(resp):
        # Basic hardening; allow required third-party origins used in app
        csp_parts = [
            "default-src 'self'",
            "img-src 'self' data:",
            "font-src 'self' https://cdnjs.cloudflare.com data:",
            "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'",
            "script-src 'self' https://cdnjs.cloudflare.com https://challenges.cloudflare.com 'unsafe-inline'",
            "connect-src 'self'",
            "frame-src 'self' https://challenges.cloudflare.com",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
        ]
        resp.headers.setdefault('Content-Security-Policy', '; '.join(csp_parts))
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('X-Frame-Options', 'DENY')
        resp.headers.setdefault('Referrer-Policy', 'no-referrer')
        # Cache policy: avoid caching dynamic pages and all API responses
        try:
            is_api = request.path.startswith('/api/')
        except Exception:
            is_api = False
        # Treat HTML pages as dynamic; allow static assets to be cached by SW/edge
        is_html = (resp.mimetype or '').startswith('text/html')
        is_static = request.path.startswith('/static/') if hasattr(request, 'path') else False
        if is_api or (is_html and not is_static):
            resp.headers['Cache-Control'] = 'no-store'
            resp.headers['Pragma'] = 'no-cache'
        return resp
        return resp

    @app.route('/api/health')
    def health():
        return jsonify(ok=True)

    def ensure_csrf_token():
        token = session.get('csrf_token')
        if not token:
            token = secrets.token_hex(16)
            session['csrf_token'] = token
            session.permanent = True
        return token

    @app.route('/api/csrf', methods=['GET'])
    def csrf():
        token = ensure_csrf_token()
        return jsonify(token=token)

    # --- Helpers ---
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

    def _b64url_decode(data: str) -> bytes:
        pad = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode((data + pad).encode('ascii'))

    def _jwt_sign(payload: dict) -> str:
        header = {'alg': 'HS256', 'typ': 'JWT'}
        header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
        signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
        secret = app.config['JWT_SECRET'].encode('utf-8')
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        sig_b64 = _b64url_encode(sig)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _jwt_verify(token: str):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header_b64, payload_b64, sig_b64 = parts
            signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
            secret = app.config['JWT_SECRET'].encode('utf-8')
            expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
            given = _b64url_decode(sig_b64)
            if not hmac.compare_digest(expected, given):
                return None
            payload = json.loads(_b64url_decode(payload_b64).decode('utf-8'))
            # exp check (unix seconds)
            exp = int(payload.get('exp') or 0)
            now = int(datetime.now(timezone.utc).timestamp())
            if exp and now > exp:
                return None
            return payload
        except Exception:
            return None

    def _make_access_token(user_id: int) -> str:
        now = int(datetime.now(timezone.utc).timestamp())
        payload = {
            'sub': int(user_id),
            'iat': now,
            'exp': now + int(app.config['JWT_TTL_SECONDS']),
        }
        return _jwt_sign(payload)

    def _set_auth_cookie(resp, token: str):
        resp.set_cookie(
            app.config['AUTH_COOKIE_NAME'],
            token,
            httponly=True,
            secure=bool(app.config['AUTH_COOKIE_SECURE']),
            samesite=app.config['AUTH_COOKIE_SAMESITE'],
            max_age=int(app.config['JWT_TTL_SECONDS']),
            path='/',
            domain=app.config['AUTH_COOKIE_DOMAIN'] or None,
        )

    def _clear_auth_cookie(resp):
        resp.delete_cookie(
            app.config['AUTH_COOKIE_NAME'],
            path='/',
            domain=app.config['AUTH_COOKIE_DOMAIN'] or None,
        )

    def current_user_id():
        # 1) Authorization: Bearer (optional), 2) Cookie
        auth = request.headers.get('Authorization') or ''
        if auth.startswith('Bearer '):
            payload = _jwt_verify(auth[7:].strip())
            if payload and 'sub' in payload:
                return int(payload['sub'])
        tok = request.cookies.get(app.config['AUTH_COOKIE_NAME'])
        if not tok:
            return None
        payload = _jwt_verify(tok)
        if not payload or 'sub' not in payload:
            return None
        return int(payload['sub'])

    def is_admin_user(user_id=None) -> bool:
        uid = user_id if user_id is not None else current_user_id()
        if not uid:
            return False
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT MIN(id) AS min_id FROM users")
        row = cur.fetchone()
        conn.close()
        return bool(row and row['min_id'] and int(row['min_id']) == int(uid))

    def login_required(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user_id():
                # For API endpoints: JSON 401; for pages: redirect to /login
                if request.path.startswith('/api/'):
                    return jsonify(error='unauthorized'), 401
                return redirect(url_for('login_page'))
            return f(*args, **kwargs)
        return wrapped

    def require_csrf():
        token = request.headers.get('X-CSRF-Token')
        # We continue using server-signed Flask session to hold CSRF token
        if not token or token != session.get('csrf_token'):
            return False
        return True

    def ensure_positions_sequential(conn, user_id):
        cur = conn.cursor()
        cur.execute("SELECT id FROM todos WHERE user_id=? ORDER BY position ASC, id ASC", (user_id,))
        ids = [row['id'] for row in cur.fetchall()]
        for idx, tid in enumerate(ids):
            cur.execute("UPDATE todos SET position=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (idx, tid))

    # Settings helpers
    def get_setting(key, default=None):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        conn.close()
        return row['value'] if row and row['value'] is not None else default

    def set_settings(pairs):
        if not pairs:
            return
        conn = get_conn()
        cur = conn.cursor()
        for k, v in pairs.items():
            cur.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v) if v is not None else ''))
        conn.commit()
        conn.close()

    # --- Page routes (Jinja2) ---
    @app.get('/login')
    def login_page():
        if current_user_id():
            return redirect(url_for('home'))
        # read toggles
        registration_open = (get_setting('registration_open', '1') or '1') == '1'
        smtp_enabled = (get_setting('smtp_enabled', '0') or '0') == '1'
        turnstile_enabled = (get_setting('turnstile_enabled', '0') or '0') == '1'
        turnstile_site_key = get_setting('turnstile_site_key', '') or ''
        return render_template(
            'login.html',
            title='登录 / 注册 - EasyTodo',
            registration_open=registration_open,
            smtp_enabled=smtp_enabled,
            turnstile_enabled=turnstile_enabled,
            turnstile_site_key=turnstile_site_key,
        )

    @app.get('/')
    @login_required
    def home():
        token = ensure_csrf_token()
        return render_template('index.html', title='EasyTodo 待办', csrf_token=token)

    @app.get('/settings')
    @login_required
    def settings_page():
        token = ensure_csrf_token()
        uid = current_user_id()
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT email FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
        conn.close()
        email = row['email'] if row else ''
        return render_template('settings.html', title='设置 - EasyTodo', csrf_token=token, email=email, is_admin=is_admin_user(uid))

    # --- PWA assets ---
    # Serve service worker at root scope so it can control all pages
    @app.get('/sw.js')
    def service_worker():
        resp = make_response(send_from_directory(app.static_folder, 'sw.js', mimetype='application/javascript'))
        # Allow the SW to control root scope
        resp.headers['Service-Worker-Allowed'] = '/'
        return resp

    # --- Auth ---
    @app.post('/api/auth/register')
    def register():
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        # Basic validations with specific errors
        if not email:
            return jsonify(error='invalid_email'), 400
        if '@' not in email or '.' not in email.split('@')[-1]:
            return jsonify(error='invalid_email'), 400
        if not password:
            return jsonify(error='weak_password'), 400
        if len(password) < 8:
            return jsonify(error='weak_password'), 400
        # Registration toggle: allow if open OR there are no users yet
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM users")
        cnt = int(cur.fetchone()['c'])
        registration_open = (get_setting('registration_open', '1') or '1') == '1'
        if not registration_open and cnt > 0:
            conn.close()
            return jsonify(error='registration_closed'), 403
        try:
            cur.execute("INSERT INTO users(email, password_hash) VALUES(?, ?)", (email, generate_password_hash(password)))
            conn.commit()
        except Exception:
            conn.rollback()
            conn.close()
            return jsonify(error='email_taken'), 409
        # auto-login via JWT
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        user_id = cur.fetchone()['id']
        if not session.get('csrf_token'):
            session['csrf_token'] = secrets.token_hex(16)
        session.permanent = True
        conn.close()
        token = _make_access_token(int(user_id))
        resp = jsonify(ok=True)
        _set_auth_cookie(resp, token)
        return resp

    @app.post('/api/auth/login')
    def login():
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash, temp_password_hash, temp_password_expires FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify(error='invalid_credentials'), 401

        uid = row['id']
        pw_hash = row['password_hash']
        tmp_hash = row['temp_password_hash']
        tmp_exp = row['temp_password_expires']

        authed_with_temp = False
        # First try permanent password
        if not check_password_hash(pw_hash, password):
            # Then try temp password if present and not expired
            if tmp_hash and tmp_exp:
                try:
                    exp_dt = datetime.strptime(tmp_exp, '%Y-%m-%dT%H:%M:%fZ')
                except Exception:
                    exp_dt = None
                now = datetime.utcnow()
                valid = bool(exp_dt and exp_dt >= now)
                if valid and check_password_hash(tmp_hash, password):
                    authed_with_temp = True
                else:
                    # If expired, clear temp creds for hygiene
                    if exp_dt and exp_dt < now:
                        try:
                            cur.execute("UPDATE users SET temp_password_hash=NULL, temp_password_expires=NULL WHERE id=?", (uid,))
                            conn.commit()
                        except Exception:
                            pass
                    conn.close()
                    return jsonify(error='invalid_credentials'), 401
            else:
                conn.close()
                return jsonify(error='invalid_credentials'), 401

        # If logged in using temp password, promote it to permanent now
        if authed_with_temp:
            try:
                cur.execute(
                    "UPDATE users SET password_hash=temp_password_hash, temp_password_hash=NULL, temp_password_expires=NULL WHERE id=?",
                    (uid,),
                )
                conn.commit()
            except Exception:
                # If promotion fails, still avoid logging in with invalid state
                conn.close()
                return jsonify(error='server_error'), 500

        conn.close()
        if not session.get('csrf_token'):
            session['csrf_token'] = secrets.token_hex(16)
        session.permanent = True
        token = _make_access_token(int(uid))
        resp = jsonify(ok=True)
        _set_auth_cookie(resp, token)
        return resp

    @app.post('/api/auth/logout')
    def logout():
        session.clear()
        resp = jsonify(ok=True)
        _clear_auth_cookie(resp)
        return resp

    @app.post('/api/auth/change_password')
    @login_required
    def change_password():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        data = request.get_json(silent=True) or {}
        current = data.get('current') or ''
        new = data.get('new') or ''
        if len(new) < 8:
            return jsonify(error='weak_password'), 400
        uid = current_user_id()
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
        if not row or not check_password_hash(row['password_hash'], current):
            conn.close()
            return jsonify(error='invalid_current'), 400
        cur.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), uid))
        conn.commit()
        conn.close()
        return jsonify(ok=True)

    @app.delete('/api/auth/delete_account')
    @login_required
    def delete_account():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        uid = current_user_id()
        # Protect admin account from deletion via API
        if is_admin_user(uid):
            return jsonify(error='admin_protected'), 403
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM todos WHERE user_id=?", (uid,))
            cur.execute("DELETE FROM users WHERE id=?", (uid,))
            conn.commit()
        finally:
            conn.close()
        session.clear()
        return jsonify(ok=True)

    # --- Admin-only APIs ---
    def admin_required(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user_id():
                return jsonify(error='unauthorized'), 401
            if not is_admin_user():
                return jsonify(error='forbidden'), 403
            return f(*args, **kwargs)
        return wrapped

    @app.get('/api/admin/config')
    @login_required
    @admin_required
    def admin_get_config():
        cfg = {
            'registration_open': (get_setting('registration_open', '1') or '1') == '1',
            'smtp_enabled': (get_setting('smtp_enabled', '0') or '0') == '1',
            'smtp_host': get_setting('smtp_host', '') or '',
            'smtp_port': get_setting('smtp_port', '') or '',
            'smtp_username': get_setting('smtp_username', '') or '',
            # Do not return password content; indicate if set
            'smtp_password_set': bool(get_setting('smtp_password', '') or ''),
            'smtp_use_tls': (get_setting('smtp_use_tls', '1') or '1') == '1',
            'smtp_sender': get_setting('smtp_sender', '') or '',
            'smtp_tls_skip_verify': (get_setting('smtp_tls_skip_verify', '0') or '0') == '1',
            # Turnstile
            'turnstile_enabled': (get_setting('turnstile_enabled', '0') or '0') == '1',
            'turnstile_site_key': get_setting('turnstile_site_key', '') or '',
            'turnstile_secret_set': bool(get_setting('turnstile_secret_key', '') or ''),
            'turnstile_tls_skip_verify': (get_setting('turnstile_tls_skip_verify', '0') or '0') == '1',
        }
        return jsonify(config=cfg)

    @app.post('/api/admin/config')
    @login_required
    @admin_required
    def admin_set_config():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        data = request.get_json(silent=True) or {}
        updates = {}
        # Read current settings to validate effective values when enabling SMTP/Turnstile
        current_cfg = {
            'smtp_enabled': (get_setting('smtp_enabled', '0') or '0') == '1',
            'smtp_host': get_setting('smtp_host', '') or '',
            'smtp_port': get_setting('smtp_port', '') or '',
            'smtp_username': get_setting('smtp_username', '') or '',
            'smtp_password': get_setting('smtp_password', '') or '',
            'smtp_sender': get_setting('smtp_sender', '') or '',
            'smtp_tls_skip_verify': (get_setting('smtp_tls_skip_verify', '0') or '0') == '1',
            'turnstile_enabled': (get_setting('turnstile_enabled', '0') or '0') == '1',
            'turnstile_site_key': get_setting('turnstile_site_key', '') or '',
            'turnstile_secret_key': get_setting('turnstile_secret_key', '') or '',
            'turnstile_tls_skip_verify': (get_setting('turnstile_tls_skip_verify', '0') or '0') == '1',
        }
        if 'registration_open' in data:
            updates['registration_open'] = '1' if bool(data.get('registration_open')) else '0'
        if 'smtp_enabled' in data:
            updates['smtp_enabled'] = '1' if bool(data.get('smtp_enabled')) else '0'
        if 'smtp_host' in data:
            updates['smtp_host'] = (data.get('smtp_host') or '').strip()
        if 'smtp_port' in data:
            updates['smtp_port'] = str(data.get('smtp_port') or '').strip()
        if 'smtp_username' in data:
            updates['smtp_username'] = (data.get('smtp_username') or '').strip()
        if 'smtp_use_tls' in data:
            updates['smtp_use_tls'] = '1' if bool(data.get('smtp_use_tls')) else '0'
        if 'smtp_sender' in data:
            updates['smtp_sender'] = (data.get('smtp_sender') or '').strip()
        if 'smtp_tls_skip_verify' in data:
            updates['smtp_tls_skip_verify'] = '1' if bool(data.get('smtp_tls_skip_verify')) else '0'
        # Track if a new password is explicitly provided (even empty to clear)
        new_password = None
        if data.get('smtp_password') is not None:
            # Only update if explicitly provided
            new_password = str(data.get('smtp_password') or '')
            updates['smtp_password'] = new_password

        # Turnstile updates
        if 'turnstile_enabled' in data:
            updates['turnstile_enabled'] = '1' if bool(data.get('turnstile_enabled')) else '0'
        if 'turnstile_site_key' in data:
            updates['turnstile_site_key'] = (data.get('turnstile_site_key') or '').strip()
        # For secret, only update when explicitly present; allow empty to clear
        if data.get('turnstile_secret_key') is not None:
            updates['turnstile_secret_key'] = str(data.get('turnstile_secret_key') or '')
        if 'turnstile_tls_skip_verify' in data:
            updates['turnstile_tls_skip_verify'] = '1' if bool(data.get('turnstile_tls_skip_verify')) else '0'

        # Validate when attempting to enable SMTP
        # Compute the effective final values (incoming value if provided, else current)
        incoming_enabled = data.get('smtp_enabled')
        effective_enabled = bool(incoming_enabled) if incoming_enabled is not None else bool(current_cfg['smtp_enabled'])
        if effective_enabled:
            effective_host = (data.get('smtp_host') if 'smtp_host' in data else current_cfg['smtp_host']).strip()
            effective_port = str(data.get('smtp_port') if 'smtp_port' in data else current_cfg['smtp_port']).strip()
            effective_username = (data.get('smtp_username') if 'smtp_username' in data else current_cfg['smtp_username']).strip()
            effective_sender = (data.get('smtp_sender') if 'smtp_sender' in data else current_cfg['smtp_sender']).strip()
            effective_skip_verify = bool(data.get('smtp_tls_skip_verify')) if 'smtp_tls_skip_verify' in data else bool(current_cfg['smtp_tls_skip_verify'])
            # Password considered set if new non-empty provided, else existing non-empty remains
            if new_password is not None:
                effective_password_set = new_password.strip() != ''
            else:
                effective_password_set = (current_cfg['smtp_password'] or '').strip() != ''

            # Basic validations: non-empty host/username/sender, numeric port > 0, password set
            try:
                port_int = int(effective_port)
            except Exception:
                port_int = -1
            if not effective_host or not effective_username or not effective_sender or port_int <= 0 or not effective_password_set:
                return jsonify(error='smtp_invalid'), 400

        # Validate when attempting to enable Turnstile
        incoming_ts_enabled = data.get('turnstile_enabled')
        effective_ts_enabled = bool(incoming_ts_enabled) if incoming_ts_enabled is not None else bool(current_cfg['turnstile_enabled'])
        if effective_ts_enabled:
            effective_site = (data.get('turnstile_site_key') if 'turnstile_site_key' in data else current_cfg['turnstile_site_key']).strip()
            # Secret is considered set if explicit non-empty provided or already present
            if data.get('turnstile_secret_key') is not None:
                secret_set = str(data.get('turnstile_secret_key') or '').strip() != ''
            else:
                secret_set = (current_cfg['turnstile_secret_key'] or '').strip() != ''
            if not effective_site or not secret_set:
                return jsonify(error='turnstile_invalid'), 400

        set_settings(updates)
        return jsonify(ok=True)

    # ---- Forgot Password (with optional Turnstile + arithmetic challenge) ----
    @app.post('/api/auth/forgot/start')
    def forgot_start():
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        if not email or '@' not in email:
            return jsonify(error='invalid_email'), 400
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return jsonify(error='not_found'), 404
        # Generate simple arithmetic challenge and store in session
        a = secrets.randbelow(10) + 1
        b = secrets.randbelow(10) + 1
        op = '+' if secrets.randbelow(2) == 0 else '-'
        ans = a + b if op == '+' else a - b
        # keep email bound to challenge
        session['fp'] = {
            'email': email,
            'ans': str(ans),
        }
        session.permanent = True
        return jsonify(ok=True, challenge=f"{a} {op} {b} = ?")

    def _client_ip_from_headers() -> str:
        # Prefer Cloudflare/Proxy forwarded IPs when present
        cf_ip = request.headers.get('CF-Connecting-IP')
        if cf_ip:
            return cf_ip.strip()
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            # Use left-most IP
            return xff.split(',')[0].strip()
        return ''

    def verify_turnstile(token: str):
        enabled = (get_setting('turnstile_enabled', '0') or '0') == '1'
        if not enabled:
            return True, None
        secret = get_setting('turnstile_secret_key', '') or ''
        if not secret:
            return False, ['invalid-input-secret']
        try:
            # Only send required fields; omit remote IP to avoid proxy/IP mismatches
            payload_dict = {
                'secret': secret,
                'response': token or '',
            }
            # Include real client IP when reliably available (CF/XFF)
            cip = _client_ip_from_headers()
            if cip:
                payload_dict['remoteip'] = cip
            data = urllib.parse.urlencode(payload_dict).encode('utf-8')
            # SSL context: try certifi CA; allow admin to skip verify if needed
            skip_verify = (get_setting('turnstile_tls_skip_verify', '0') or '0') == '1'
            try:
                import ssl as _ssl
                context = _ssl.create_default_context()
                if not skip_verify:
                    try:
                        import certifi
                        context.load_verify_locations(cafile=certifi.where())
                    except Exception:
                        pass
                else:
                    context.check_hostname = False
                    context.verify_mode = _ssl.CERT_NONE
            except Exception:
                context = None
            req = urllib.request.Request(
                'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            # Pass context when available (HTTPS only)
            if context is not None:
                resp_ctx = urllib.request.urlopen(req, timeout=10, context=context)
            else:
                resp_ctx = urllib.request.urlopen(req, timeout=10)
            with resp_ctx as resp:
                payload = resp.read()
                try:
                    j = json.loads(payload.decode('utf-8'))
                except Exception:
                    return False, ['bad-json']
                ok = bool(j.get('success'))
                errs = j.get('error-codes') or []
                if not ok:
                    # Best-effort log for diagnostics
                    try:
                        app.logger.info('Turnstile verify failed: %s ip=%s', errs, cip)
                    except Exception:
                        pass
                return ok, errs
        except Exception as e:
            try:
                app.logger.warning('Turnstile verify exception: %s', e)
            except Exception:
                pass
            return False, ['network-error']

    def _send_email_with_settings(to_addr: str, subject: str, content: str):
        # Load saved SMTP
        host = (get_setting('smtp_host', '') or '').strip()
        port_s = (get_setting('smtp_port', '') or '').strip()
        username = (get_setting('smtp_username', '') or '').strip()
        password = get_setting('smtp_password', '') or ''
        use_tls = (get_setting('smtp_use_tls', '1') or '1') == '1'
        sender = (get_setting('smtp_sender', '') or '').strip()
        skip_verify = (get_setting('smtp_tls_skip_verify', '0') or '0') == '1'
        try:
            port = int(port_s)
        except Exception:
            port = -1
        if not host or port <= 0 or not username or not password or not sender:
            return False, 'smtp_invalid'
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = to_addr
            msg.set_content(content)
            if use_tls and port == 465:
                context = ssl.create_default_context()
                if skip_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
                    server.login(username, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=15) as server:
                    server.ehlo()
                    if use_tls:
                        context = ssl.create_default_context()
                        if skip_verify:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                        server.starttls(context=context)
                        server.ehlo()
                    server.login(username, password)
                    server.send_message(msg)
        except smtplib.SMTPAuthenticationError:
            return False, 'smtp_auth_failed'
        except Exception:
            return False, 'smtp_send_failed'
        return True, None

    @app.post('/api/auth/forgot/confirm')
    def forgot_confirm():
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        answer = str(data.get('answer') or '').strip()
        token = data.get('turnstile_token')
        if not email or '@' not in email:
            return jsonify(error='invalid_email'), 400
        # Validate session challenge
        fp = session.get('fp') or {}
        if not fp or fp.get('email') != email or str(fp.get('ans')) != answer:
            return jsonify(error='bad_challenge'), 400
        # Verify Turnstile if enabled
        ok_ts, errs = verify_turnstile(token or '')
        if not ok_ts:
            return jsonify(error='turnstile_failed', detail=(','.join(errs) if errs else '')), 400
        # Ensure user exists
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify(error='not_found'), 404
        user_id = row['id']
        # Generate temporary password
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%_'
        new_pw = ''.join(alphabet[secrets.randbelow(len(alphabet))] for _ in range(12))
        # Send email first (mention 1-day validity)
        ok, err = _send_email_with_settings(
            to_addr=email,
            subject='EasyTodo 密码重置',
            content=(
                f'你的临时密码为：{new_pw}\n\n'
                f'有效期：1 天（自本邮件发送时起计算）。\n'
                f'提示：原密码仍然可用，不会影响当前登录状态。只有当你使用临时密码成功登录后，系统才会用该临时密码覆盖原密码。\n\n'
                f'建议你登录后尽快在“设置”页修改为自己的新密码。'
            ),
        )
        if not ok:
            return jsonify(error=err or 'smtp_send_failed'), 500
        # Store temp password hash and expiry (1 day)
        try:
            expires = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%fZ')
            cur.execute(
                "UPDATE users SET temp_password_hash=?, temp_password_expires=? WHERE id=?",
                (generate_password_hash(new_pw), expires, user_id),
            )
            conn.commit()
        finally:
            conn.close()
        # Clear challenge
        try:
            session.pop('fp', None)
        except Exception:
            pass
        return jsonify(ok=True)

    @app.post('/api/admin/smtp_test')
    @login_required
    @admin_required
    def admin_smtp_test():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        data = request.get_json(silent=True) or {}
        to_addr = (data.get('to') or '').strip()
        if not to_addr or '@' not in to_addr:
            return jsonify(error='invalid_to'), 400
        # Load saved config
        saved = {
            'host': get_setting('smtp_host', '') or '',
            'port': get_setting('smtp_port', '') or '',
            'username': get_setting('smtp_username', '') or '',
            'password': get_setting('smtp_password', '') or '',
            'use_tls': (get_setting('smtp_use_tls', '1') or '1') == '1',
            'sender': get_setting('smtp_sender', '') or '',
            'skip_verify': (get_setting('smtp_tls_skip_verify', '0') or '0') == '1',
        }
        # Apply overrides from request (do not persist)
        host = (data.get('smtp_host') if 'smtp_host' in data else saved['host']).strip()
        port_s = str(data.get('smtp_port') if 'smtp_port' in data else saved['port']).strip()
        username = (data.get('smtp_username') if 'smtp_username' in data else saved['username']).strip()
        sender = (data.get('smtp_sender') if 'smtp_sender' in data else saved['sender']).strip()
        use_tls = bool(data.get('smtp_use_tls')) if 'smtp_use_tls' in data else bool(saved['use_tls'])
        skip_verify = bool(data.get('smtp_tls_skip_verify')) if 'smtp_tls_skip_verify' in data else bool(saved['skip_verify'])
        if data.get('smtp_password') is not None:
            password = str(data.get('smtp_password') or '')
        else:
            password = saved['password']
        try:
            port = int(port_s)
        except Exception:
            port = -1
        # Validate effective config with specific hints
        invalid_reasons = []
        if not host:
            invalid_reasons.append('主机未设置')
        if port <= 0:
            invalid_reasons.append('端口无效')
        if not username:
            invalid_reasons.append('用户名未设置')
        if not password:
            invalid_reasons.append('密码未设置')
        if not sender:
            invalid_reasons.append('发件人未设置')
        if invalid_reasons:
            return jsonify(error='smtp_invalid', detail='；'.join(invalid_reasons)), 400

        # Send test email
        try:
            msg = EmailMessage()
            msg['Subject'] = 'EasyTodo 邮件测试'
            msg['From'] = sender
            msg['To'] = to_addr
            msg.set_content('这是一封来自 EasyTodo 的测试邮件。若你收到此邮件，说明 SMTP 配置可用。')

            if use_tls and port == 465:
                context = ssl.create_default_context()
                if skip_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
                    server.login(username, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=15) as server:
                    server.ehlo()
                    if use_tls:
                        context = ssl.create_default_context()
                        if skip_verify:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                        server.starttls(context=context)
                        server.ehlo()
                    server.login(username, password)
                    server.send_message(msg)
        except smtplib.SMTPAuthenticationError as e:
            # Authentication problems: surface concise reason to the admin
            try:
                detail = str(e)
            except Exception:
                detail = 'authentication failed'
            app.logger.warning('SMTP auth failed: %s', detail)
            return jsonify(error='smtp_auth_failed', detail=detail), 400
        except smtplib.SMTPResponseException as e:
            # Server returned an SMTP error code and message
            code = getattr(e, 'smtp_code', None)
            err = getattr(e, 'smtp_error', b'')
            try:
                err_str = err.decode('utf-8', errors='ignore') if isinstance(err, (bytes, bytearray)) else str(err)
            except Exception:
                err_str = str(err)
            detail = f"{code} {err_str}" if code else err_str
            app.logger.warning('SMTP response error: %s', detail)
            return jsonify(error='smtp_send_failed', detail=detail), 500
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, smtplib.SMTPHeloError, smtplib.SMTPDataError,
                smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused, ssl.SSLError, TimeoutError) as e:
            # Connection/handshake/data issues: return detail for admin to diagnose
            detail = str(e)
            app.logger.warning('SMTP send failed: %s', detail)
            return jsonify(error='smtp_send_failed', detail=detail), 500
        except Exception as e:
            # Unexpected error; include class name for context while avoiding secrets
            detail = f"{e.__class__.__name__}: {e}"
            app.logger.exception('SMTP test unexpected failure')
            return jsonify(error='smtp_send_failed', detail=detail), 500

        return jsonify(ok=True)

    @app.get('/api/admin/users')
    @login_required
    @admin_required
    def admin_list_users():
        # query params
        try:
            page = max(1, int(request.args.get('page', '1')))
        except Exception:
            page = 1
        page_size = 10
        q = (request.args.get('q') or '').strip().lower()
        sort_by = request.args.get('sort', 'id')
        order = request.args.get('order', 'asc')
        allowed_sort = {'id': 'u.id', 'email': 'u.email', 'created_at': 'u.created_at', 'todo_count': 'todo_count'}
        sort_sql = allowed_sort.get(sort_by, 'u.id')
        order_sql = 'DESC' if order.lower() == 'desc' else 'ASC'
        offset = (page - 1) * page_size

        conn = get_conn()
        cur = conn.cursor()
        where = ''
        args = []
        if q:
            where = 'WHERE LOWER(u.email) LIKE ?'
            args.append(f'%{q}%')
        # total count
        cur.execute(f"SELECT COUNT(*) AS c FROM users u {where}", tuple(args))
        total = int(cur.fetchone()['c'])
        # page rows with todo count
        cur.execute(
            f"""
            SELECT u.id, u.email, u.created_at, COALESCE(COUNT(t.id),0) AS todo_count
            FROM users u
            LEFT JOIN todos t ON t.user_id = u.id
            {where}
            GROUP BY u.id
            ORDER BY {sort_sql} {order_sql}
            LIMIT ? OFFSET ?
            """,
            tuple(args + [page_size, offset])
        )
        rows = [dict(id=r['id'], email=r['email'], created_at=r['created_at'], todo_count=r['todo_count']) for r in cur.fetchall()]
        conn.close()
        return jsonify(users=rows, total=total, page=page, page_size=page_size)

    @app.post('/api/admin/users/<int:uid_target>/password')
    @login_required
    @admin_required
    def admin_change_user_password(uid_target: int):
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        data = request.get_json(silent=True) or {}
        new = data.get('new') or ''
        if len(new) < 8:
            return jsonify(error='weak_password'), 400
        # Protect admin account: 禁止通过管理端接口修改管理员（自身）密码
        if current_user_id() == uid_target:
            return jsonify(error='admin_protected'), 403
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), uid_target))
        conn.commit()
        conn.close()
        return jsonify(ok=True)

    @app.delete('/api/admin/users/<int:uid_target>')
    @login_required
    @admin_required
    def admin_delete_user(uid_target: int):
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        # Protect admin account: 禁止管理员删除自己
        if current_user_id() == uid_target:
            return jsonify(error='admin_protected'), 403
        # Prevent deletion of the primary admin
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT MIN(id) AS min_id FROM users")
        minrow = cur.fetchone()
        min_id = int(minrow['min_id']) if minrow and minrow['min_id'] is not None else None
        if min_id is not None and uid_target == min_id:
            conn.close()
            return jsonify(error='admin_protected'), 403
        cur.execute("DELETE FROM todos WHERE user_id=?", (uid_target,))
        cur.execute("DELETE FROM users WHERE id=?", (uid_target,))
        conn.commit()
        conn.close()
        return jsonify(ok=True)

    # --- Todos ---
    @app.get('/api/todos')
    @login_required
    def list_todos():
        uid = current_user_id()
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, text, completed, position, updated_at FROM todos WHERE user_id=? ORDER BY position ASC", (uid,))
        todos = [dict(id=row['id'], text=row['text'], completed=bool(row['completed']), position=row['position'], updated_at=row['updated_at']) for row in cur.fetchall()]
        conn.close()
        return jsonify(todos=todos)

    @app.post('/api/todos')
    @login_required
    def create_todo():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        uid = current_user_id()
        data = request.get_json(silent=True) or {}
        text = (data.get('text') or '').strip()
        if not text:
            return jsonify(error='empty_text'), 400
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COALESCE(MAX(position), -1) AS maxp FROM todos WHERE user_id=?", (uid,))
        maxp = cur.fetchone()['maxp']
        pos = maxp + 1
        cur.execute(
            "INSERT INTO todos(user_id, text, completed, position) VALUES(?, ?, 0, ?)",
            (uid, text, pos)
        )
        conn.commit()
        tid = cur.lastrowid
        cur.execute("SELECT id, text, completed, position, updated_at FROM todos WHERE id=?", (tid,))
        row = cur.fetchone()
        conn.close()
        return jsonify(todo=dict(id=row['id'], text=row['text'], completed=bool(row['completed']), position=row['position'], updated_at=row['updated_at']))

    @app.put('/api/todos/<int:todo_id>')
    @login_required
    def update_todo(todo_id: int):
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        uid = current_user_id()
        data = request.get_json(silent=True) or {}
        text = data.get('text')
        completed = data.get('completed')
        position = data.get('position')
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM todos WHERE id=? AND user_id=?", (todo_id, uid))
        if not cur.fetchone():
            conn.close()
            return jsonify(error='not_found'), 404
        sets = []
        args = []
        if isinstance(text, str):
            sets.append('text=?')
            args.append(text.strip())
        if completed is not None:
            sets.append('completed=?')
            args.append(1 if bool(completed) else 0)
        if isinstance(position, int):
            sets.append('position=?')
            args.append(position)
        if not sets:
            conn.close()
            return jsonify(ok=True)
        sets.append("updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')")
        args.extend([todo_id, uid])
        cur.execute(f"UPDATE todos SET {', '.join(sets)} WHERE id=? AND user_id=?", tuple(args))
        if isinstance(position, int):
            ensure_positions_sequential(conn, uid)
        conn.commit()
        conn.close()
        return jsonify(ok=True)

    @app.post('/api/todos/reorder')
    @login_required
    def reorder():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        uid = current_user_id()
        data = request.get_json(silent=True) or {}
        order = data.get('order') or []
        if not isinstance(order, list):
            return jsonify(error='invalid_order'), 400
        conn = get_conn()
        cur = conn.cursor()
        for idx, tid in enumerate(order):
            try:
                tid_int = int(tid)
            except Exception:
                continue
            cur.execute(
                "UPDATE todos SET position=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND user_id=?",
                (idx, tid_int, uid),
            )
        conn.commit()
        conn.close()
        return jsonify(ok=True)

    @app.delete('/api/todos/completed')
    @login_required
    def delete_completed():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        uid = current_user_id()
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM todos WHERE user_id=? AND completed=1", (uid,))
        conn.commit()
        ensure_positions_sequential(conn, uid)
        conn.commit()
        conn.close()
        return jsonify(ok=True)

    @app.post('/api/todos/bulk_upsert')
    @login_required
    def bulk_upsert():
        if not require_csrf():
            return jsonify(error='bad_csrf'), 403
        uid = current_user_id()
        data = request.get_json(silent=True) or {}
        items = data.get('todos') or []
        if not isinstance(items, list):
            return jsonify(error='invalid_payload'), 400
        conn = get_conn()
        cur = conn.cursor()
        for item in items:
            tid = item.get('id')
            text = (item.get('text') or '').strip()
            completed = 1 if item.get('completed') else 0
            position = int(item.get('position') or 0)
            if tid:
                cur.execute(
                    "UPDATE todos SET text=?, completed=?, position=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND user_id=?",
                    (text, completed, position, tid, uid),
                )
            else:
                cur.execute(
                    "INSERT INTO todos(user_id, text, completed, position) VALUES(?, ?, ?, ?)",
                    (uid, text, completed, position),
                )
        conn.commit()
        ensure_positions_sequential(conn, uid)
        conn.commit()
        conn.close()
        return jsonify(ok=True)

    # Preflight handling (not needed for same-origin, kept harmless)
    @app.route('/api/<path:_path>', methods=['OPTIONS'])
    def options(_path):
        return ('', 204)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
