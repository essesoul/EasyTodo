import os
import secrets
from datetime import timedelta
from functools import wraps

from flask import Flask, jsonify, request, session, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_conn, init_db


def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # Set in deployment behind HTTPS
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    init_db()

    # Same-origin app, no CORS needed

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
    def current_user_id():
        return session.get('user_id')

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
        if not token or token != session.get('csrf_token'):
            return False
        return True

    def ensure_positions_sequential(conn, user_id):
        cur = conn.cursor()
        cur.execute("SELECT id FROM todos WHERE user_id=? ORDER BY position ASC, id ASC", (user_id,))
        ids = [row['id'] for row in cur.fetchall()]
        for idx, tid in enumerate(ids):
            cur.execute("UPDATE todos SET position=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (idx, tid))

    # --- Page routes (Jinja2) ---
    @app.get('/login')
    def login_page():
        if current_user_id():
            return redirect(url_for('home'))
        return render_template('login.html', title='登录 / 注册 - EasyNote')

    @app.get('/')
    @login_required
    def home():
        token = ensure_csrf_token()
        return render_template('index.html', title='EasyNote 待办', csrf_token=token)

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
        return render_template('settings.html', title='设置 - EasyNote', csrf_token=token, email=email)

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
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users(email, password_hash) VALUES(?, ?)", (email, generate_password_hash(password)))
            conn.commit()
        except Exception:
            conn.rollback()
            conn.close()
            return jsonify(error='email_taken'), 409
        # auto-login
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        user_id = cur.fetchone()['id']
        session['user_id'] = user_id
        if not session.get('csrf_token'):
            session['csrf_token'] = secrets.token_hex(16)
        session.permanent = True
        conn.close()
        return jsonify(ok=True)

    @app.post('/api/auth/login')
    def login():
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        conn.close()
        if not row or not check_password_hash(row['password_hash'], password):
            return jsonify(error='invalid_credentials'), 401
        session['user_id'] = row['id']
        if not session.get('csrf_token'):
            session['csrf_token'] = secrets.token_hex(16)
        session.permanent = True
        return jsonify(ok=True)

    @app.post('/api/auth/logout')
    def logout():
        session.clear()
        return jsonify(ok=True)

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
