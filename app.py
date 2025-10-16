import os
import io
import base64
import sqlite3
import qrcode
import secrets
import pyotp
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()  # Load .env file

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from flask import url_for as flask_url_for  # just to be explicit

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'your-secret-key-change-this-in-production')

# Rate limiter (brute force) 
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")

# OAuth2 CLIENT (GitHub)
app.config.update(
    GITHUB_CLIENT_ID=os.getenv("GITHUB_CLIENT_ID", ""),
    GITHUB_CLIENT_SECRET=os.getenv("GITHUB_CLIENT_SECRET", ""),
)
oauth = OAuth(app)
oauth.register(
    name='github',
    client_id=app.config["GITHUB_CLIENT_ID"],
    client_secret=app.config["GITHUB_CLIENT_SECRET"],
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'read:user user:email'},
)
GITHUB_READY = bool(app.config["GITHUB_CLIENT_ID"] and app.config["GITHUB_CLIENT_SECRET"])

@app.context_processor
def inject_flags():
    return {"GITHUB_READY": GITHUB_READY}

# DB helpers
def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def verify_password(password, hashed):
    return check_password_hash(hashed, password)

def record_login_attempt(username, success, ip_address):
    conn = get_db_connection()
    conn.execute('INSERT INTO login_attempts (username, success, ip_address) VALUES (?, ?, ?)',
                 (username, 1 if success else 0, ip_address))
    conn.commit()
    conn.close()

def get_failed_attempts(username):
    conn = get_db_connection()
    attempts = conn.execute(
        'SELECT success FROM login_attempts WHERE username=? ORDER BY attempt_time DESC',
        (username,)
    ).fetchall()
    conn.close()
    count = 0
    for a in attempts:
        if a['success'] == 0:
            count += 1
        else:
            break
    return count

def lock_account(username, minutes=15):
    conn = get_db_connection()
    lock_until = datetime.now() + timedelta(minutes=minutes)
    conn.execute('UPDATE users SET account_locked=1, lock_until=? WHERE username=?',
                 (lock_until, username))
    conn.commit()
    conn.close()

def is_account_locked(username):
    conn = get_db_connection()
    user = conn.execute('SELECT id, account_locked, lock_until FROM users WHERE username=?',
                        (username,)).fetchone()
    conn.close()
    if not user or not user['account_locked']:
        return False
    if user['lock_until']:
        if datetime.now() > datetime.fromisoformat(user['lock_until']):
            # unlock
            conn = get_db_connection()
            conn.execute('UPDATE users SET account_locked=0, lock_until=NULL WHERE id=?', (user['id'],))
            conn.commit()
            conn.close()
            return False
    return True

# BASIC PAGES 
@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT p.*, u.username
        FROM posts p JOIN users u ON p.author_id = u.id
        ORDER BY p.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

# LOCAL AUTH 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        email = (request.form.get('email') or '').strip()
        enable_2fa = 'enable_2fa' in request.form

        if not username or not password or not email:
            flash('All fields are required!')
            return render_template('register.html')

        totp_secret = None
        qr_code_data = None
        if enable_2fa:
            totp_secret = pyotp.random_base32()
            uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name='Demo Blog')
            img = qrcode.make(uri)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            qr_code_data = base64.b64encode(buf.getvalue()).decode()

        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, password_hash, email, totp_secret, totp_enabled)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hash_password(password), email, totp_secret, 1 if enable_2fa else 0))
            conn.commit()
            if enable_2fa:
                flash('Registration successful! Scan this QR code with Google Authenticator.')
                return render_template('show_qr.html', qr_code=qr_code_data, secret=totp_secret)
            else:
                flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        ip_address = request.remote_addr

        if is_account_locked(username):
            flash('Account is locked due to too many failed attempts. Try again later.')
            return render_template('login.html')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        conn.close()

        if user and user['password_hash'] and verify_password(password, user['password_hash']):
            if user['totp_enabled']:
                session['pending_2fa_user_id'] = user['id']
                session['pending_2fa_username'] = user['username']
                return redirect(url_for('verify_2fa'))
            session['user_id'] = user['id']
            session['username'] = user['username']
            record_login_attempt(username, True, ip_address)
            conn = get_db_connection()
            conn.execute('UPDATE users SET last_login=? WHERE id=?', (datetime.now(), user['id']))
            conn.commit()
            conn.close()
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            if user:
                record_login_attempt(username, False, ip_address)
                fails = get_failed_attempts(username)
                if fails >= 3:
                    lock_account(username, minutes=15)
                    flash('Too many failed attempts. Account locked for 15 minutes.')
                else:
                    flash(f'Invalid credentials. {3 - fails} attempts remaining.')
            else:
                flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_2fa_user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = (request.form.get('token') or '').strip()
        user_id = session['pending_2fa_user_id']
        username = session['pending_2fa_username']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        conn.close()

        if user and user['totp_secret']:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(token, valid_window=1):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session.pop('pending_2fa_user_id', None)
                session.pop('pending_2fa_username', None)
                record_login_attempt(username, True, request.remote_addr)
                conn = get_db_connection()
                conn.execute('UPDATE users SET last_login=? WHERE id=?', (datetime.now(), user['id']))
                conn.commit()
                conn.close()
                flash('Login successful with 2FA!')
                return redirect(url_for('index'))
            else:
                flash('Invalid 2FA code. Please try again.')
        else:
            flash('2FA configuration error.')
            return redirect(url_for('login'))
    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

# GitHub OAuth (CLIENT): Login/Register with GitHub
@app.route('/login/github')
def github_login():
    if not GITHUB_READY:
        flash('GitHub login is not configured.')
        return redirect(url_for('login'))
    return oauth.github.authorize_redirect(flask_url_for('github_callback', _external=True))

@app.route('/github/callback')
def github_callback():
    # If GitHub didn’t send code (misconfig / direct hit), fail nicely
    if 'code' not in request.args:
        flash("GitHub callback missing 'code'. Start at 'Login with GitHub' and verify OAuth App settings.")
        return redirect(url_for('login'))

    token = oauth.github.authorize_access_token()
    me = oauth.github.get('user').json()
    emails = oauth.github.get('user/emails').json()

    # choose best email
    primary_email = None
    if isinstance(emails, list) and emails:
        for e in emails:
            if e.get('primary') and e.get('verified'):
                primary_email = e.get('email')
                break
        if not primary_email:
            primary_email = emails[0].get('email')

    username = me.get('login') or f"github_{me.get('id')}"
    email = me.get('email') or primary_email or f"{username}@users.noreply.github"
    provider_id = str(me['id'])

    conn = get_db_connection()

    # If already logged in locally, link this GitHub to account
    if 'user_id' in session:
        conn.execute('UPDATE users SET oauth_provider=?, oauth_id=? WHERE id=?',
                     ('github', provider_id, session['user_id']))
        conn.commit()
        conn.close()
        flash('GitHub account linked.')
        return redirect(url_for('index'))

    # Find existing oauth user
    existing = conn.execute(
        'SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?',
        ('github', provider_id)
    ).fetchone()

    if existing:
        user_id = existing['id']
        final_username = existing['username']
    else:
        # Create a new user (REGISTER with GitHub) – keep NOT NULL password_hash happy
        random_pw = secrets.token_urlsafe(32)
        pw_hash = hash_password(random_pw)
        conn.execute(
            '''INSERT INTO users (username, email, password_hash, oauth_provider, oauth_id, totp_enabled, created_at)
               VALUES (?, ?, ?, ?, ?, 0, ?)''',
            (username, email, pw_hash, 'github', provider_id, datetime.utcnow().isoformat())
        )
        conn.commit()
        user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        final_username = username

    conn.close()

    session['user_id'] = user_id
    session['username'] = final_username
    flash('Logged in with GitHub.')
    return redirect(url_for('index'))

# Posts
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        flash('Please log in to create a post.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if not title or not content:
            flash('Title and content are required!')
            return render_template('create_post.html')
        conn = get_db_connection()
        conn.execute('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
                     (title, content, session['user_id']))
        conn.commit()
        conn.close()
        flash('Post created successfully!')
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/post/<int:post_id>')
def view_post(post_id):
    conn = get_db_connection()
    post = conn.execute('''
        SELECT p.*, u.username
        FROM posts p JOIN users u ON p.author_id = u.id
        WHERE p.id=?
    ''', (post_id,)).fetchone()
    if not post:
        flash('Post not found!')
        return redirect(url_for('index'))
    comments = conn.execute('SELECT * FROM comments WHERE post_id=? ORDER BY created_at ASC',
                            (post_id,)).fetchall()
    conn.close()
    return render_template('post.html', post=post, comments=comments)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
