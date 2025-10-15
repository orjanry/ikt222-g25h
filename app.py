from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64
import secrets
from datetime import datetime, timedelta
from markupsafe import Markup
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Initialize rate limiter for brute force protection
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# OAuth2 client setup
oauth = OAuth(app)
oauth.register(
    name='github',
    client_id='Ov23ctTighr3bE82ppTH',
    client_secret='d4f06209cf08dbc4e78c6b24d1323ff4e0f70a80',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn



def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def verify_password(password, hashed):
    return check_password_hash(hashed, password)

def record_login_attempt(username, success, ip_address):
    """Record login attempt for brute force tracking"""
    conn = get_db_connection()
    conn.execute('''INSERT INTO login_attempts (username, success, ip_address) 
                    VALUES (?, ?, ?)''', (username, 1 if success else 0, ip_address))
    conn.commit()
    conn.close()

def get_failed_attempts(username):
    """Get consecutive failed attempts since last success"""
    conn = get_db_connection()
    
    # Get all attempts for this user, newest first
    attempts = conn.execute('''
        SELECT success FROM login_attempts 
        WHERE username = ? 
        ORDER BY attempt_time DESC
    ''', (username,)).fetchall()
    
    conn.close()
    
    # Count consecutive failures from most recent
    count = 0
    for attempt in attempts:
        if attempt['success'] == 0:
            count += 1
        else:
            break  # Stop at first success
    
    print(f"DEBUG: {count} consecutive failed attempts for {username}")
    return count

def lock_account(username, minutes=15):
    """Lock user account for specified minutes"""
    conn = get_db_connection()
    lock_until = datetime.now() + timedelta(minutes=minutes)
    conn.execute('UPDATE users SET account_locked = 1, lock_until = ? WHERE username = ?',
                (lock_until, username))
    conn.commit()
    conn.close()

def is_account_locked(username):
    """Check if account is currently locked"""
    conn = get_db_connection()
    user = conn.execute('SELECT account_locked, lock_until FROM users WHERE username = ?',
                       (username,)).fetchone()
    conn.close()
    
    if not user or not user['account_locked']:
        return False
    
    # Check if lock period has expired
    if user['lock_until']:
        lock_until = datetime.fromisoformat(user['lock_until'])
        if datetime.now() > lock_until:
            # Unlock account
            conn = get_db_connection()
            conn.execute('UPDATE users SET account_locked = 0, lock_until = NULL WHERE username = ?',
                        (username,))
            conn.commit()
            conn.close()
            return False
    
    return True

# ============= BASIC ROUTES =============

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('''SELECT p.*, u.username 
                            FROM posts p 
                            JOIN users u ON p.author_id = u.id 
                            ORDER BY p.created_at DESC''').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

# ============= AUTHENTICATION ROUTES =============

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        enable_2fa = 'enable_2fa' in request.form
        
        if not username or not password or not email:
            flash('All fields are required!')
            return render_template('register.html')
        
        # Generate TOTP secret if 2FA is enabled
        totp_secret = None
        qr_code_data = None
        if enable_2fa:
            totp_secret = pyotp.random_base32()
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email,
                issuer_name='XSS Demo Blog'
            )
            # Generate QR code
            qr = qrcode.make(totp_uri)
            buffered = io.BytesIO()
            qr.save(buffered, format="PNG")
            qr_code_data = base64.b64encode(buffered.getvalue()).decode()
        
        conn = get_db_connection()
        try:
            conn.execute('''INSERT INTO users (username, password_hash, email, totp_secret, totp_enabled) 
                            VALUES (?, ?, ?, ?, ?)''',
                        (username, hash_password(password), email, totp_secret, 1 if enable_2fa else 0))
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
@limiter.limit("5 per minute")  # Rate limiting
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        
        # Check if account is locked
        if is_account_locked(username):
            flash('Account is locked due to too many failed attempts. Try again later.')
            return render_template('login.html')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and user['password_hash'] and verify_password(password, user['password_hash']):
            # Password is correct
            if user['totp_enabled']:
                # Store user ID temporarily for 2FA verification
                session['pending_2fa_user_id'] = user['id']
                session['pending_2fa_username'] = user['username']
                # Don't record as success or failure yet - wait for 2FA
                return redirect(url_for('verify_2fa'))
            else:
                # Login successful without 2FA
                session['user_id'] = user['id']
                session['username'] = user['username']
                record_login_attempt(username, True, ip_address)
                
                # Update last login
                conn = get_db_connection()
                conn.execute('UPDATE users SET last_login = ? WHERE id = ?',
                            (datetime.now(), user['id']))
                conn.commit()
                conn.close()
                
                flash('Login successful!')
                return redirect(url_for('index'))
        else:
            # Failed login - WRONG PASSWORD
            if user:  # User exists but password wrong
                record_login_attempt(username, False, ip_address)
                failed_attempts = get_failed_attempts(username)
                
                # Lock account after 3 failed attempts
                if failed_attempts >= 3:
                    lock_account(username, minutes=15)
                    flash('Too many failed attempts. Account locked for 15 minutes.')
                else:
                    remaining = 3 - failed_attempts
                    flash(f'Invalid credentials. {remaining} attempts remaining.')
            else:
                # Username doesn't exist
                flash('Invalid credentials.')
    
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_2fa_user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form['token']
        user_id = session['pending_2fa_user_id']
        username = session['pending_2fa_username']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if user and user['totp_secret']:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(token, valid_window=1):
                # 2FA successful - NOW record as successful login
                session['user_id'] = user['id']
                session['username'] = user['username']
                session.pop('pending_2fa_user_id', None)
                session.pop('pending_2fa_username', None)
                
                record_login_attempt(username, True, request.remote_addr)
                
                # Update last login
                conn = get_db_connection()
                conn.execute('UPDATE users SET last_login = ? WHERE id = ?',
                            (datetime.now(), user['id']))
                conn.commit()
                conn.close()
                
                flash('Login successful with 2FA!')
                return redirect(url_for('index'))
            else:
                # 2FA code wrong - but don't lock account for this
                # Users often mistype 2FA codes
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



@app.route('/login/github')
def github_login():
    redirect_uri = url_for('github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@app.route('/github/callback')
def github_callback():
    token = oauth.github.authorize_access_token()
    user_info = oauth.github.get('user').json()
    
    # Store in database
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE oauth_id = ? AND oauth_provider = ?',
                       (str(user_info['id']), 'github')).fetchone()
    
    if not user:
        # Create new user from GitHub data
        conn.execute('''INSERT INTO users (username, email, oauth_provider, oauth_id) 
                       VALUES (?, ?, ?, ?)''',
                    (user_info['login'], user_info['email'], 'github', str(user_info['id'])))
        conn.commit()
        user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    else:
        user_id = user['id']
    
    conn.close()
    
    # Login user
    session['user_id'] = user_id
    session['username'] = user_info['login']
    flash('Logged in with GitHub!')
    return redirect(url_for('index'))

# ============= 2FA MANAGEMENT =============

@app.route('/enable_2fa', methods=['GET', 'POST'])
def enable_2fa():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['totp_enabled']:
        flash('2FA is already enabled.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Generate new TOTP secret
        totp_secret = pyotp.random_base32()
        
        conn.execute('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?',
                    (totp_secret, session['user_id']))
        conn.commit()
        conn.close()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=user['email'],
            issuer_name='XSS Demo Blog'
        )
        qr = qrcode.make(totp_uri)
        buffered = io.BytesIO()
        qr.save(buffered, format="PNG")
        qr_code_data = base64.b64encode(buffered.getvalue()).decode()
        
        return render_template('show_qr.html', qr_code=qr_code_data, secret=totp_secret)
    
    conn.close()
    return render_template('enable_2fa.html')

# ============= OAUTH2 ROUTES =============

@app.route('/auth', methods=['GET'])
def oauth_auth():
    """OAuth2 authorization endpoint"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state', '')
    scope = request.args.get('scope', 'read')
    
    if not client_id or not redirect_uri:
        return jsonify({'error': 'invalid_request'}), 400
    
    # Verify client_id and redirect_uri
    conn = get_db_connection()
    client = conn.execute('SELECT * FROM oauth_clients WHERE client_id = ?', 
                         (client_id,)).fetchone()
    conn.close()
    
    if not client:
        return jsonify({'error': 'invalid_client'}), 400
    
    # Check if redirect_uri is registered
    registered_uris = client['redirect_uris'].split(',')
    if redirect_uri not in registered_uris:
        return jsonify({'error': 'invalid_redirect_uri'}), 400
    
    # User must be logged in to authorize
    if 'user_id' not in session:
        session['oauth_return_params'] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'state': state,
            'scope': scope
        }
        flash('Please log in to authorize the application.')
        return redirect(url_for('login'))
    
    # Show authorization page
    return render_template('oauth_authorize.html', 
                         client=client, 
                         redirect_uri=redirect_uri,
                         state=state,
                         scope=scope)

@app.route('/approve_auth', methods=['POST'])
def approve_auth():
    """User approves OAuth2 authorization"""
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state', '')
    scope = request.form.get('scope', 'read')
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(minutes=10)
    
    conn = get_db_connection()
    conn.execute('''INSERT INTO oauth_auth_codes 
                    (code, client_id, user_id, redirect_uri, scope, expires_at) 
                    VALUES (?, ?, ?, ?, ?, ?)''',
                (auth_code, client_id, session['user_id'], redirect_uri, scope, expires_at))
    conn.commit()
    conn.close()
    
    # Redirect back to client with auth code
    separator = '&' if '?' in redirect_uri else '?'
    return redirect(f"{redirect_uri}{separator}code={auth_code}&state={state}")

@app.route('/token', methods=['POST'])
def oauth_token():
    """Exchange authorization code for access token"""
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    
    if not all([code, redirect_uri, client_id, client_secret]):
        return jsonify({'error': 'invalid_request'}), 400
    
    conn = get_db_connection()
    
    # Verify client credentials
    client = conn.execute('''SELECT * FROM oauth_clients 
                             WHERE client_id = ? AND client_secret = ?''',
                         (client_id, client_secret)).fetchone()
    if not client:
        conn.close()
        return jsonify({'error': 'invalid_client'}), 401
    
    # Verify authorization code
    auth_code_record = conn.execute('''SELECT * FROM oauth_auth_codes 
                                       WHERE code = ? AND client_id = ? 
                                       AND redirect_uri = ? AND used = 0''',
                                   (code, client_id, redirect_uri)).fetchone()
    
    if not auth_code_record:
        conn.close()
        return jsonify({'error': 'invalid_grant'}), 400
    
    # Check if code has expired
    expires_at = datetime.fromisoformat(auth_code_record['expires_at'])
    if datetime.now() > expires_at:
        conn.close()
        return jsonify({'error': 'invalid_grant', 'error_description': 'authorization code expired'}), 400
    
    # Mark code as used
    conn.execute('UPDATE oauth_auth_codes SET used = 1 WHERE code = ?', (code,))
    
    # Generate access token
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)
    token_expires_at = datetime.now() + timedelta(hours=1)
    
    conn.execute('''INSERT INTO oauth_tokens 
                    (access_token, refresh_token, client_id, user_id, scope, expires_at) 
                    VALUES (?, ?, ?, ?, ?, ?)''',
                (access_token, refresh_token, client_id, auth_code_record['user_id'], 
                 auth_code_record['scope'], token_expires_at))
    conn.commit()
    conn.close()
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': refresh_token,
        'scope': auth_code_record['scope']
    })

@app.route('/protected_resource', methods=['GET'])
def protected_resource():
    """Protected API endpoint requiring OAuth2 token"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'invalid_token'}), 401
    
    access_token = auth_header.split(' ')[1]
    
    conn = get_db_connection()
    token_record = conn.execute('''SELECT t.*, u.username, u.email 
                                   FROM oauth_tokens t 
                                   JOIN users u ON t.user_id = u.id 
                                   WHERE t.access_token = ?''', 
                               (access_token,)).fetchone()
    conn.close()
    
    if not token_record:
        return jsonify({'error': 'invalid_token'}), 401
    
    # Check if token has expired
    expires_at = datetime.fromisoformat(token_record['expires_at'])
    if datetime.now() > expires_at:
        return jsonify({'error': 'token_expired'}), 401
    
    # Return protected user data
    return jsonify({
        'user_id': token_record['user_id'],
        'username': token_record['username'],
        'email': token_record['email']
    })

# ============= BLOG POST ROUTES (Keep existing) =============

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
    post = conn.execute('''SELECT p.*, u.username 
                           FROM posts p 
                           JOIN users u ON p.author_id = u.id 
                           WHERE p.id = ?''', (post_id,)).fetchone()
    
    if not post:
        flash('Post not found!')
        return redirect(url_for('index'))
    
    comments = conn.execute('''SELECT * FROM comments 
                               WHERE post_id = ? 
                               ORDER BY created_at ASC''', (post_id,)).fetchall()
    conn.close()
    return render_template('post.html', post=post, comments=comments)

# ============= XSS DEMO ROUTES (Keep existing) =============

@app.route('/vulnerable_search')
def vulnerable_search():
    search_query = request.args.get('q', '')
    conn = get_db_connection()
    posts = conn.execute('''SELECT p.*, u.username 
                            FROM posts p 
                            JOIN users u ON p.author_id = u.id 
                            WHERE p.title LIKE ? OR p.content LIKE ?
                            ORDER BY p.created_at DESC''',
                        (f'%{search_query}%', f'%{search_query}%')).fetchall()
    conn.close()
    return render_template('vulnerable_search.html', posts=posts, query=Markup(search_query))

@app.route('/secure_search')
def secure_search():
    search_query = request.args.get('q', '')
    conn = get_db_connection()
    posts = conn.execute('''SELECT p.*, u.username 
                            FROM posts p 
                            JOIN users u ON p.author_id = u.id 
                            WHERE p.title LIKE ? OR p.content LIKE ?
                            ORDER BY p.created_at DESC''',
                        (f'%{search_query}%', f'%{search_query}%')).fetchall()
    conn.close()
    return render_template('secure_search.html', posts=posts, query=search_query)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)