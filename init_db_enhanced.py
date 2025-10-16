import sqlite3
from datetime import datetime

def init_enhanced_db():
    """
    Enhanced database initialization with support for:
    - 2FA/TOTP
    - OAuth2
    - Brute force protection
    """
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # Drop old users table if migrating
    # c.execute('DROP TABLE IF EXISTS users')
    
    # Enhanced users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT,
                  totp_secret TEXT,
                  totp_enabled INTEGER DEFAULT 0,
                  oauth_provider TEXT,
                  oauth_id TEXT,
                  account_locked INTEGER DEFAULT 0,
                  lock_until TIMESTAMP,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP)''')
    
    # Login attempts tracking (for brute force protection)
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  ip_address TEXT,
                  success INTEGER DEFAULT 0,
                  attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # OAuth2 authorization codes
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_auth_codes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  code TEXT UNIQUE NOT NULL,
                  client_id TEXT NOT NULL,
                  user_id INTEGER,
                  redirect_uri TEXT NOT NULL,
                  scope TEXT,
                  expires_at TIMESTAMP NOT NULL,
                  used INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # OAuth2 access tokens
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  access_token TEXT UNIQUE NOT NULL,
                  refresh_token TEXT UNIQUE,
                  client_id TEXT NOT NULL,
                  user_id INTEGER,
                  scope TEXT,
                  expires_at TIMESTAMP NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # OAuth2 registered clients
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_clients
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  client_id TEXT UNIQUE NOT NULL,
                  client_secret TEXT NOT NULL,
                  client_name TEXT NOT NULL,
                  redirect_uris TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Keep existing posts table
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  author_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (author_id) REFERENCES users (id))''')
    
    # Keep existing comments table
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  post_id INTEGER,
                  author_name TEXT NOT NULL,
                  content TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (post_id) REFERENCES posts (id))''')
    
    # Insert a default OAuth client for testing
    c.execute('''INSERT OR IGNORE INTO oauth_clients 
                 (client_id, client_secret, client_name, redirect_uris) 
                 VALUES (?, ?, ?, ?)''',
              ('test_client_123', 
               'test_secret_456', 
               'Test OAuth Client',
               'http://localhost:5000/callback,http://localhost:3000/callback'))
    
    conn.commit()
    conn.close()
    print("Enhanced database initialized successfully!")

if __name__ == '__main__':
    init_enhanced_db()